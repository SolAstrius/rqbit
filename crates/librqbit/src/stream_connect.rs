use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use fast_socks5::client::Socks5Datagram;
use fast_socks5::util::target_addr::TargetAddr;
use futures::future::BoxFuture;
use librqbit_dualstack_sockets::ConnectOpts;
use librqbit_utp::{BindDevice, UtpSocketUdp};
use serde::Serialize;
use tracing::debug;

use crate::{
    Error, PeerConnectionOptions, Result,
    type_aliases::{BoxAsyncReadVectored, BoxAsyncWrite},
    vectored_traits::AsyncReadVectoredIntoCompat,
};

#[derive(Debug, Clone, Copy, Serialize)]
pub enum ConnectionKind {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "utp")]
    Utp,
    #[serde(rename = "socks")]
    Socks,
}

impl std::fmt::Display for ConnectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionKind::Tcp => f.write_str("tcp"),
            ConnectionKind::Utp => f.write_str("uTP"),
            ConnectionKind::Socks => f.write_str("socks"),
        }
    }
}

pub struct ConnectionOptions {
    // socks5://[username:password@]host:port
    // If set, all outgoing connections will go through the proxy over TCP.
    pub proxy_url: Option<String>,
    // TCP outgoing connections are enabled by default
    pub enable_tcp: bool,
    pub peer_opts: Option<PeerConnectionOptions>,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            proxy_url: None,
            peer_opts: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SocksProxyConfig {
    pub host: String,
    pub port: u16,
    pub username_password: Option<(String, String)>,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct StreamConnectorArgs {
    pub enable_tcp: bool,
    pub socks_proxy_config: Option<SocksProxyConfig>,
    pub utp_socket: Option<Arc<UtpSocketUdp>>,
    pub bind_device: Option<BindDevice>,
    pub ipv4_only: bool,
}

impl SocksProxyConfig {
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let url = ::url::Url::parse(url).context("invalid proxy URL")?;
        if url.scheme() != "socks5" {
            anyhow::bail!("proxy URL should have socks5 scheme");
        }
        let host = url.host_str().context("missing host")?;
        let port = url.port().context("missing port")?;
        let up = url
            .password()
            .map(|p| (url.username().to_owned(), p.to_owned()));
        Ok(Self {
            host: host.to_owned(),
            port,
            username_password: up,
        })
    }

    async fn resolve_proxy_addr(&self) -> Result<SocketAddr> {
        tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .map_err(|e| {
                Error::Anyhow(anyhow::anyhow!(
                    "error resolving proxy address {}:{}: {e:#}",
                    self.host,
                    self.port
                ))
            })?
            .next()
            .ok_or_else(|| {
                Error::Anyhow(anyhow::anyhow!(
                    "proxy address {}:{} resolved to no addresses",
                    self.host,
                    self.port
                ))
            })
    }

    // Connect a TCP stream to the proxy itself. Unlike tokio-socks' own
    // connect(), this goes through dualstack sockets so it honors bind_device.
    async fn connect_to_proxy_tcp(
        &self,
        bind_device: Option<&BindDevice>,
    ) -> Result<(SocketAddr, tokio::net::TcpStream)> {
        let proxy_addr = self.resolve_proxy_addr().await?;
        let tcp = librqbit_dualstack_sockets::tcp_connect(
            proxy_addr,
            ConnectOpts {
                source_port: None,
                bind_device,
            },
        )
        .await
        .map_err(Error::TcpConnect)?;
        Ok((proxy_addr, tcp))
    }

    async fn connect(
        &self,
        addr: SocketAddr,
        bind_device: Option<&BindDevice>,
    ) -> Result<(
        impl tokio::io::AsyncRead + Unpin + 'static,
        impl tokio::io::AsyncWrite + Unpin + 'static,
    )> {
        let (_, tcp) = self.connect_to_proxy_tcp(bind_device).await?;

        let stream = if let Some((username, password)) = self.username_password.as_ref() {
            tokio_socks::tcp::Socks5Stream::connect_with_password_and_socket(
                tcp,
                addr,
                username.as_str(),
                password.as_str(),
            )
            .await?
        } else {
            tokio_socks::tcp::Socks5Stream::connect_with_socket(tcp, addr).await?
        };

        Ok(tokio::io::split(stream))
    }

    // Establish a SOCKS5 UDP association for tunneling datagrams (DHT, UDP
    // trackers) through the proxy. Each association owns its TCP control
    // connection, so callers needing independent receive demuxing (DHT vs. UDP
    // trackers) should create one each.
    pub(crate) async fn udp_associate(
        &self,
        bind_device: Option<&BindDevice>,
    ) -> Result<SocksUdpSocket> {
        let (proxy_addr, tcp) = self.connect_to_proxy_tcp(bind_device).await?;
        let local_bind: SocketAddr = if proxy_addr.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let inner = if let Some((username, password)) = self.username_password.as_ref() {
            Socks5Datagram::bind_with_password(tcp, local_bind, username, password).await
        } else {
            Socks5Datagram::bind(tcp, local_bind).await
        }
        .map_err(|e| {
            Error::Anyhow(anyhow::anyhow!(
                "error establishing SOCKS5 UDP association: {e:#}"
            ))
        })?;
        let bind_addr = inner.get_ref().local_addr().map_err(|e| {
            Error::Anyhow(anyhow::anyhow!(
                "error getting local UDP socket address: {e:#}"
            ))
        })?;
        Ok(SocksUdpSocket { inner, bind_addr })
    }
}

/// A UDP socket whose datagrams are relayed through a SOCKS5 proxy via UDP
/// ASSOCIATE. Implements the leaf-crate socket traits so it can be injected into
/// the DHT and the UDP tracker client, keeping them unaware of SOCKS.
pub(crate) struct SocksUdpSocket {
    inner: Socks5Datagram<tokio::net::TcpStream>,
    bind_addr: SocketAddr,
}

fn socks_err_to_io(e: fast_socks5::SocksError) -> std::io::Error {
    std::io::Error::other(e)
}

fn target_addr_to_socket_addr(ta: TargetAddr) -> std::io::Result<SocketAddr> {
    match ta {
        TargetAddr::Ip(sa) => Ok(sa),
        TargetAddr::Domain(host, port) => Err(std::io::Error::other(format!(
            "unexpected domain target address from SOCKS5 UDP relay: {host}:{port}"
        ))),
    }
}

impl dht::DhtSocket for SocksUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, std::io::Result<usize>> {
        Box::pin(async move {
            self.inner
                .send_to(buf, target)
                .await
                .map_err(socks_err_to_io)
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, std::io::Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (n, ta) = self.inner.recv_from(buf).await.map_err(socks_err_to_io)?;
            Ok((n, target_addr_to_socket_addr(ta)?))
        })
    }

    fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

impl tracker_comms::UdpTransport for SocksUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, std::io::Result<usize>> {
        Box::pin(async move {
            self.inner
                .send_to(buf, target)
                .await
                .map_err(socks_err_to_io)
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, std::io::Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (n, ta) = self.inner.recv_from(buf).await.map_err(socks_err_to_io)?;
            Ok((n, target_addr_to_socket_addr(ta)?))
        })
    }
}

gen_stats!(SingleStatAtomic SingleStatSnapshot, [
    attempts u64,
    successes u64,
    errors u64
], []);
gen_stats!(PerFamilyAtomic PerFamilySnapshot, [], [
    v4 SingleStatAtomic SingleStatSnapshot,
    v6 SingleStatAtomic SingleStatSnapshot
]);
gen_stats!(ConnectStatsAtomic ConnectStatsSnapshot, [], [
    socks PerFamilyAtomic PerFamilySnapshot,
    tcp PerFamilyAtomic PerFamilySnapshot,
    utp PerFamilyAtomic PerFamilySnapshot
]);

#[derive(Debug)]
pub(crate) struct StreamConnector {
    proxy_config: Option<SocksProxyConfig>,
    enable_tcp: bool,
    bind_device: Option<BindDevice>,
    utp_socket: Option<Arc<librqbit_utp::UtpSocketUdp>>,
    stats: ConnectStatsAtomic,
    ipv4_only: bool,
}

impl StreamConnector {
    pub async fn new(config: StreamConnectorArgs) -> anyhow::Result<Self> {
        #[allow(clippy::single_match)]
        match (
            config.socks_proxy_config.is_some(),
            config.enable_tcp,
            config.utp_socket.is_some(),
        ) {
            (false, false, false) => {
                bail!("no way to connect to peers, enable TCP, uTP or socks proxy")
            }
            _ => {
                // TODO: maybe validate other combinations. For now there's no way to disable TCP
            }
        }

        Ok(Self {
            proxy_config: config.socks_proxy_config,
            enable_tcp: config.enable_tcp,
            utp_socket: config.utp_socket,
            bind_device: config.bind_device,
            stats: Default::default(),
            ipv4_only: config.ipv4_only,
        })
    }

    fn get_stat(&self, kind: ConnectionKind, is_v6: bool) -> &SingleStatAtomic {
        let stat = match kind {
            ConnectionKind::Tcp => &self.stats.tcp,
            ConnectionKind::Utp => &self.stats.utp,
            ConnectionKind::Socks => &self.stats.socks,
        };
        if is_v6 { &stat.v6 } else { &stat.v4 }
    }

    async fn with_stat<R, E>(
        &self,
        kind: ConnectionKind,
        is_v6: bool,
        fut: impl Future<Output = std::result::Result<R, E>>,
    ) -> std::result::Result<R, E> {
        let stat = self.get_stat(kind, is_v6);
        stat.attempts(1);
        fut.await
            .inspect(|_| stat.successes(1))
            .inspect_err(|_| stat.errors(1))
    }

    async fn tcp_connect(
        &self,
        addr: SocketAddr,
    ) -> librqbit_dualstack_sockets::Result<tokio::net::TcpStream> {
        self.with_stat(
            ConnectionKind::Tcp,
            addr.is_ipv6(),
            librqbit_dualstack_sockets::tcp_connect(
                addr,
                ConnectOpts {
                    // Setting source port doesn't work with cloudflare warp on linux
                    // source_port: self.tcp_source_port,
                    source_port: None,
                    bind_device: self.bind_device.as_ref(),
                },
            ),
        )
        .await
    }

    pub fn stats(&self) -> &ConnectStatsAtomic {
        &self.stats
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
    ) -> Result<(ConnectionKind, BoxAsyncReadVectored, BoxAsyncWrite)> {
        if addr.port() == 0 {
            return Err(Error::Anyhow(anyhow::anyhow!(
                "invalid peer address (port 0): {}",
                addr
            )));
        }

        if self.ipv4_only && addr.is_ipv6() {
            return Err(Error::Anyhow(anyhow::anyhow!(
                "ipv6 disabled, skipping connection to {}",
                addr
            )));
        }

        if let Some(proxy) = self.proxy_config.as_ref() {
            let (r, w) = self
                .with_stat(
                    ConnectionKind::Socks,
                    addr.is_ipv6(),
                    proxy.connect(addr, self.bind_device.as_ref()),
                )
                .await?;
            debug!(?addr, "connected through SOCKS5");
            return Ok((
                ConnectionKind::Socks,
                Box::new(r.into_vectored_compat()),
                Box::new(w),
            ));
        }

        // Try to connect over TCP first. If in 1 second we haven't connected, try uTP also (if configured).
        // Whoever connects first wins.
        let tcp_connect = async {
            if !self.enable_tcp {
                return Ok(None);
            }
            let conn = self.tcp_connect(addr).await?;
            debug!(?addr, "connected over TCP");
            Ok::<_, librqbit_dualstack_sockets::Error>(Some(conn))
        };

        let tcp_failed_notify = tokio::sync::Notify::new();

        let utp_connect = async {
            let sock = match self.utp_socket.as_ref() {
                Some(sock) => sock,
                None => return Ok(None),
            };

            // Give TCP priority as it's more mature and simpler.
            if self.enable_tcp {
                // wait until either 1 second has passed or TCP failed.
                tokio::select! {
                    _ = tcp_failed_notify.notified() => {},
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }

            let conn = self
                .with_stat(ConnectionKind::Utp, addr.is_ipv6(), sock.connect(addr))
                .await?;

            debug!(?addr, "connected over uTP");
            Ok(Some(conn))
        };

        tokio::pin!(tcp_connect);
        tokio::pin!(utp_connect);

        let mut tcp_err: Option<Option<librqbit_dualstack_sockets::Error>> = None;
        let mut utp_err: Option<Option<librqbit_utp::Error>> = None;

        // wait until all fail, or one succeeds.
        loop {
            if let (Some(tcp), Some(utp)) = (tcp_err.as_mut(), utp_err.as_mut()) {
                match (tcp.take(), utp.take()) {
                    (Some(tcp), Some(utp)) => return Err(Error::Connect { tcp, utp }),
                    (Some(tcp), None) => return Err(Error::TcpConnect(tcp)),
                    (None, Some(utp)) => return Err(Error::UtpConnect(utp)),
                    (None, None) => return Err(Error::ConnectDisabled),
                }
            }
            tokio::select! {
                tcp_res = &mut tcp_connect, if tcp_err.is_none() => {
                    match tcp_res {
                        Ok(Some(stream)) => {
                            let (r, w) = stream.into_split();
                            return Ok((ConnectionKind::Tcp, Box::new(r), Box::new(w)));
                        },
                        Ok(None) => {
                            tcp_err = Some(None);
                            tcp_failed_notify.notify_waiters();
                        }
                        Err(e) => {
                            tcp_err = Some(Some(e));
                            tcp_failed_notify.notify_waiters();
                        }
                    }
                },
                utp_res = &mut utp_connect, if utp_err.is_none() => {
                    match utp_res {
                        Ok(Some(stream)) => {
                            let (r, w) = stream.split();
                            return Ok((ConnectionKind::Utp, Box::new(r), Box::new(w)));
                        },
                        Ok(None) => {
                            utp_err = Some(None);
                        }
                        Err(e) => {
                            utp_err = Some(Some(e));
                        }
                    }
                },
            };
        }
    }
}
