use std::{
    io::IoSlice,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock as StdRwLock},
    task::Poll,
    time::Duration,
};

use anyhow::{Context, bail};
use fast_socks5::client::Socks5Datagram;
use fast_socks5::new_udp_header;
use fast_socks5::util::target_addr::TargetAddr;
use futures::future::BoxFuture;
use librqbit_dualstack_sockets::{ConnectOpts, PollSendToVectored};
use librqbit_utp::{BindDevice, DefaultUtpEnvironment, Transport, UtpSocket, UtpSocketUdp};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::{
    Error, PeerConnectionOptions, Result,
    mse::Encryption,
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
    /// MSE/PE protocol obfuscation policy for incoming and outgoing peer
    /// connections. Default `Disabled` (plaintext only).
    pub encryption: Encryption,
    /// Experimental: relay outbound uTP through the SOCKS5 proxy (UDP ASSOCIATE).
    /// Only has an effect when `proxy_url` is set. Default off.
    pub experimental_utp_over_socks: bool,
    /// Head start given to TCP (or SOCKS-TCP) before the uTP arm of an outbound
    /// connection race is attempted. `None` uses the default (1s). Lower it to let
    /// uTP compete more evenly; `0` races both simultaneously.
    pub utp_race_delay: Option<Duration>,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            proxy_url: None,
            peer_opts: None,
            encryption: Encryption::default(),
            experimental_utp_over_socks: false,
            utp_race_delay: None,
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
    /// Experimental: outbound uTP relayed through the SOCKS5 proxy. Mutually
    /// exclusive with a direct `utp_socket` in practice (proxy disables listening).
    pub utp_socket_socks: Option<Arc<SocksUtpSocket>>,
    /// Head start for TCP over uTP in the outbound connection race. `None` => 1s.
    pub utp_race_delay: Option<Duration>,
    pub bind_device: Option<BindDevice>,
    pub ipv4_only: bool,
    pub encryption: Encryption,
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

    // Establish one SOCKS5 UDP association: connect the TCP control channel and
    // bind the relayed datagram socket. Returns the datagram plus the local UDP
    // bind address. Used both for the initial association and for transparent
    // re-association when the relay dies.
    async fn bind_udp_datagram(
        &self,
        bind_device: Option<&BindDevice>,
    ) -> Result<(Socks5Datagram<tokio::net::TcpStream>, SocketAddr)> {
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
        Ok((inner, bind_addr))
    }

    // Establish a SOCKS5 UDP association for tunneling datagrams (DHT, UDP
    // trackers) through the proxy. The returned socket is self-healing: a SOCKS5
    // UDP association lives only as long as its TCP control connection and the
    // proxy/NAT relay mapping, so when that dies (sends erroring, or no datagrams
    // arriving despite outstanding sends) [`SocksUdpSocket`] transparently
    // rebuilds it instead of going deaf for the rest of the process lifetime.
    //
    // Each association owns its TCP control connection, so callers needing
    // independent receive demuxing (DHT vs. UDP trackers) should create one each.
    pub(crate) async fn udp_associate(
        &self,
        bind_device: Option<&BindDevice>,
    ) -> Result<SocksUdpSocket> {
        let (inner, bind_addr) = self.bind_udp_datagram(bind_device).await?;
        Ok(SocksUdpSocket {
            proxy: self.clone(),
            bind_device: bind_device.cloned(),
            inner: tokio::sync::RwLock::new(inner),
            bind_addr,
            sent_since_recv: std::sync::atomic::AtomicBool::new(false),
            reassociating: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

/// A UDP socket whose datagrams are relayed through a SOCKS5 proxy via UDP
/// ASSOCIATE. Implements the leaf-crate socket traits so it can be injected into
/// the DHT and the UDP tracker client, keeping them unaware of SOCKS.
///
/// The association is supervised and self-healing: a SOCKS5 UDP association is
/// only alive while its TCP control connection and the proxy/NAT relay mapping
/// are, so when that dies this rebuilds it transparently. Without this, the DHT
/// learns a handful of nodes at startup and then goes permanently deaf once the
/// initial association lapses (`recv_from` parks forever, routing table frozen).
pub(crate) struct SocksUdpSocket {
    proxy: SocksProxyConfig,
    bind_device: Option<BindDevice>,
    inner: tokio::sync::RwLock<Socks5Datagram<tokio::net::TcpStream>>,
    bind_addr: SocketAddr,
    // Set on send, cleared on receive. If a recv idles out while this is set, we
    // sent into the void and the relay is presumed dead.
    sent_since_recv: std::sync::atomic::AtomicBool,
    // Ensures only one reassociation runs at a time across the send/recv paths.
    reassociating: std::sync::atomic::AtomicBool,
}

// Default head start for TCP over uTP in an outbound connection race (overridable
// via ConnectionOptions::utp_race_delay).
const DEFAULT_UTP_RACE_DELAY: Duration = Duration::from_secs(1);
// If no datagram arrives within this window while a send is outstanding, assume
// the SOCKS5 UDP relay died and rebuild the association.
const SOCKS_UDP_RECV_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// Backoff after a failed reassociation attempt, so we don't spin on a down proxy.
const SOCKS_REASSOCIATE_BACKOFF: Duration = Duration::from_secs(5);

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

impl SocksUdpSocket {
    // Rebuild the SOCKS5 UDP association in place. De-duplicated so concurrent
    // triggers from the send and recv paths don't stack up rebuilds.
    async fn reassociate(&self, reason: &str) {
        use std::sync::atomic::Ordering;
        if self
            .reassociating
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        match self
            .proxy
            .bind_udp_datagram(self.bind_device.as_ref())
            .await
        {
            Ok((dgram, _)) => {
                *self.inner.write().await = dgram;
                self.sent_since_recv.store(false, Ordering::Relaxed);
                info!(reason, "re-established SOCKS5 UDP association");
            }
            Err(e) => {
                warn!(
                    reason,
                    "failed to re-establish SOCKS5 UDP association: {e:#}"
                );
                tokio::time::sleep(SOCKS_REASSOCIATE_BACKOFF).await;
            }
        }
        self.reassociating.store(false, Ordering::Release);
    }

    async fn do_send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        use std::sync::atomic::Ordering;
        let res = {
            let g = self.inner.read().await;
            g.send_to(buf, target).await
        };
        match res {
            Ok(n) => {
                self.sent_since_recv.store(true, Ordering::Relaxed);
                Ok(n)
            }
            Err(e) => {
                self.reassociate("send error").await;
                Err(socks_err_to_io(e))
            }
        }
    }

    async fn do_recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        use std::sync::atomic::Ordering;
        loop {
            let timed = {
                let g = self.inner.read().await;
                tokio::time::timeout(SOCKS_UDP_RECV_IDLE_TIMEOUT, g.recv_from(buf)).await
            };
            match timed {
                Ok(Ok((n, ta))) => {
                    self.sent_since_recv.store(false, Ordering::Relaxed);
                    return Ok((n, target_addr_to_socket_addr(ta)?));
                }
                Ok(Err(e)) => {
                    debug!("error receiving from SOCKS5 UDP relay: {e:#}");
                    self.reassociate("recv error").await;
                }
                Err(_elapsed) => {
                    // Idle timeout. If we sent without hearing anything back, the
                    // relay is presumed dead and we rebuild it. Otherwise it's just
                    // a quiet period: keep waiting (we never surface this as an
                    // error, since callers treat a recv error as fatal).
                    if self.sent_since_recv.swap(false, Ordering::Relaxed) {
                        self.reassociate("recv idle after send").await;
                    }
                }
            }
        }
    }
}

impl dht::DhtSocket for SocksUdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, std::io::Result<usize>> {
        Box::pin(self.do_send_to(buf, target))
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, std::io::Result<(usize, SocketAddr)>> {
        Box::pin(self.do_recv_from(buf))
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
        Box::pin(self.do_send_to(buf, target))
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, std::io::Result<(usize, SocketAddr)>> {
        Box::pin(self.do_recv_from(buf))
    }
}

/// Outbound µTP transport whose datagrams are relayed through a SOCKS5 proxy via
/// UDP ASSOCIATE. Implements [`librqbit_utp::Transport`] so a `UtpSocket` can be
/// built over the proxy — the missing bridge that lets uTP work behind the SOCKS5
/// relay we already use for DHT and UDP trackers.
///
/// uTP's `Transport` needs a *synchronous* `poll_send_to`, which the async-only
/// [`SocksUdpSocket`] can't provide. The enabler: the datagram's inner UDP socket
/// is `connect()`ed to the relay (see `Socks5Datagram::bind_internal`), so
/// `get_ref()` hands back a connected `tokio::net::UdpSocket` with a real
/// `poll_send`. We frame manually with `new_udp_header` and keep the datagram
/// behind a std `RwLock<Arc<..>>` so the sync path reads it without `.await`.
pub(crate) struct SocksUtpTransport {
    proxy: SocksProxyConfig,
    bind_device: Option<BindDevice>,
    // Swappable so the sync poll path reads it without `.await`, while the async
    // recv supervisor can rebuild it on relay death. std (not tokio) RwLock on
    // purpose: NEVER hold the guard across `.await` — clone the Arc and drop it.
    inner: StdRwLock<Arc<Socks5Datagram<tokio::net::TcpStream>>>,
    bind_addr: SocketAddr,
    // Set on send, cleared on receive. If a recv idles out while set, we sent into
    // the void and the relay is presumed dead.
    sent_since_recv: std::sync::atomic::AtomicBool,
    // Ensures only one reassociation runs at a time across send/recv paths.
    reassociating: std::sync::atomic::AtomicBool,
}

impl SocksUtpTransport {
    pub(crate) async fn new(
        proxy: SocksProxyConfig,
        bind_device: Option<BindDevice>,
    ) -> Result<Self> {
        let (dgram, bind_addr) = proxy.bind_udp_datagram(bind_device.as_ref()).await?;
        Ok(Self {
            proxy,
            bind_device,
            inner: StdRwLock::new(Arc::new(dgram)),
            bind_addr,
            sent_since_recv: std::sync::atomic::AtomicBool::new(false),
            reassociating: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn current(&self) -> Arc<Socks5Datagram<tokio::net::TcpStream>> {
        self.inner.read().unwrap().clone()
    }

    // Rebuild the SOCKS5 UDP association in place. De-duplicated so concurrent
    // triggers from the send and recv paths don't stack up rebuilds. NOTE: a new
    // association means a new relay source port, which breaks any in-flight uTP
    // connection — acceptable for the DHT-style "don't go permanently deaf" goal,
    // but see the idle-reassoc note in `recv_from`.
    async fn reassociate(&self, reason: &str) {
        use std::sync::atomic::Ordering;
        if self
            .reassociating
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        match self
            .proxy
            .bind_udp_datagram(self.bind_device.as_ref())
            .await
        {
            Ok((dgram, _)) => {
                *self.inner.write().unwrap() = Arc::new(dgram);
                self.sent_since_recv.store(false, Ordering::Relaxed);
                info!(reason, "re-established SOCKS5 UDP association for uTP");
            }
            Err(e) => {
                warn!(
                    reason,
                    "failed to re-establish SOCKS5 UDP association for uTP: {e:#}"
                );
                tokio::time::sleep(SOCKS_REASSOCIATE_BACKOFF).await;
            }
        }
        self.reassociating.store(false, Ordering::Release);
    }

    // Frame `parts` (concatenated) for `target` and synchronously poll_send the
    // SOCKS5-UDP-framed datagram to the connected relay socket. On success returns
    // the *payload* length (a datagram send is atomic — all or nothing).
    fn poll_send_framed(
        &self,
        cx: &mut std::task::Context<'_>,
        target: SocketAddr,
        parts: &[&[u8]],
    ) -> Poll<std::io::Result<usize>> {
        let mut frame = match new_udp_header(target) {
            Ok(h) => h,
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e))),
        };
        let mut payload_len = 0usize;
        for p in parts {
            frame.extend_from_slice(p);
            payload_len += p.len();
        }
        let dgram = self.current();
        match dgram.get_ref().poll_send(cx, &frame) {
            Poll::Ready(Ok(_n)) => {
                self.sent_since_recv
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                Poll::Ready(Ok(payload_len))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl PollSendToVectored for SocksUtpTransport {
    fn poll_send_to_vectored(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
        target: SocketAddr,
    ) -> Poll<std::io::Result<usize>> {
        // Coalesce into one framed datagram (the SOCKS header is prepended inside
        // poll_send_framed). Correct but copies; optimize to a writev to the relay
        // addr later only if profiles show it hot.
        let parts: Vec<&[u8]> = bufs.iter().map(|s| &s[..]).collect();
        self.poll_send_framed(cx, target, &parts)
    }
}

impl Transport for SocksUtpTransport {
    // The trait's explicit `+ Send + Sync` return bounds preclude a clean `async fn`,
    // so keep the impl-Future form (matching the crate's own UdpSocket impl).
    #[allow(clippy::manual_async_fn)]
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<(usize, SocketAddr)>> + Send + Sync + 'a
    {
        async move {
            use std::sync::atomic::Ordering;
            loop {
                let dgram = self.current();
                let timed =
                    tokio::time::timeout(SOCKS_UDP_RECV_IDLE_TIMEOUT, dgram.recv_from(buf)).await;
                match timed {
                    Ok(Ok((n, ta))) => {
                        self.sent_since_recv.store(false, Ordering::Relaxed);
                        return Ok((n, target_addr_to_socket_addr(ta)?));
                    }
                    Ok(Err(e)) => {
                        debug!("error receiving from SOCKS5 UDP relay (uTP): {e:#}");
                        self.reassociate("recv error").await;
                    }
                    Err(_elapsed) => {
                        // Idle. Only reassociate if we sent into the void (relay
                        // presumed dead). During active uTP transfers recv is
                        // constant, so this won't fire mid-connection. TODO: consider
                        // error-only reassoc to never risk a live connection.
                        if self.sent_since_recv.swap(false, Ordering::Relaxed) {
                            self.reassociate("recv idle after send").await;
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send + Sync + 'a {
        async move {
            let dgram = self.current();
            match dgram.send_to(buf, target).await {
                Ok(n) => {
                    self.sent_since_recv
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    Ok(n)
                }
                Err(e) => {
                    self.reassociate("send error").await;
                    Err(socks_err_to_io(e))
                }
            }
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<std::io::Result<usize>> {
        self.poll_send_framed(cx, target, &[buf])
    }

    fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

/// A uTP socket whose datagrams are relayed through a SOCKS5 proxy.
pub(crate) type SocksUtpSocket = UtpSocket<SocksUtpTransport, DefaultUtpEnvironment>;

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
    utp_socket_socks: Option<Arc<SocksUtpSocket>>,
    utp_race_delay: Duration,
    stats: ConnectStatsAtomic,
    ipv4_only: bool,
    encryption: Encryption,
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
            utp_socket_socks: config.utp_socket_socks,
            utp_race_delay: config.utp_race_delay.unwrap_or(DEFAULT_UTP_RACE_DELAY),
            bind_device: config.bind_device,
            stats: Default::default(),
            ipv4_only: config.ipv4_only,
            encryption: config.encryption,
        })
    }

    /// The configured MSE/PE obfuscation policy.
    pub fn encryption(&self) -> Encryption {
        self.encryption
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
            // uTP-over-SOCKS configured AND TCP connect disabled => uTP only. Lets
            // `--disable-tcp-connect --experimental-utp-over-socks` force every
            // outbound peer over uTP, which is how we measure it in isolation (a
            // healthy swarm otherwise wins the SOCKS-TCP arm of the race below
            // every time, so uTP would never actually run).
            if !self.enable_tcp
                && let Some(usock) = self.utp_socket_socks.clone()
            {
                let conn = self
                    .with_stat(ConnectionKind::Utp, addr.is_ipv6(), usock.connect(addr))
                    .await
                    .map_err(Error::UtpConnect)?;
                debug!(?addr, "connected over uTP-over-SOCKS (tcp connect disabled)");
                let (r, w) = conn.split();
                return Ok((ConnectionKind::Utp, Box::new(r), Box::new(w)));
            }

            // Primary: SOCKS5 TCP CONNECT (mature, simple).
            let socks_tcp = async {
                let (r, w) = self
                    .with_stat(
                        ConnectionKind::Socks,
                        addr.is_ipv6(),
                        proxy.connect(addr, self.bind_device.as_ref()),
                    )
                    .await?;
                debug!(?addr, "connected through SOCKS5");
                Ok::<_, Error>((
                    ConnectionKind::Socks,
                    Box::new(r.into_vectored_compat()) as BoxAsyncReadVectored,
                    Box::new(w) as BoxAsyncWrite,
                ))
            };

            // Without uTP-over-SOCKS configured, behaviour is unchanged: SOCKS TCP only.
            let Some(usock) = self.utp_socket_socks.clone() else {
                return socks_tcp.await;
            };

            // Secondary: uTP relayed through the same SOCKS5 proxy. Give SOCKS TCP a
            // 1s head start (mirrors the direct TCP-vs-uTP race below), then race.
            let socks_failed_notify = tokio::sync::Notify::new();
            let socks_utp = async {
                tokio::select! {
                    _ = socks_failed_notify.notified() => {},
                    _ = tokio::time::sleep(self.utp_race_delay) => {}
                }
                let conn = self
                    .with_stat(ConnectionKind::Utp, addr.is_ipv6(), usock.connect(addr))
                    .await
                    .map_err(Error::UtpConnect)?;
                debug!(?addr, "connected over uTP-over-SOCKS");
                let (r, w) = conn.split();
                Ok::<_, Error>((
                    ConnectionKind::Utp,
                    Box::new(r) as BoxAsyncReadVectored,
                    Box::new(w) as BoxAsyncWrite,
                ))
            };

            tokio::pin!(socks_tcp);
            tokio::pin!(socks_utp);
            let mut tcp_err: Option<Error> = None;
            let mut utp_err: Option<Error> = None;
            loop {
                if tcp_err.is_some() && utp_err.is_some() {
                    // Both failed; surface the SOCKS TCP error (the primary path).
                    return Err(tcp_err.take().unwrap());
                }
                tokio::select! {
                    res = &mut socks_tcp, if tcp_err.is_none() => match res {
                        Ok(triple) => return Ok(triple),
                        Err(e) => {
                            tcp_err = Some(e);
                            socks_failed_notify.notify_waiters();
                        }
                    },
                    res = &mut socks_utp, if utp_err.is_none() => match res {
                        Ok(triple) => return Ok(triple),
                        Err(e) => utp_err = Some(e),
                    },
                }
            }
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
                    _ = tokio::time::sleep(self.utp_race_delay) => {}
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
