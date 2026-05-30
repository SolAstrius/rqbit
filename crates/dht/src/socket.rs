use std::net::SocketAddr;

use futures::future::BoxFuture;

/// Abstraction over the UDP socket the DHT uses to exchange packets.
///
/// The default implementation is a plain dual-stack UDP socket. Callers may
/// inject an alternative transport (for example one that tunnels datagrams
/// through a SOCKS5 proxy) via [`crate::DhtConfig::socket`]; the DHT itself
/// stays unaware of how packets actually reach the wire.
pub trait DhtSocket: Send + Sync {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, std::io::Result<usize>>;

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, std::io::Result<(usize, SocketAddr)>>;

    fn bind_addr(&self) -> SocketAddr;
}

impl DhtSocket for librqbit_dualstack_sockets::UdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, std::io::Result<usize>> {
        Box::pin(librqbit_dualstack_sockets::UdpSocket::send_to(
            self, buf, target,
        ))
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, std::io::Result<(usize, SocketAddr)>> {
        Box::pin(librqbit_dualstack_sockets::UdpSocket::recv_from(self, buf))
    }

    fn bind_addr(&self) -> SocketAddr {
        librqbit_dualstack_sockets::UdpSocket::bind_addr(self)
    }
}
