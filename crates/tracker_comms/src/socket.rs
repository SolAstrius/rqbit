use std::net::SocketAddr;

use futures::future::BoxFuture;

/// Abstraction over the UDP socket the UDP tracker client uses.
///
/// Defaults to a plain dual-stack UDP socket, but a caller can inject an
/// alternative transport (e.g. one tunneling datagrams through a SOCKS5 proxy)
/// when constructing [`crate::UdpTrackerClient`].
pub trait UdpTransport: Send + Sync {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> BoxFuture<'a, std::io::Result<usize>>;

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, std::io::Result<(usize, SocketAddr)>>;
}

impl UdpTransport for librqbit_dualstack_sockets::UdpSocket {
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
}
