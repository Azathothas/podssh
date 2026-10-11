//! The forwards of the test's server: a direct-tcpip channel (`-W`, `podssh
//! pipe ssh:`) reaches its HOST:PORT from the server, each way with its
//! half-close; a direct-streamlocal channel to the socket `/echo` (T-040)
//! sends back what it gets, and one to another socket is refused.

use russh::server::{ChannelOpenHandle, Msg};
use russh::Channel;

/// A direct-tcpip channel to `host`:`port`.
pub(super) async fn tcpip(channel: Channel<Msg>, host: &str, port: u32, reply: ChannelOpenHandle) {
    match tokio::net::TcpStream::connect(format!("{host}:{port}")).await {
        Ok(mut tcp) => {
            reply.accept().await;
            tokio::spawn(async move {
                let mut stream = channel.into_stream();
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
            });
        }
        Err(_) => reply.reject(russh::ChannelOpenFailure::ConnectFailed).await,
    }
}

/// A direct-streamlocal channel to `socket_path`.
pub(super) async fn streamlocal(channel: Channel<Msg>, socket_path: &str, reply: ChannelOpenHandle) {
    if socket_path != "/echo" {
        reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
        return;
    }
    reply.accept().await;
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let (mut from, mut to) = tokio::io::split(channel.into_stream());
        let _ = tokio::io::copy(&mut from, &mut to).await;
        let _ = to.shutdown().await;
    });
}
