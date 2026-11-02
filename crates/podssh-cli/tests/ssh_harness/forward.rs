//! The forwards of the test's server: a direct-tcpip channel (`-W`, `podssh
//! pipe ssh:`) reaches its HOST:PORT from the server, each way with its
//! half-close; a direct-streamlocal channel to the socket `/echo` (T-040)
//! sends back what it gets, and one to another socket is refused. A hop that
//! hangs never answers a direct-tcpip open (T-462).

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

/// No answer to the open of `channel`, as a hop that hangs (T-462): the
/// reply is held, as its drop would refuse the open.
pub(super) fn never(channel: Channel<Msg>, reply: ChannelOpenHandle) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        drop((channel, reply));
    });
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
