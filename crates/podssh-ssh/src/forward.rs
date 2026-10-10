//! `-W HOST:PORT`: the server opens a TCP connection and podssh's stdin and
//! stdout become that stream. Nothing listens locally, which is why this is
//! the forwarding podssh offers. Also how `-J` reaches each next hop.

use russh::client::Handle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::handler::Client;
use crate::log::Log;

/// Open `host:port` from the server; the caller wraps the channel in a stream.
pub async fn open(
    handle: &Handle<Client>,
    host: &str,
    port: u16,
) -> Result<russh::ChannelStream<russh::client::Msg>, String> {
    handle.channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0).await.map(|c| c.into_stream()).map_err(
        |e| format!("the server could not open a connection to {}: {e}", podssh_ws::dial::authority(host, port)),
    )
}

/// Copy stdin to the stream and the stream to stdout until the far side
/// closes. Returns the exit code: 0 for a normal close.
pub async fn stdio(handle: &Handle<Client>, host: &str, port: u16, log: &Log) -> i32 {
    let stream = match open(handle, host, port).await {
        Ok(s) => s,
        Err(why) => {
            log.error(&why);
            return crate::run::EXIT_FAILURE;
        }
    };
    let (mut from_far, mut to_far) = tokio::io::split(stream);
    let up = async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_far.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
        // End of stdin: send EOF and keep receiving.
        let _ = to_far.shutdown().await;
    };
    let down = async move {
        let mut stdout = tokio::io::stdout();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match from_far.read(&mut buf).await {
                Ok(0) => return 0,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).await.is_err() || stdout.flush().await.is_err() {
                        return 0;
                    }
                }
                Err(e) => {
                    log.error(&format!("the forwarded connection failed: {e}"));
                    return crate::run::EXIT_FAILURE;
                }
            }
        }
    };
    tokio::pin!(up);
    tokio::pin!(down);
    let mut sending = true;
    let code = loop {
        tokio::select! {
            _ = &mut up, if sending => sending = false,
            code = &mut down => break code,
        }
    };
    // russh ends a channel's stream the same way whether the far side closed
    // it or the whole connection died; only the second is a failure.
    if code == 0 && handle.is_closed() {
        let cause = crate::handler::take_last_error().map(|c| format!(": {c}")).unwrap_or_default();
        log.error(&format!(
            "the connection was lost while forwarding to {}{cause}",
            podssh_ws::dial::authority(host, port)
        ));
        return crate::run::EXIT_FAILURE;
    }
    code
}
