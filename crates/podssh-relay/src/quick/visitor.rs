//! A visitor's WebSocket on a stream that reads and writes (T-301), as a QUIC
//! stream of the edge is one: the bytes of its messages, both ways, as one end
//! of a pipe. The same rules as `serve.rs`'s for HTTP/2: podssh is the
//! WebSocket's server, so its frames go unmasked (RFC 6455, section 5.1);
//! pings get their pongs; a close, or the end of the stream, ends the pipe.

use podssh_ws::frame::{self, Frame, Role};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::watch;

/// The buffer of the bridge, each way.
const PIPE: usize = 64 * 1024;

/// The visitor's WebSocket on `from_edge` and `to_edge`, as the user's end
/// of a pipe of its bytes.
pub fn websocket<R, W>(mut from_edge: R, mut to_edge: W) -> DuplexStream
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (user, ours) = tokio::io::duplex(PIPE);
    let (mut from_user, mut to_user) = tokio::io::split(ours);
    // The latest ping's payload only (RFC 6455, section 5.5.3): a visitor
    // that pings while the writer waits holds one payload.
    let (pongs, mut pongs_due) = watch::channel::<Option<Vec<u8>>>(None);
    // The visitor's frames, masked as a client writes them, to the user.
    tokio::spawn(async move {
        let (mut inbox, mut chunk) = (Vec::new(), vec![0u8; PIPE]);
        'read: loop {
            let n = match from_edge.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            inbox.extend_from_slice(&chunk[..n]);
            loop {
                match frame::decode(&inbox, Role::Client) {
                    Ok(Some((frame, used))) => {
                        inbox.drain(..used);
                        match frame.opcode {
                            // A continuation, a text or a binary message.
                            0x0..=0x2 => {
                                if to_user.write_all(&frame.payload).await.is_err() {
                                    return;
                                }
                            }
                            0x9 => {
                                pongs.send_replace(Some(frame.payload));
                            }
                            0x8 => break 'read,
                            _ => {}
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break 'read,
                }
            }
        }
        let _ = to_user.shutdown().await;
    });
    // The user's bytes, as binary messages unmasked, to the visitor.
    tokio::spawn(async move {
        let mut buf = vec![0u8; PIPE];
        loop {
            tokio::select! {
                n = from_user.read(&mut buf) => {
                    let n = match n {
                        Ok(0) | Err(_) => {
                            let close = Frame { fin: true, opcode: 0x8, payload: 1000u16.to_be_bytes().to_vec() };
                            let _ = to_edge.write_all(&frame::encode(&close, Role::Server, [0; 4])).await;
                            let _ = to_edge.shutdown().await;
                            return;
                        }
                        Ok(n) => n,
                    };
                    let message = Frame { fin: true, opcode: 0x2, payload: buf[..n].to_vec() };
                    if to_edge.write_all(&frame::encode(&message, Role::Server, [0; 4])).await.is_err() {
                        return;
                    }
                }
                Ok(()) = pongs_due.changed() => {
                    let Some(payload) = pongs_due.borrow_and_update().clone() else { continue };
                    let pong = Frame { fin: true, opcode: 0xA, payload };
                    if to_edge.write_all(&frame::encode(&pong, Role::Server, [0; 4])).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    user
}
