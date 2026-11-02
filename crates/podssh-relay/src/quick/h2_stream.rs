//! A stream of HTTP/2 between the node and the edge (T-300): bytes sent as
//! the edge's window lets them go, and a visitor's WebSocket on a stream as
//! one end of a pipe of its messages' bytes. Apart from `serve.rs` for the
//! length of that file, and shared with the node's origin (T-428).

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use podssh_ws::frame::{self, Frame, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::watch;

/// The buffer of each bridge between a stream and its user.
const PIPE: usize = 64 * 1024;

/// Send `bytes` on `send` as the edge's window lets them go.
pub(super) async fn send_all(send: &mut SendStream<Bytes>, mut bytes: &[u8]) -> Result<(), h2::Error> {
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len());
        let room = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(room)) => room,
            Some(Err(e)) => return Err(e),
            None => return Err(h2::Error::from(h2::Reason::CANCEL)),
        };
        let take = room.min(bytes.len());
        if take == 0 {
            continue;
        }
        send.send_data(Bytes::copy_from_slice(&bytes[..take]), false)?;
        bytes = &bytes[take..];
    }
    Ok(())
}

/// A visitor's WebSocket on a stream: the bytes of its messages, both ways,
/// as one end of a pipe. Pings get their pongs; a close, or the end of the
/// stream, ends the pipe.
pub(super) fn websocket(mut recv: RecvStream, mut send: SendStream<Bytes>) -> DuplexStream {
    let (user, ours) = tokio::io::duplex(PIPE);
    let (mut from_user, mut to_user) = tokio::io::split(ours);
    // The latest ping's payload only: RFC 6455, section 5.5.3, lets an end
    // answer the most recent of the pings that wait, so a visitor that
    // pings while the writer waits for the edge's window holds one payload.
    let (pongs, mut pongs_due) = watch::channel::<Option<Vec<u8>>>(None);
    // The visitor's frames, masked as a client writes them, to the user.
    tokio::spawn(async move {
        let mut inbox = Vec::new();
        while let Some(Ok(chunk)) = recv.data().await {
            let _ = recv.flow_control().release_capacity(chunk.len());
            inbox.extend_from_slice(&chunk);
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
                            0x8 => {
                                let _ = to_user.shutdown().await;
                                return;
                            }
                            _ => {}
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return,
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
                            let _ = send_all(&mut send, &frame::encode(&close, Role::Server, [0; 4])).await;
                            let _ = send.send_data(Bytes::new(), true);
                            return;
                        }
                        Ok(n) => n,
                    };
                    let message = Frame { fin: true, opcode: 0x2, payload: buf[..n].to_vec() };
                    if send_all(&mut send, &frame::encode(&message, Role::Server, [0; 4])).await.is_err() {
                        return;
                    }
                }
                Ok(()) = pongs_due.changed() => {
                    let Some(payload) = pongs_due.borrow_and_update().clone() else { continue };
                    let pong = Frame { fin: true, opcode: 0xA, payload };
                    if send_all(&mut send, &frame::encode(&pong, Role::Server, [0; 4])).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    user
}
