//! A stand-in of the Wisp demo server (T-438), behind the proxy as the
//! other stand-ins: version 1 of the protocol, as wisp-server-python speaks
//! it, written from the protocol's document. Its CONTINUE of 128 packets on
//! stream 0 first; each CONNECT dials the test's SSH server, whatever target
//! it names, or is closed with 0x42 when its name closes; another CONTINUE
//! after each 32 DATA written; a CLOSE 0x02 when the server ends.

use std::sync::Arc;

use podssh_ws::http::Request;
use podssh_ws::{frame, RelaySession};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use super::super::cloud_support::Stream;
use super::{Seen, Stands};

/// The demo server's name.
pub const HOST: &str = "wisp.mercurywork.shop";

/// The packets of credit of each stream.
const BUFFER: u32 = 128;

/// A packet: its type, its stream id (little-endian), its payload.
fn packet(kind: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// The connection, after the upgrade: one stream is what podssh opens.
pub(super) async fn carry(stands: &Stands, host: String, head: Request, session: Arc<RelaySession<Stream>>) {
    if session.send_binary(&packet(0x03, 0, &BUFFER.to_le_bytes())).await.is_err() {
        return;
    }
    let mut target: Option<OwnedWriteHalf> = None;
    let mut written: u32 = 0;
    while let Ok(f) = session.read_frame().await {
        if f.opcode == frame::OPCODE_CLOSE {
            break;
        }
        if f.opcode != frame::OPCODE_BINARY || f.payload.len() < 5 {
            continue;
        }
        let id = u32::from_le_bytes([f.payload[1], f.payload[2], f.payload[3], f.payload[4]]);
        let body = &f.payload[5..];
        match f.payload[0] {
            0x01 if body.len() >= 3 => {
                let port = u16::from_le_bytes([body[1], body[2]]);
                let name = String::from_utf8_lossy(&body[3..]).into_owned();
                let seen = Seen {
                    host: host.clone(),
                    path: head.target.clone(),
                    headers: head.headers.clone(),
                    target: (name, port),
                    first_frame: None,
                };
                stands.seen.lock().unwrap().push(seen);
                let closing = stands.closing.lock().unwrap().contains(&host);
                let dialed = match closing {
                    true => None,
                    false => TcpStream::connect(("127.0.0.1", stands.sshd)).await.ok(),
                };
                match dialed {
                    Some(sshd) => {
                        let (rd, wr) = sshd.into_split();
                        target = Some(wr);
                        tokio::spawn(back(session.clone(), id, rd));
                    }
                    // wisp-server-python's one reason for a stream it cannot open.
                    None => {
                        let _ = session.send_binary(&packet(0x04, id, &[0x42])).await;
                    }
                }
            }
            0x02 => {
                let Some(wr) = target.as_mut() else { continue };
                if wr.write_all(body).await.is_err() {
                    break;
                }
                written += 1;
                if written.is_multiple_of(32) {
                    let _ = session.send_binary(&packet(0x03, id, &BUFFER.to_le_bytes())).await;
                }
            }
            // Dropped, the write half ends the server's input.
            0x04 => target = None,
            _ => {}
        }
    }
}

/// The server's bytes in DATA, then a CLOSE 0x02 at its end.
async fn back(session: Arc<RelaySession<Stream>>, id: u32, mut rd: OwnedReadHalf) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if session.send_binary(&packet(0x02, id, &buf[..n])).await.is_err() {
                    return;
                }
            }
        }
    }
    let _ = session.send_binary(&packet(0x04, id, &[0x02])).await;
}
