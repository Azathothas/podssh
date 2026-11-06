//! The server's side of yamux, as frps runs fatedier/yamux (hashicorp's),
//! written here from its specification: a 12-byte header (version 0, type,
//! flags, stream id, length, big-endian), streams that the client opens with
//! a SYN, a window of 256 KiB each way that a WINDOW_UPDATE grows, a PING
//! answered with its ACK, and a GO_AWAY that ends the session. Each stream
//! is handed over as a pipe.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, Notify};

const DATA: u8 = 0;
const WINDOW_UPDATE: u8 = 1;
const PING: u8 = 2;
const GO_AWAY: u8 = 3;
const SYN: u16 = 1;
const ACK: u16 = 2;
const FIN: u16 = 4;
const RST: u16 = 8;
const WINDOW: u32 = 256 * 1024;
const CHUNK: usize = 16 * 1024;

fn header(kind: u8, flags: u16, stream: u32, length: u32) -> Vec<u8> {
    let mut h = vec![0, kind];
    h.extend_from_slice(&flags.to_be_bytes());
    h.extend_from_slice(&stream.to_be_bytes());
    h.extend_from_slice(&length.to_be_bytes());
    h
}

/// The room that the client gave a stream to send in.
struct Room {
    left: Mutex<u64>,
    grew: Notify,
}

struct Stream {
    to_user: mpsc::UnboundedSender<Option<Vec<u8>>>,
    room: Arc<Room>,
}

/// Serve yamux on `io` until it ends; each stream that the client opens
/// goes to `on_stream`.
pub async fn serve<IO, F>(io: IO, on_stream: F)
where
    IO: AsyncRead + AsyncWrite + Send + 'static,
    F: Fn(DuplexStream) + Send + Sync + 'static,
{
    let (mut r, mut w) = tokio::io::split(io);
    let (out, mut frames) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(frame) = frames.recv().await {
            if w.write_all(&frame).await.is_err() {
                return;
            }
        }
    });
    let mut streams: HashMap<u32, Stream> = HashMap::new();
    loop {
        let mut head = [0u8; 12];
        if r.read_exact(&mut head).await.is_err() || head[0] != 0 {
            return;
        }
        let kind = head[1];
        let flags = u16::from_be_bytes([head[2], head[3]]);
        let id = u32::from_be_bytes(head[4..8].try_into().unwrap());
        let length = u32::from_be_bytes(head[8..12].try_into().unwrap());
        if flags & SYN != 0 && (kind == DATA || kind == WINDOW_UPDATE) && !streams.contains_key(&id) {
            let room = Arc::new(Room { left: Mutex::new(u64::from(WINDOW)), grew: Notify::new() });
            let stream = open(id, out.clone(), room.clone(), &on_stream);
            streams.insert(id, Stream { to_user: stream, room });
            let _ = out.send(header(WINDOW_UPDATE, ACK, id, 0));
        }
        match kind {
            DATA => {
                let mut payload = vec![0u8; length as usize];
                if r.read_exact(&mut payload).await.is_err() {
                    return;
                }
                if let Some(s) = streams.get(&id) {
                    if !payload.is_empty() {
                        let _ = s.to_user.send(Some(payload));
                    }
                }
            }
            WINDOW_UPDATE => {
                if let Some(s) = streams.get(&id) {
                    // The window that the SYN carries counts from 256 KiB too.
                    if flags & SYN == 0 {
                        *s.room.left.lock().unwrap() += u64::from(length);
                        s.room.grew.notify_waiters();
                    }
                }
            }
            PING if flags & SYN != 0 => {
                let _ = out.send(header(PING, ACK, 0, length));
            }
            GO_AWAY => return,
            _ => {}
        }
        if flags & (FIN | RST) != 0 {
            if let Some(s) = streams.remove(&id) {
                let _ = s.to_user.send(None);
                // A pump that waits for room ends on its next send.
                *s.room.left.lock().unwrap() = u64::from(u32::MAX);
                s.room.grew.notify_waiters();
            }
        }
    }
}

/// A stream's pipe, and its two pumps: the client's bytes to the user, with
/// each one granted back once the user took it, and the user's bytes to the
/// client within the room that it gave.
fn open<F>(
    id: u32,
    out: mpsc::UnboundedSender<Vec<u8>>,
    room: Arc<Room>,
    on_stream: &F,
) -> mpsc::UnboundedSender<Option<Vec<u8>>>
where
    F: Fn(DuplexStream),
{
    let (user, ours) = tokio::io::duplex(1 << 20);
    let (mut ours_r, mut ours_w) = tokio::io::split(ours);
    let (to_user, mut from_client) = mpsc::unbounded_channel::<Option<Vec<u8>>>();
    let grants = out.clone();
    tokio::spawn(async move {
        while let Some(Some(bytes)) = from_client.recv().await {
            if ours_w.write_all(&bytes).await.is_err() {
                return;
            }
            let _ = grants.send(header(WINDOW_UPDATE, 0, id, bytes.len() as u32));
        }
        let _ = ours_w.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match ours_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut sent = 0;
            while sent < n {
                let take = loop {
                    let notified = room.grew.notified();
                    let left = *room.left.lock().unwrap();
                    if left > 0 {
                        break (left as usize).min(n - sent);
                    }
                    notified.await;
                };
                *room.left.lock().unwrap() -= take as u64;
                let mut frame = header(DATA, 0, id, take as u32);
                frame.extend_from_slice(&buf[sent..sent + take]);
                if out.send(frame).is_err() {
                    return;
                }
                sent += take;
            }
        }
        let _ = out.send(header(WINDOW_UPDATE, FIN, id, 0));
    });
    on_stream(user);
    to_user
}
