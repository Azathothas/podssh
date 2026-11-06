//! yamux's client side, as frpc runs it on its connection to frps: frpc
//! opens each stream (the control stream, then each work and visitor
//! connection, odd ids from 1), and frps opens none. Each stream is a
//! `DuplexStream` to its user. Its sending waits for the window that frps
//! grants; its receiving grants the bytes back once its user's side of the
//! pipe took them, so that a slow reader holds frps, not podssh's memory.
//! A ping of frps is answered; a go-away or the connection's end ends each
//! stream, and [`Mux::closed`] says why.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, watch, Notify};

use super::mux_frame::{self as frame, Header};

/// The pipe between a stream's user and its pump: the largest read that
/// becomes one data frame, and the room of the pipe.
const CHUNK: usize = 16 * 1024;
const PIPE: usize = 64 * 1024;

/// What the reader hands a stream's pump.
enum Inbound {
    Data(Vec<u8>),
    Fin,
    Rst,
}

/// The window that frps granted a stream for its sending.
struct Window {
    room: Mutex<u32>,
    grew: Notify,
}

impl Window {
    /// Take up to `want` bytes of room, waiting while there is none.
    async fn take(&self, want: usize) -> usize {
        loop {
            let granted = self.grew.notified();
            {
                let mut room = self.room.lock().unwrap_or_else(|e| e.into_inner());
                if *room > 0 {
                    let n = (*room as usize).min(want);
                    *room -= n as u32;
                    return n;
                }
            }
            granted.await;
        }
    }

    fn grant(&self, delta: u32) {
        let mut room = self.room.lock().unwrap_or_else(|e| e.into_inner());
        *room = room.saturating_add(delta);
        self.grew.notify_waiters();
    }
}

struct Stream {
    inbox: mpsc::UnboundedSender<Inbound>,
    window: Arc<Window>,
}

struct Shared {
    streams: Mutex<HashMap<u32, Stream>>,
    frames: mpsc::UnboundedSender<Vec<u8>>,
    next: AtomicU32,
    closed: watch::Sender<Option<String>>,
}

impl Shared {
    fn send(&self, bytes: Vec<u8>) {
        let _ = self.frames.send(bytes);
    }

    fn end(&self, why: String) {
        self.closed.send_if_modified(|now| {
            if now.is_some() {
                return false;
            }
            *now = Some(why);
            true
        });
        // Each stream's pump ends, and so does its user's side.
        for (_, stream) in self.streams.lock().unwrap_or_else(|e| e.into_inner()).drain() {
            let _ = stream.inbox.send(Inbound::Rst);
            stream.window.grant(u32::MAX);
        }
    }
}

/// A yamux session of frpc's side on one connection.
#[derive(Clone)]
pub struct Mux(Arc<Shared>);

impl Mux {
    /// The session on `io`: its writer and its reader run as tasks for as
    /// long as the connection lasts.
    pub fn client<S>(io: S) -> Mux
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (read, mut write) = tokio::io::split(io);
        let (frames, mut queued) = mpsc::unbounded_channel::<Vec<u8>>();
        let (closed, _) = watch::channel(None);
        let shared = Arc::new(Shared { streams: Mutex::new(HashMap::new()), frames, next: AtomicU32::new(1), closed });
        let writer = Arc::downgrade(&shared);
        tokio::spawn(async move {
            while let Some(bytes) = queued.recv().await {
                if let Err(e) = write.write_all(&bytes).await {
                    if let Some(shared) = writer.upgrade() {
                        shared.end(format!("the connection to frps failed: {e}"));
                    }
                    return;
                }
                if queued.is_empty() && write.flush().await.is_err() {
                    return;
                }
            }
        });
        tokio::spawn(read_loop(read, shared.clone()));
        Mux(shared)
    }

    /// A new stream, opened at once: frps sees it with its first frame.
    pub fn open(&self) -> Result<DuplexStream, String> {
        if let Some(why) = self.0.closed.borrow().clone() {
            return Err(why);
        }
        let id = self.0.next.fetch_add(2, Ordering::SeqCst);
        let (inbox, rx) = mpsc::unbounded_channel();
        let window = Arc::new(Window { room: Mutex::new(frame::INITIAL_WINDOW), grew: Notify::new() });
        self.0.streams.lock().unwrap_or_else(|e| e.into_inner()).insert(id, Stream { inbox, window: window.clone() });
        self.0.send(frame::window(id, frame::SYN, 0));
        let (user, ours) = tokio::io::duplex(PIPE);
        tokio::spawn(pump(id, ours, rx, window, self.0.clone()));
        Ok(user)
    }

    /// Why the session ended, once it did.
    pub async fn closed(&self) -> String {
        let mut rx = self.0.closed.subscribe();
        loop {
            if let Some(why) = rx.borrow().clone() {
                return why;
            }
            if rx.changed().await.is_err() {
                return "the yamux session ended".into();
            }
        }
    }

    /// Whether the session has ended.
    pub fn is_closed(&self) -> bool {
        self.0.closed.borrow().is_some()
    }

    /// End the session: a go-away, then each stream ends.
    pub fn close(&self) {
        self.0.send(frame::Header::new(frame::GO_AWAY, 0, 0, 0).encode().to_vec());
        self.0.end("podssh ended the session".into());
    }
}

/// Read frps's frames until the connection ends.
async fn read_loop<R: AsyncRead + Unpin>(mut read: R, shared: Arc<Shared>) {
    let why = loop {
        let mut head = [0u8; frame::HEADER];
        if let Err(e) = read.read_exact(&mut head).await {
            break format!("frps ended the connection ({e})");
        }
        let header = match Header::decode(&head) {
            Ok(header) => header,
            Err(why) => break why,
        };
        match header.kind {
            frame::DATA => {
                let mut payload = vec![0u8; header.length as usize];
                if let Err(e) = read.read_exact(&mut payload).await {
                    break format!("frps ended the connection inside a frame ({e})");
                }
                deliver(&shared, &header, Some(payload));
            }
            frame::WINDOW_UPDATE => {
                if let Some(stream) = shared.streams.lock().unwrap_or_else(|e| e.into_inner()).get(&header.stream) {
                    stream.window.grant(header.length);
                }
                deliver(&shared, &header, None);
            }
            frame::PING if header.has(frame::SYN) => {
                shared.send(Header::new(frame::PING, frame::ACK, 0, header.length).encode().to_vec());
            }
            frame::PING => {}
            _ => break format!("frps went away: {}", frame::go_away_words(header.length)),
        }
    };
    shared.end(why);
}

/// Hand a frame's payload and its end to its stream; a stream that frps
/// opened, which frpc never takes, is refused.
fn deliver(shared: &Shared, header: &Header, payload: Option<Vec<u8>>) {
    if header.has(frame::SYN) && header.stream.is_multiple_of(2) {
        shared.send(frame::window(header.stream, frame::RST, 0));
        return;
    }
    let mut streams = shared.streams.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = streams.get(&header.stream) else { return };
    if let Some(payload) = payload.filter(|p| !p.is_empty()) {
        let _ = stream.inbox.send(Inbound::Data(payload));
    }
    if header.has(frame::RST) {
        let _ = stream.inbox.send(Inbound::Rst);
        stream.window.grant(u32::MAX);
        streams.remove(&header.stream);
    } else if header.has(frame::FIN) {
        let _ = stream.inbox.send(Inbound::Fin);
    }
}

/// Carry one stream between its user's pipe and the session.
async fn pump(
    id: u32,
    ours: DuplexStream,
    mut inbox: mpsc::UnboundedReceiver<Inbound>,
    window: Arc<Window>,
    shared: Arc<Shared>,
) {
    let (mut from_user, mut to_user) = tokio::io::split(ours);
    let up_shared = shared.clone();
    let up = async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match from_user.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    up_shared.send(frame::data(id, frame::FIN, &[]));
                    return;
                }
                Ok(n) => n,
            };
            let mut sent = 0;
            while sent < n {
                let room = window.take(n - sent).await;
                if up_shared.closed.borrow().is_some() {
                    return;
                }
                up_shared.send(frame::data(id, 0, &buf[sent..sent + room]));
                sent += room;
            }
        }
    };
    let down_shared = shared.clone();
    let down = async move {
        while let Some(inbound) = inbox.recv().await {
            match inbound {
                Inbound::Data(bytes) => {
                    if to_user.write_all(&bytes).await.is_err() {
                        down_shared.send(frame::window(id, frame::RST, 0));
                        return;
                    }
                    // The user's side took them: frps may send as many more.
                    down_shared.send(frame::window(id, 0, bytes.len() as u32));
                }
                Inbound::Fin => {
                    let _ = to_user.shutdown().await;
                    return;
                }
                Inbound::Rst => return,
            }
        }
    };
    tokio::join!(up, down);
    shared.streams.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
}
