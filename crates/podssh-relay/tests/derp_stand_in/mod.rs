//! A stand-in DERP server for the tests of the DERP road (T-349), over pipes
//! in memory: no listener. It answers the WebSocket upgrade at `/derp` with
//! the subprotocol `derp`, runs DERP's handshake as derper does
//! (tailscale/tailscale:derp/derpserver/derpserver.go at v1.104.4): its key,
//! the client's info opened with NaCl's box, its own info sealed back; then
//! it forwards each packet to the key that it names, through a queue of 32
//! for each receiver whose oldest packet goes when it is full, and drops a
//! share of the packets at random, by a seed. It answers pings, and derper's
//! probe at `/derp/probe`. Its frames are written here, apart from the
//! library's, so that a defect of one is not the other's. The tests of the
//! command line serve it over TLS on the loopback (T-379).

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crypto_box::aead::Aead;
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use podssh_relay::derp::dial::{BoxIo, Dial, Dialing};
use podssh_relay::derp::Server;
use podssh_ws::frame::{self, Frame, Role, OPCODE_BINARY, OPCODE_CLOSE};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::Notify;

const MAGIC: &[u8] = b"DERP\xF0\x9F\x94\x91";
const QUEUE: usize = 32;
const PIPE: usize = 1 << 20;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// A DERP frame: the type, the length, the body.
fn derp(kind: u8, body: &[u8]) -> Vec<u8> {
    [&[kind][..], &(body.len() as u32).to_be_bytes()[..], body].concat()
}

/// The frames that wait for one client, the oldest dropped past 32.
#[derive(Default)]
struct Queue {
    frames: Mutex<VecDeque<Vec<u8>>>,
    ready: Notify,
}

impl Queue {
    /// Whether a frame was dropped to make room.
    fn push(&self, frame: Vec<u8>) -> bool {
        let mut frames = lock(&self.frames);
        let full = frames.len() >= QUEUE;
        if full {
            frames.pop_front();
        }
        frames.push_back(frame);
        drop(frames);
        self.ready.notify_one();
        full
    }

    async fn pop(&self) -> Vec<u8> {
        loop {
            if let Some(frame) = lock(&self.frames).pop_front() {
                return frame;
            }
            self.ready.notified().await;
        }
    }
}

struct Client {
    queue: Arc<Queue>,
    cut: Arc<Notify>,
}

pub struct StandIn {
    secret: SecretKey,
    public: [u8; 32],
    clients: Mutex<HashMap<[u8; 32], Client>>,
    drop_percent: u64,
    dice: Mutex<u64>,
    /// Packets forwarded, dropped at random, and dropped by a full queue.
    pub forwarded: AtomicUsize,
    pub dropped: AtomicUsize,
    pub overflowed: AtomicUsize,
    /// The connections that completed DERP's handshake.
    pub logins: AtomicUsize,
}

impl StandIn {
    pub fn new(drop_percent: u64) -> Arc<StandIn> {
        let secret = SecretKey::from_bytes([0x5a; 32]);
        let public = secret.public_key().to_bytes();
        Arc::new(StandIn {
            secret,
            public,
            clients: Mutex::new(HashMap::new()),
            drop_percent,
            dice: Mutex::new(0x2545_f491_4f6c_dd1d),
            forwarded: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
            overflowed: AtomicUsize::new(0),
            logins: AtomicUsize::new(0),
        })
    }

    /// The server's name in the tests.
    pub fn server() -> Server {
        Server::new("derp.test", 443).expect("a server name")
    }

    /// A pipe to the stand-in, which serves its other end.
    pub fn connect(self: &Arc<Self>) -> BoxIo {
        let (ours, theirs) = tokio::io::duplex(PIPE);
        let me = self.clone();
        tokio::spawn(async move { me.serve(theirs).await });
        Box::new(ours)
    }

    /// A dial of the road that reaches the stand-in, whatever the server.
    pub fn dial(self: &Arc<Self>) -> Dial {
        let me = self.clone();
        Arc::new(move |_: &Server| -> Dialing {
            let io = me.connect();
            Box::pin(async move { Ok(io) })
        })
    }

    /// End the connection of the client of `key`, as a lost link does.
    pub fn cut(&self, key: &[u8; 32]) {
        if let Some(client) = lock(&self.clients).get(key) {
            client.cut.notify_one();
        }
    }

    pub fn connected(&self) -> usize {
        lock(&self.clients).len()
    }

    fn roll(&self) -> u64 {
        let mut dice = lock(&self.dice);
        *dice ^= *dice >> 12;
        *dice ^= *dice << 25;
        *dice ^= *dice >> 27;
        dice.wrapping_mul(0x2545_f491_4f6c_dd1d) % 100
    }

    async fn serve(self: Arc<Self>, io: DuplexStream) {
        let (mut reader, mut writer) = tokio::io::split(io);
        let Some(mut ws) = upgrade(&mut reader, &mut writer).await else { return };
        let mut stream = Vec::new();
        if message(&mut writer, &derp(0x01, &[MAGIC, &self.public[..]].concat())).await.is_err() {
            return;
        }
        let Some((0x02, info)) = next(&mut reader, &mut ws, &mut stream).await else { return };
        if info.len() < 32 + 24 + 16 {
            return;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&info[..32]);
        let opener = SalsaBox::new(&PublicKey::from(key), &self.secret);
        let nonce = crypto_box::Nonce::from(<[u8; 24]>::try_from(&info[32..56]).expect("24 bytes"));
        let Ok(json) = opener.decrypt(&nonce, &info[56..]) else { return };
        if !String::from_utf8_lossy(&json).contains("\"version\":2") {
            return;
        }
        let answer = [9u8; 24];
        let sealed = opener.encrypt(&crypto_box::Nonce::from(answer), &b"{\"version\":2}"[..]).expect("a box");
        if message(&mut writer, &derp(0x03, &[&answer[..], &sealed[..]].concat())).await.is_err() {
            return;
        }
        self.logins.fetch_add(1, Ordering::SeqCst);
        let queue = Arc::new(Queue::default());
        let cut = Arc::new(Notify::new());
        lock(&self.clients).insert(key, Client { queue: queue.clone(), cut: cut.clone() });
        let writing = tokio::spawn({
            let queue = queue.clone();
            async move {
                loop {
                    let frame = queue.pop().await;
                    if message(&mut writer, &frame).await.is_err() {
                        return;
                    }
                }
            }
        });
        loop {
            let frame = tokio::select! {
                frame = next(&mut reader, &mut ws, &mut stream) => frame,
                () = cut.notified() => None,
            };
            let Some((kind, body)) = frame else { break };
            match kind {
                0x04 if body.len() >= 32 => self.forward(&key, &body),
                0x12 if body.len() >= 8 => {
                    queue.push(derp(0x13, &body[..8]));
                }
                _ => {}
            }
        }
        writing.abort();
        let mut clients = lock(&self.clients);
        if clients.get(&key).is_some_and(|c| Arc::ptr_eq(&c.queue, &queue)) {
            clients.remove(&key);
        }
    }

    fn forward(&self, from: &[u8; 32], body: &[u8]) {
        if self.roll() < self.drop_percent {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            return;
        }
        let mut to = [0u8; 32];
        to.copy_from_slice(&body[..32]);
        let Some(queue) = lock(&self.clients).get(&to).map(|c| c.queue.clone()) else { return };
        self.forwarded.fetch_add(1, Ordering::SeqCst);
        if queue.push(derp(0x05, &[&from[..], &body[32..]].concat())) {
            self.overflowed.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// The upgrade: the request read and checked, the 101 written; the bytes
/// after the request, the start of the WebSocket.
async fn upgrade(reader: &mut ReadHalf<DuplexStream>, writer: &mut WriteHalf<DuplexStream>) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = reader.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    // derper's probe of latency, an empty answer, by which a node of the
    // command line finds its home (T-379).
    if head.starts_with("GET /derp/probe HTTP/1.1\r\n") {
        let _ = writer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        let _ = writer.shutdown().await;
        return None;
    }
    let header = |name: &str| {
        head.split("\r\n").find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string())
        })
    };
    let wants_derp = header("sec-websocket-protocol").is_some_and(|p| p.split(',').any(|p| p.trim() == "derp"));
    if !head.starts_with("GET /derp HTTP/1.1\r\n") || !wants_derp {
        let _ = writer.write_all(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n").await;
        return None;
    }
    let accept = podssh_ws::handshake::accept_key(&header("sec-websocket-key")?);
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: derp\r\n\r\n"
    );
    writer.write_all(answer.as_bytes()).await.ok()?;
    Some(buf.split_off(end))
}

/// One binary message of the server's, unmasked.
async fn message(writer: &mut WriteHalf<DuplexStream>, payload: &[u8]) -> std::io::Result<()> {
    let frame = Frame { fin: true, opcode: OPCODE_BINARY, payload: payload.to_vec() };
    writer.write_all(&frame::encode(&frame, Role::Server, [0; 4])).await
}

/// The next DERP frame of the client's: its type and body; `None` at the
/// end of the connection.
async fn next(reader: &mut ReadHalf<DuplexStream>, ws: &mut Vec<u8>, stream: &mut Vec<u8>) -> Option<(u8, Vec<u8>)> {
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        if stream.len() >= 5 {
            let len = u32::from_be_bytes([stream[1], stream[2], stream[3], stream[4]]) as usize;
            if stream.len() >= 5 + len {
                let kind = stream[0];
                let body = stream[5..5 + len].to_vec();
                stream.drain(..5 + len);
                return Some((kind, body));
            }
        }
        match frame::decode(ws, Role::Client) {
            Ok(Some((frame, used))) => {
                ws.drain(..used);
                match frame.opcode {
                    OPCODE_BINARY => stream.extend_from_slice(&frame.payload),
                    OPCODE_CLOSE => return None,
                    _ => {}
                }
            }
            Ok(None) => {
                let n = reader.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                ws.extend_from_slice(&chunk[..n]);
            }
            Err(_) => return None,
        }
    }
}
