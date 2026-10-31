//! One connection to a DERP server, and the links on it. The handshake is
//! DERP's: the server's key, this end's key with its info sealed to it, the
//! server's info sealed back. Then a reader gives each packet to its link,
//! answers the server's pings, and ends the links of a peer that the server
//! says is gone; it never waits for a link, as derper drops a client that
//! reads nothing for 2 s (`DefaultTCPWiteTimeout`). A writer sends the
//! control packets (`OPEN`, `ACK`, `RESET`, pongs) before the `DATA`, pings
//! the server each [`PING_EVERY`], and keeps to the rate that a server names
//! in its info. A node takes the links that clients open ([`Conn::accept`]);
//! a client opens them ([`Conn::open_link`]).

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior};

use super::dial::{self, BoxIo};
use super::frame::{self, Decoder, Frame};
use super::key::{self, Key, Secret, ServerInfo};
use super::link::{self, Link, Shared};
use super::packet::{self, Body, LinkId, Packet};
use super::servers::Server;
use super::Say;
use crate::session::secret::{Entropy, OsEntropy};

/// The bound of each step of DERP's handshake, as derper bounds its own.
pub const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);
/// How often this end pings the server, which answers each ping: a read
/// that waits longer than [`dial::IDLE_LIMIT`] finds a dead link.
pub const PING_EVERY: Duration = Duration::from_secs(10);
/// The most links on one connection, and from one peer.
pub const MAX_LINKS: usize = 256;
pub const MAX_PER_PEER: usize = 32;
/// The frames that wait for the writer, of each kind.
const QUEUE: usize = 64;
/// The most `RESET`s each second for packets of links that this end has not.
const RESETS_PER_SECOND: u32 = 10;

/// What a connection is for.
pub struct Setup {
    pub secret: Arc<Secret>,
    /// A node takes the links that clients open; a client takes none.
    pub serves: bool,
    pub say: Say,
}

/// A connection to a DERP server. Its clones are one connection; it ends
/// when [`Conn::close`] is called, when the server ends it, or when its last
/// clone goes.
#[derive(Clone)]
pub struct Conn {
    inner: Arc<Inner>,
}

struct Inner {
    server: Server,
    me: Key,
    server_key: Key,
    info: ServerInfo,
    ctl: mpsc::Sender<Vec<u8>>,
    data: mpsc::Sender<Vec<u8>>,
    links: Mutex<HashMap<(Key, LinkId), Arc<Shared>>>,
    incoming: Option<(mpsc::Sender<Link>, tokio::sync::Mutex<mpsc::Receiver<Link>>)>,
    ended: watch::Sender<Option<String>>,
    say: Say,
    resets: Mutex<(Instant, u32)>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Conn {
    /// DERP over `io`, a stream to `server`: the WebSocket, the handshake,
    /// and the tasks that read and write.
    pub async fn start(server: Server, io: BoxIo, setup: Setup) -> Result<Conn, String> {
        let session = dial::upgrade(io, &server).await?;
        let mut decoder = Decoder::new();
        let (server_key, info) = handshake(&session, &mut decoder, &setup.secret, &server).await?;
        let (ctl, ctl_rx) = mpsc::channel(QUEUE);
        let (data, data_rx) = mpsc::channel(QUEUE);
        let incoming = setup.serves.then(|| {
            let (sender, receiver) = mpsc::channel(QUEUE);
            (sender, tokio::sync::Mutex::new(receiver))
        });
        let (ended, _) = watch::channel(None);
        let inner = Arc::new(Inner {
            server,
            me: setup.secret.public(),
            server_key,
            info,
            ctl,
            data,
            links: Mutex::new(HashMap::new()),
            incoming,
            ended,
            say: setup.say,
            resets: Mutex::new((Instant::now(), 0)),
        });
        let session = Arc::new(session);
        let (read_end, write_end) = (inner.ended.subscribe(), inner.ended.subscribe());
        tokio::spawn(read_loop(Arc::downgrade(&inner), session.clone(), decoder, read_end));
        tokio::spawn(write_loop(Arc::downgrade(&inner), session, ctl_rx, data_rx, write_end, info));
        Ok(Conn { inner })
    }

    pub fn server(&self) -> &Server {
        &self.inner.server
    }

    /// This end's key on the server.
    pub fn key(&self) -> Key {
        self.inner.me
    }

    pub fn server_key(&self) -> Key {
        self.inner.server_key
    }

    pub fn info(&self) -> ServerInfo {
        self.inner.info
    }

    /// Why the connection ended; `None` while it lives.
    pub fn why_ended(&self) -> Option<String> {
        self.inner.ended.borrow().clone()
    }

    /// Until the connection ended: why, in a sentence.
    pub async fn ended(&self) -> String {
        let mut seen = self.inner.ended.subscribe();
        let why = match seen.wait_for(Option::is_some).await {
            Ok(why) => why.clone().unwrap_or_default(),
            Err(_) => "it closed".to_string(),
        };
        format!("the connection to the DERP server {} ended: {why}", self.inner.server)
    }

    /// End the connection, and each link on it.
    pub fn close(&self) {
        self.inner.end("this end closed it".to_string());
    }

    /// The links on the connection.
    pub fn links(&self) -> usize {
        lock(&self.inner.links).len()
    }

    /// A new link to the end of `peer`, whose `OPEN` goes at once; it is the
    /// peer's once [`Link::opened`] says so.
    pub fn open_link(&self, peer: Key, entropy: &mut dyn Entropy) -> Result<Link, String> {
        if let Some(why) = self.why_ended() {
            return Err(format!("the connection to the DERP server {} ended: {why}", self.inner.server));
        }
        let mut id = [0u8; packet::ID];
        entropy.fill(&mut id).map_err(|e| e.to_string())?;
        let shared = Shared::opening(peer, id, Instant::now());
        lock(&self.inner.links).insert((peer, id), shared.clone());
        tokio::spawn(link::drive(shared.clone(), self.clone()));
        Ok(Link::new(shared))
    }

    /// The next link that a client opened; `None` at a client, and once the
    /// connection ended.
    pub async fn accept(&self) -> Option<Link> {
        let (_, receiver) = self.inner.incoming.as_ref()?;
        let mut receiver = receiver.lock().await;
        tokio::select! {
            link = receiver.recv() => link,
            _ = self.ended() => None,
        }
    }

    pub(super) async fn send_data(&self, peer: Key, packet: Vec<u8>) -> Result<(), String> {
        let frame = frame::send_packet(&peer.0, &packet);
        self.inner.data.send(frame).await.map_err(|_| self.gone())
    }

    pub(super) async fn send_ctl(&self, peer: Key, packet: Vec<u8>) -> Result<(), String> {
        let frame = frame::send_packet(&peer.0, &packet);
        self.inner.ctl.send(frame).await.map_err(|_| self.gone())
    }

    fn gone(&self) -> String {
        let why = self.why_ended().unwrap_or_else(|| "its writer stopped".to_string());
        format!("the connection to the DERP server {} ended: {why}", self.inner.server)
    }

    pub(super) fn forget(&self, peer: &Key, id: &LinkId) {
        lock(&self.inner.links).remove(&(*peer, *id));
    }
}

impl Inner {
    /// The connection ends with `why`, once; each link on it fails.
    fn end(&self, why: String) {
        let first = self.ended.send_if_modified(|ended| {
            if ended.is_some() {
                return false;
            }
            *ended = Some(why.clone());
            true
        });
        if !first {
            return;
        }
        let text = format!("the connection to the DERP server {} ended: {why}", self.server);
        let links: Vec<Arc<Shared>> = lock(&self.links).values().cloned().collect();
        for shared in links {
            shared.fail(&text, false);
        }
    }

    fn handle(self: &Arc<Self>, frame: Frame) {
        match frame {
            Frame::RecvPacket { src, packet } => self.dispatch(Key(src), &packet),
            // Never a wait in the reader: a pong that finds no room is lost,
            // and the server pings again.
            Frame::Ping(data) => {
                let _ = self.ctl.try_send(frame::pong(data));
            }
            Frame::Pong(_) | Frame::KeepAlive | Frame::Other { .. } => {}
            Frame::PeerGone { key, reason } => {
                let why = match reason {
                    Some(frame::gone::NOT_HERE) => "the DERP server does not know the far end",
                    _ => "the far end left the DERP server",
                };
                self.fail_peer(Key(key), why);
            }
            Frame::Health(text) if text.is_empty() => {}
            Frame::Health(text) => (self.say)(format!("the DERP server {} says: {text}", self.server)),
            Frame::Restarting { reconnect_ms, .. } => {
                self.end(format!("the DERP server restarts, and asks for a new connection after {reconnect_ms} ms"))
            }
            Frame::ServerKey { .. } | Frame::ServerInfo { .. } => {
                self.end("the DERP server began its handshake again".to_string())
            }
        }
    }

    fn dispatch(self: &Arc<Self>, peer: Key, bytes: &[u8]) {
        // Another program's packet to this key is dropped.
        let Ok(packet) = Packet::decode(bytes) else { return };
        let now = Instant::now();
        let found = lock(&self.links).get(&(peer, packet.link)).cloned();
        if let Some(shared) = found {
            shared.on_packet(packet.body, now);
            return;
        }
        match packet.body {
            Body::Open => self.accept(peer, packet.link, now),
            Body::Reset(_) => {}
            _ => self.reset(peer, packet.link, "no such link: it ended, or this end started again"),
        }
    }

    /// A client opened a link to this node.
    fn accept(self: &Arc<Self>, peer: Key, id: LinkId, now: Instant) {
        let Some((sender, _)) = &self.incoming else {
            self.reset(peer, id, "this end opens links, and takes none");
            return;
        };
        let full = {
            let links = lock(&self.links);
            let from_peer = links.keys().filter(|(from, _)| *from == peer).count();
            links.len() >= MAX_LINKS || from_peer >= MAX_PER_PEER
        };
        if full {
            self.reset(peer, id, "the node holds as many links as it takes");
            return;
        }
        let shared = Shared::answering(peer, id, now);
        lock(&self.links).insert((peer, id), shared.clone());
        tokio::spawn(link::drive(shared.clone(), Conn { inner: self.clone() }));
        if sender.try_send(Link::new(shared.clone())).is_err() {
            // The link that came back is dropped: the node takes no more now.
            shared.fail("the node takes no more links now", true);
        }
    }

    /// A `RESET` of a link that this end has not, a few each second at most.
    fn reset(&self, peer: Key, id: LinkId, why: &str) {
        {
            let mut resets = lock(&self.resets);
            let now = Instant::now();
            if now.saturating_duration_since(resets.0) >= Duration::from_secs(1) {
                *resets = (now, 0);
            }
            if resets.1 >= RESETS_PER_SECOND {
                return;
            }
            resets.1 += 1;
        }
        let packet = Packet { link: id, body: Body::Reset(why.to_string()) }.encode();
        let _ = self.ctl.try_send(frame::send_packet(&peer.0, &packet));
    }

    fn fail_peer(&self, peer: Key, why: &str) {
        let links: Vec<Arc<Shared>> =
            lock(&self.links).iter().filter(|((from, _), _)| *from == peer).map(|(_, shared)| shared.clone()).collect();
        for shared in links {
            shared.fail(why, false);
        }
    }
}

/// DERP's handshake on `session`: the server's key and info.
async fn handshake(
    session: &RelaySession<BoxIo>,
    decoder: &mut Decoder,
    secret: &Secret,
    server: &Server,
) -> Result<(Key, ServerInfo), String> {
    let server_key = match within(next_frame(session, decoder), server, "its key").await? {
        Frame::ServerKey { key } => Key(key),
        other => return Err(format!("{server} sent {} first, where a DERP server sends its key", other.name())),
    };
    let mut nonce = [0u8; frame::NONCE];
    OsEntropy.fill(&mut nonce).map_err(|e| e.to_string())?;
    let sealed = secret.seal(&server_key, &key::client_info_json(key::APP_NAME), nonce);
    let hello = frame::client_info(&secret.public().0, &sealed);
    session.send_binary(&hello).await.map_err(|e| format!("{server}: {e}"))?;
    let sealed = match within(next_frame(session, decoder), server, "its info").await? {
        Frame::ServerInfo { sealed } => sealed,
        other => {
            let sent = other.name();
            return Err(format!("{server} sent {sent} after this end's key, where a DERP server sends its info"));
        }
    };
    let json = secret.open(&server_key, &sealed).map_err(|why| format!("{server}'s info: {why}"))?;
    let info = key::server_info(&json).map_err(|why| format!("{server}: {why}"))?;
    Ok((server_key, info))
}

async fn within<T>(step: impl Future<Output = Result<T, String>>, server: &Server, what: &str) -> Result<T, String> {
    match tokio::time::timeout(HANDSHAKE_LIMIT, step).await {
        Err(_) => Err(format!("{server} did not send {what} within {} s", HANDSHAKE_LIMIT.as_secs())),
        Ok(answer) => answer,
    }
}

async fn next_frame(session: &RelaySession<BoxIo>, decoder: &mut Decoder) -> Result<Frame, String> {
    loop {
        if let Some(frame) = decoder.next().map_err(|e| e.to_string())? {
            return Ok(frame);
        }
        let message = session.read_frame().await.map_err(|e| e.to_string())?;
        match message.opcode {
            OPCODE_BINARY => decoder.push(&message.payload),
            OPCODE_CLOSE => return Err(closed(&message.payload)),
            _ => return Err("a text message, where DERP sends binary ones".to_string()),
        }
    }
}

fn closed(payload: &[u8]) -> String {
    match close_code_and_reason(payload) {
        (Some(code), reason) if reason.is_empty() => format!("the server closed its WebSocket ({code})"),
        (Some(code), reason) => format!("the server closed its WebSocket ({code} {reason})"),
        (None, _) => "the server closed its WebSocket".to_string(),
    }
}

async fn read_loop(
    inner: Weak<Inner>,
    session: Arc<RelaySession<BoxIo>>,
    mut decoder: Decoder,
    mut ended: watch::Receiver<Option<String>>,
) {
    let why = loop {
        match decoder.next() {
            Ok(Some(frame)) => {
                let Some(inner) = inner.upgrade() else { return };
                inner.handle(frame);
                continue;
            }
            Ok(None) => {}
            Err(e) => break e.to_string(),
        }
        let message = tokio::select! {
            message = session.read_frame() => message,
            _ = ended.wait_for(Option::is_some) => return,
        };
        match message {
            Ok(message) if message.opcode == OPCODE_BINARY => decoder.push(&message.payload),
            Ok(message) if message.opcode == OPCODE_CLOSE => break closed(&message.payload),
            Ok(_) => break "a text message, where DERP sends binary ones".to_string(),
            Err(e) => break e.to_string(),
        }
    };
    if let Some(inner) = inner.upgrade() {
        inner.end(why);
    }
}

async fn write_loop(
    inner: Weak<Inner>,
    session: Arc<RelaySession<BoxIo>>,
    mut ctl: mpsc::Receiver<Vec<u8>>,
    mut data: mpsc::Receiver<Vec<u8>>,
    mut ended: watch::Receiver<Option<String>>,
    info: ServerInfo,
) {
    let mut pings = tokio::time::interval(PING_EVERY);
    pings.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut bucket = Bucket::of(&info);
    let mut sent: u64 = 0;
    let why = loop {
        let frame = tokio::select! {
            biased;
            _ = ended.wait_for(Option::is_some) => {
                let _ = session.send_close(1000, "").await;
                return;
            }
            Some(frame) = ctl.recv() => frame,
            Some(frame) = data.recv() => {
                if let Some(bucket) = bucket.as_mut() {
                    bucket.take(frame.len()).await;
                }
                frame
            }
            _ = pings.tick() => {
                sent += 1;
                frame::ping(sent.to_be_bytes())
            }
        };
        if let Err(e) = session.send_binary(&frame).await {
            break format!("a write to the server failed: {e}");
        }
    };
    if let Some(inner) = inner.upgrade() {
        inner.end(why);
    }
}

/// The rate that a server names in its info, kept as Go's client keeps it,
/// but by waiting where Go's client drops.
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn of(info: &ServerInfo) -> Option<Bucket> {
        (info.bytes_per_second > 0).then(|| {
            let burst = info.burst.max((frame::MAX_PACKET + frame::KEY + frame::HEADER) as u64) as f64;
            Bucket { rate: info.bytes_per_second as f64, burst, tokens: burst, at: Instant::now() }
        })
    }

    async fn take(&mut self, bytes: usize) {
        let need = (bytes as f64).min(self.burst);
        loop {
            let now = Instant::now();
            let since = now.saturating_duration_since(self.at).as_secs_f64();
            self.tokens = (self.tokens + self.rate * since).min(self.burst);
            self.at = now;
            if self.tokens >= need {
                self.tokens -= bytes as f64;
                return;
            }
            tokio::time::sleep(Duration::from_secs_f64((need - self.tokens) / self.rate)).await;
        }
    }
}
