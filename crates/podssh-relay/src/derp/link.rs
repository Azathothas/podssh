//! A link: one byte stream between a client and a node over DERP, which the
//! resumable layer reads and writes as it does a relay's link. The two halves
//! of the adapter ([`Sender`], [`Receiver`]) hold its state; a task of its
//! own sends what they say, when they say it, through the connection
//! ([`drive`]); the connection's reader gives it each packet of the link.
//!
//! A client's link is the node's once the node answered its `OPEN`, which
//! goes again until then. A link that failed ends both ways with the reason.
//! One that is dropped ends its direction and stays for its last bytes, for
//! [`LINGER`] at most, as a TCP connection closes.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{watch, Notify};
use tokio::time::Instant;

use super::conn::Conn;
use super::key::Key;
use super::packet::{self, Body, LinkId, Packet};
use super::recv::Receiver;
use super::send::Sender;

/// How long a client sends its `OPEN` again before it gives up on the node
/// at this server.
pub const OPEN_LIMIT: Duration = Duration::from_secs(6);
/// The first wait between two `OPEN`s, and the most; each doubles.
const OPEN_FIRST: Duration = Duration::from_millis(400);
const OPEN_MOST: Duration = Duration::from_secs(2);
/// How long a dropped link waits for its last bytes to arrive.
pub const LINGER: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
enum Open {
    Waiting { next: Instant, wait: Duration, until: Instant },
    Done,
}

struct State {
    send: Sender,
    recv: Receiver,
    open: Open,
    failed: Option<String>,
    /// A `RESET` to send once, with this side's reason.
    reset: Option<String>,
    dropped: bool,
    linger: Option<Instant>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    finished: bool,
}

impl State {
    fn wake_both(&mut self) {
        if let Some(reader) = self.reader.take() {
            reader.wake();
        }
        if let Some(writer) = self.writer.take() {
            writer.wake();
        }
    }
}

/// A link's state, which its [`Link`], its task and its connection share.
pub(super) struct Shared {
    pub(super) peer: Key,
    pub(super) id: LinkId,
    state: Mutex<State>,
    wake: Notify,
    opened: watch::Sender<Option<Result<(), String>>>,
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a link's task does next.
struct Step {
    /// Each packet, and whether it is `DATA`, which goes behind the others.
    packets: Vec<(bool, Vec<u8>)>,
    at: Option<Instant>,
    end: bool,
}

impl Shared {
    fn new(peer: Key, id: LinkId, open: Open, now: Instant) -> Arc<Shared> {
        let state = State {
            send: Sender::new(now),
            recv: Receiver::new(),
            open,
            failed: None,
            reset: None,
            dropped: false,
            linger: None,
            reader: None,
            writer: None,
            finished: false,
        };
        let opened = match open {
            Open::Done => Some(Ok(())),
            Open::Waiting { .. } => None,
        };
        let (opened, _) = watch::channel(opened);
        Arc::new(Shared { peer, id, state: Mutex::new(state), wake: Notify::new(), opened })
    }

    /// A client's new link: its `OPEN` goes at once.
    pub(super) fn opening(peer: Key, id: LinkId, now: Instant) -> Arc<Shared> {
        Shared::new(peer, id, Open::Waiting { next: now, wait: OPEN_FIRST, until: now + OPEN_LIMIT }, now)
    }

    /// A node's link, which a client opened: the answer goes at once.
    pub(super) fn answering(peer: Key, id: LinkId, now: Instant) -> Arc<Shared> {
        let shared = Shared::new(peer, id, Open::Done, now);
        lock(&shared.state).recv.ack_now();
        shared
    }

    fn packet(&self, body: Body) -> Vec<u8> {
        Packet { link: self.id, body }.encode()
    }

    fn mark_open(&self, state: &mut State) {
        if let Open::Waiting { .. } = state.open {
            state.open = Open::Done;
            self.opened.send_replace(Some(Ok(())));
        }
    }

    /// A packet of this link came.
    pub(super) fn on_packet(&self, body: Body, now: Instant) {
        let mut state = lock(&self.state);
        if state.finished || state.failed.is_some() {
            return;
        }
        match body {
            Body::Open => state.recv.ack_now(),
            Body::Data { seq, fin, data } => {
                self.mark_open(&mut state);
                state.recv.on_data(seq, fin, data, now);
                if let Some(reader) = state.reader.take() {
                    reader.wake();
                }
            }
            Body::Ack(ack) => {
                self.mark_open(&mut state);
                state.send.on_ack(&ack, now);
                if let Some(writer) = state.writer.take() {
                    writer.wake();
                }
            }
            Body::Reset(why) => {
                let why = format!("the far end ended the link: {why}");
                if let Open::Waiting { .. } = state.open {
                    self.opened.send_replace(Some(Err(why.clone())));
                }
                state.failed = Some(why);
                state.wake_both();
            }
        }
        drop(state);
        self.wake.notify_one();
    }

    /// The link fails with `why`; the far end hears it when `reset`.
    pub(super) fn fail(&self, why: &str, reset: bool) {
        let mut state = lock(&self.state);
        if state.failed.is_some() || state.finished {
            return;
        }
        state.failed = Some(why.to_string());
        if reset {
            state.reset = Some(why.to_string());
        }
        if let Open::Waiting { .. } = state.open {
            self.opened.send_replace(Some(Err(why.to_string())));
        }
        state.wake_both();
        drop(state);
        self.wake.notify_one();
    }

    fn step(&self, now: Instant) -> Step {
        let mut state = lock(&self.state);
        let mut packets = Vec::new();
        let ended = |packets| Step { packets, at: None, end: true };
        if state.finished {
            return ended(packets);
        }
        if let Some(why) = state.reset.take() {
            packets.push((false, self.packet(Body::Reset(why))));
        }
        if state.failed.is_some() {
            state.finished = true;
            state.wake_both();
            return ended(packets);
        }
        let mut open_at = None;
        if let Open::Waiting { next, wait, until } = state.open {
            if now >= until || state.dropped {
                let why = format!("the node did not answer at its DERP server within {} s", OPEN_LIMIT.as_secs());
                self.opened.send_replace(Some(Err(why.clone())));
                state.failed = Some(why);
                state.finished = true;
                state.wake_both();
                packets.push((false, self.packet(Body::Reset("the client gave up on the link".into()))));
                return ended(packets);
            }
            if now >= next {
                packets.push((false, self.packet(Body::Open)));
                state.open = Open::Waiting { next: now + wait, wait: (wait * 2).min(OPEN_MOST), until };
            }
            if let Open::Waiting { next, until, .. } = state.open {
                open_at = Some(next.min(until));
            }
        } else {
            if state.send.dead(now) {
                let why = format!("the far end acknowledged nothing for {} s", super::send::DEAD_AFTER.as_secs());
                state.failed = Some(why.clone());
                state.finished = true;
                state.wake_both();
                packets.push((false, self.packet(Body::Reset(why))));
                return ended(packets);
            }
            // The acknowledgement first: a full queue of data must not hold
            // back what the other direction waits for.
            if let Some(ack) = state.recv.ack(now) {
                packets.push((false, self.packet(Body::Ack(ack))));
            }
            let mut segments = Vec::new();
            state.send.poll(now, &mut segments);
            for segment in segments {
                packets.push((true, packet::data(&self.id, segment.seq, segment.fin, &segment.data)));
            }
        }
        // A dropped link goes once its last bytes arrived, or its wait ended.
        if state.dropped && (state.send.ended() || state.linger.is_some_and(|at| now >= at)) {
            if !state.send.ended() {
                packets.push((false, self.packet(Body::Reset("the far end closed the link".into()))));
            }
            state.finished = true;
            return ended(packets);
        }
        if state.send.space() > 0 {
            if let Some(writer) = state.writer.take() {
                writer.wake();
            }
        }
        let at = [open_at, state.send.deadline(), state.recv.deadline(), state.linger].into_iter().flatten().min();
        Step { packets, at, end: false }
    }
}

/// The task of a link: what its state says goes out through `conn`, until
/// the link ends or its connection does.
pub(super) async fn drive(shared: Arc<Shared>, conn: Conn) {
    loop {
        let step = shared.step(Instant::now());
        for (data, packet) in step.packets {
            let sent =
                if data { conn.send_data(shared.peer, packet).await } else { conn.send_ctl(shared.peer, packet).await };
            if let Err(why) = sent {
                shared.fail(&why, false);
            }
        }
        if step.end {
            conn.forget(&shared.peer, &shared.id);
            return;
        }
        let at = step.at;
        let wait = async move {
            match at {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            () = shared.wake.notified() => {}
            () = wait => {}
            why = conn.ended() => shared.fail(&why, false),
        }
    }
}

/// A link of the DERP road, as the layer reads and writes it.
pub struct Link {
    shared: Arc<Shared>,
}

impl Link {
    pub(super) fn new(shared: Arc<Shared>) -> Link {
        Link { shared }
    }

    /// Until the node answered this client's `OPEN`, or why it did not; at
    /// once for a node's link.
    pub async fn opened(&self) -> Result<(), String> {
        let mut seen = self.shared.opened.subscribe();
        // The answer is cloned out before `seen` goes, as its guard borrows it.
        let answer = match seen.wait_for(Option::is_some).await {
            Ok(answer) => answer.clone().unwrap_or(Ok(())),
            Err(_) => Err("the link ended".to_string()),
        };
        answer
    }

    /// The key of the far end.
    pub fn peer(&self) -> Key {
        self.shared.peer
    }

    /// The smoothed round trip of the link, once one was measured.
    pub fn round_trip(&self) -> Option<Duration> {
        lock(&self.shared.state).send.round_trip()
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Link({})", self.shared.peer)
    }
}

impl AsyncRead for Link {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        let mut state = lock(&shared.state);
        if state.recv.readable() {
            let n = state.recv.read(buf.initialize_unfilled());
            buf.advance(n);
            // A window that opened again is said at once.
            let tell = state.recv.wants_ack();
            drop(state);
            if tell {
                shared.wake.notify_one();
            }
            return Poll::Ready(Ok(()));
        }
        if state.recv.at_end() {
            return Poll::Ready(Ok(()));
        }
        if let Some(why) = &state.failed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, why.clone())));
        }
        state.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for Link {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let shared = &self.shared;
        let mut state = lock(&shared.state);
        if let Some(why) = &state.failed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, why.clone())));
        }
        if state.send.finishing() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "this side ended the link's bytes")));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = state.send.write(bytes);
        if n == 0 {
            state.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        drop(state);
        shared.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &lock(&self.shared.state).failed {
            Some(why) => Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, why.clone()))),
            None => Poll::Ready(Ok(())),
        }
    }

    // The end of this direction, after the bytes written: the far end reads
    // the end of the link.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        lock(&self.shared.state).send.finish();
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        let mut state = lock(&self.shared.state);
        if !state.dropped {
            state.dropped = true;
            state.send.finish();
            state.linger = Some(Instant::now() + LINGER);
        }
        drop(state);
        self.shared.wake.notify_one();
    }
}
