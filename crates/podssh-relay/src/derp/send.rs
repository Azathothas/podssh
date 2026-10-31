//! The sending half of a link: the bytes that the application wrote, cut
//! into numbered segments of [`SEGMENT`] bytes at most, each kept until the
//! peer acknowledges it, and sent again when it was lost.
//!
//! A DERP server forwards one end's packets in their order, and drops the
//! oldest of a receiver's queue when 32 wait (tailscale/tailscale:
//! derp/derpserver/derpserver.go at v1.104.4, `sendPkt`). Packets are not
//! reordered, so a segment is lost once a segment sent after it arrived:
//! no wait for more. A segment whose acknowledgement is later than the
//! retransmission timeout ([`Rtt`]) is lost too, and the timeout doubles.
//! The window halves at a loss, once for each window, and grows as TCP's:
//! by one segment for each one acknowledged, then by one for each window,
//! up to [`MAX_WINDOW`], under the server's queue, which the
//! acknowledgements of the other direction share.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

use super::packet::Ack;
use super::rtt::{self, Rtt};

/// The most bytes of one segment: with podssh's header, DERP's and the
/// frame's, a packet stays under the 32,768 bytes that derper's WebSocket
/// takes in one message (coder/websocket's read limit, at v1.8.15).
pub const SEGMENT: usize = 30 * 1024;
/// The most segments in flight on a link.
pub const MAX_WINDOW: u64 = 24;
/// The most segments from the first one not acknowledged to the next one
/// sent: what a receiver holds past a gap, at most.
pub const SPAN: u64 = 48;
/// The window of a new link, and the least after a loss.
const START_WINDOW: f64 = 4.0;
const MIN_WINDOW: f64 = 2.0;
/// The peer's window until its first acknowledgement says it.
const START_PEER_WINDOW: u64 = 16;
/// The bytes written and not yet in a segment that a link holds: a write
/// past them waits.
pub const SEND_BUFFER: usize = 1 << 20;
/// Segments on their way and no acknowledgement of any for this long: the
/// link is dead, as the layer takes a link silent for as long.
pub const DEAD_AFTER: Duration = Duration::from_secs(30);

/// A segment to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub seq: u64,
    pub fin: bool,
    pub data: Vec<u8>,
}

#[derive(Debug)]
struct Segment {
    seq: u64,
    data: Vec<u8>,
    fin: bool,
    /// When it last went out, and that send's place in the order of sends.
    sent: Option<(Instant, u64)>,
    sends: u32,
    /// The receiver holds it, past a gap.
    held: bool,
    /// Taken for lost: it goes again before any new segment.
    lost: bool,
}

impl Segment {
    fn in_flight(&self) -> bool {
        self.sent.is_some() && !self.held && !self.lost
    }
}

#[derive(Debug)]
pub struct Sender {
    unsent: VecDeque<u8>,
    /// The end of this direction: asked for, and in a segment.
    fin_asked: bool,
    fin_cut: bool,
    /// The segments from the first one not acknowledged on.
    queue: VecDeque<Segment>,
    next: u64,
    acked: u64,
    /// Sends so far, which order them; and the latest send that arrived.
    sends: u64,
    delivered: u64,
    window: f64,
    threshold: f64,
    /// No other reduction of the window until this segment is acknowledged.
    recover: u64,
    peer_window: u64,
    rtt: Rtt,
    /// The last acknowledgement, of anything.
    heard: Instant,
    probe_at: Option<Instant>,
    probe_wait: Duration,
}

impl Sender {
    pub fn new(now: Instant) -> Sender {
        Sender {
            unsent: VecDeque::new(),
            fin_asked: false,
            fin_cut: false,
            queue: VecDeque::new(),
            next: 0,
            acked: 0,
            sends: 0,
            delivered: 0,
            window: START_WINDOW,
            threshold: MAX_WINDOW as f64,
            recover: 0,
            peer_window: START_PEER_WINDOW,
            rtt: Rtt::default(),
            heard: now,
            probe_at: None,
            probe_wait: rtt::INITIAL,
        }
    }

    /// How many more bytes a write may give now.
    pub fn space(&self) -> usize {
        if self.fin_asked {
            return 0;
        }
        SEND_BUFFER.saturating_sub(self.unsent.len())
    }

    /// What fits of `bytes`: how many it took.
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        let n = bytes.len().min(self.space());
        self.unsent.extend(&bytes[..n]);
        n
    }

    /// The end of this direction, after the bytes written.
    pub fn finish(&mut self) {
        self.fin_asked = true;
    }

    pub fn finishing(&self) -> bool {
        self.fin_asked
    }

    /// The end of this direction went out and was acknowledged, with each
    /// byte before it.
    pub fn ended(&self) -> bool {
        self.fin_cut && self.queue.is_empty()
    }

    /// Nothing to send and nothing on its way.
    pub fn idle(&self) -> bool {
        self.queue.is_empty() && !self.has_new()
    }

    /// The window, in segments.
    pub fn window(&self) -> f64 {
        self.window
    }

    /// The segments sent and not acknowledged.
    pub fn unacked(&self) -> usize {
        self.queue.len()
    }

    fn in_flight(&self) -> u64 {
        self.queue.iter().filter(|s| s.in_flight()).count() as u64
    }

    fn has_new(&self) -> bool {
        !self.unsent.is_empty() || (self.fin_asked && !self.fin_cut)
    }

    /// The segments to send now, in order: each one taken for lost first,
    /// then new ones, within the window and the peer's.
    pub fn poll(&mut self, now: Instant, out: &mut Vec<Outgoing>) {
        self.expire(now);
        let room = (self.window as u64).min(self.peer_window);
        // As many as the window lets go again, and one at least: with the
        // peer's window closed, that one asks for it again.
        let again = room.max(1).saturating_sub(self.in_flight());
        for seg in self.queue.iter_mut().filter(|s| s.lost).take(again as usize) {
            self.sends += 1;
            seg.sent = Some((now, self.sends));
            seg.sends += 1;
            seg.lost = false;
            out.push(Outgoing { seq: seg.seq, fin: seg.fin, data: seg.data.clone() });
        }
        while self.has_new() && self.in_flight() < room && self.next < self.acked + SPAN {
            self.send_new(now, out);
        }
        // A closed window: one segment now and then, which the peer
        // acknowledges with its window, as TCP probes one.
        if self.peer_window == 0 && self.has_new() && self.in_flight() == 0 && self.next < self.acked + SPAN {
            match self.probe_at {
                Some(at) if now < at => {}
                _ => {
                    self.send_new(now, out);
                    self.probe_at = Some(now + self.probe_wait);
                    self.probe_wait = (self.probe_wait * 2).min(rtt::MAX);
                }
            }
        }
    }

    fn send_new(&mut self, now: Instant, out: &mut Vec<Outgoing>) {
        let (data, fin) = if self.unsent.is_empty() {
            self.fin_cut = true;
            (Vec::new(), true)
        } else {
            let n = self.unsent.len().min(SEGMENT);
            (self.unsent.drain(..n).collect::<Vec<u8>>(), false)
        };
        // A link that had nothing on its way counts its silence from now.
        if self.queue.is_empty() {
            self.heard = now;
        }
        self.sends += 1;
        let seq = self.next;
        self.next += 1;
        out.push(Outgoing { seq, fin, data: data.clone() });
        let sent = Some((now, self.sends));
        self.queue.push_back(Segment { seq, data, fin, sent, sends: 1, held: false, lost: false });
    }

    /// Each segment whose acknowledgement is later than the timeout is lost.
    fn expire(&mut self, now: Instant) {
        let timeout = self.rtt.timeout();
        let mut expired = false;
        for seg in self.queue.iter_mut() {
            if let (Some((at, _)), false, false) = (seg.sent, seg.held, seg.lost) {
                if now.saturating_duration_since(at) >= timeout {
                    seg.lost = true;
                    expired = true;
                }
            }
        }
        if expired {
            self.rtt.back_off();
            self.reduce(true);
        }
    }

    /// A loss: the window halves, once for each window, and after a timeout
    /// it starts again from the least.
    fn reduce(&mut self, timeout: bool) {
        if self.acked >= self.recover || timeout {
            self.threshold = (self.window / 2.0).max(MIN_WINDOW);
            self.window = if timeout { MIN_WINDOW } else { self.threshold };
            self.recover = self.next;
        }
    }

    /// The peer holds what `ack` says.
    pub fn on_ack(&mut self, ack: &Ack, now: Instant) {
        self.heard = now;
        let next = ack.next.min(self.next);
        let mut newly: u64 = 0;
        let mut sample = None;
        let mut delivered = self.delivered;
        while self.queue.front().is_some_and(|s| s.seq < next) {
            let Some(seg) = self.queue.pop_front() else { break };
            if let Some((at, order)) = seg.sent {
                delivered = delivered.max(order);
                if seg.sends == 1 && !seg.held {
                    sample = Some(now.saturating_duration_since(at));
                }
            }
            if !seg.held {
                newly += 1;
            }
        }
        self.acked = self.acked.max(next);
        for &(start, end) in &ack.ranges {
            for seg in self.queue.iter_mut().filter(|s| s.seq >= start && s.seq < end && !s.held) {
                seg.held = true;
                seg.lost = false;
                newly += 1;
                if let Some((at, order)) = seg.sent {
                    delivered = delivered.max(order);
                    if seg.sends == 1 {
                        sample = Some(now.saturating_duration_since(at));
                    }
                }
            }
        }
        self.delivered = delivered;
        // No packet passes another: each one sent before one that arrived,
        // and still missing, was dropped.
        let mut lost = false;
        for seg in self.queue.iter_mut() {
            if let (Some((_, order)), false, false) = (seg.sent, seg.held, seg.lost) {
                if order < delivered {
                    seg.lost = true;
                    lost = true;
                }
            }
        }
        if let Some(rtt) = sample {
            self.rtt.sample(rtt);
        }
        self.peer_window = u64::from(ack.window);
        if self.peer_window > 0 {
            self.probe_at = None;
            self.probe_wait = self.rtt.timeout();
        }
        if lost {
            self.reduce(false);
        } else if newly > 0 {
            self.grow(newly);
        }
    }

    /// The window grows when the losses of the last reduction are behind.
    fn grow(&mut self, newly: u64) {
        if self.acked < self.recover {
            return;
        }
        let n = newly as f64;
        let grown = if self.window < self.threshold { self.window + n } else { self.window + n / self.window };
        self.window = grown.min(MAX_WINDOW as f64);
    }

    /// When [`Sender::poll`] has something to do with no new event: a
    /// segment's timeout, or a probe of a closed window.
    pub fn deadline(&self) -> Option<Instant> {
        let timeout = self.rtt.timeout();
        let resend =
            self.queue.iter().filter(|s| s.in_flight()).filter_map(|s| s.sent.map(|(at, _)| at + timeout)).min();
        let probe = self.probe_at.filter(|_| self.peer_window == 0 && self.has_new());
        match (resend, probe) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Segments on their way, and no acknowledgement for [`DEAD_AFTER`].
    pub fn dead(&self, now: Instant) -> bool {
        !self.queue.is_empty() && now.saturating_duration_since(self.heard) >= DEAD_AFTER
    }

    /// The smoothed round trip, once one was measured.
    pub fn round_trip(&self) -> Option<Duration> {
        self.rtt.smoothed()
    }
}
