//! What a connection measures of its path (T-661): its rate, the most bytes
//! a second of the last few seconds, and its least round trip, from its
//! window adjusts; and what each channel took, to time those adjusts.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::INTERVAL;

/// A rate is the best of the samples of the last 5 to 10 s; older, none:
/// the path may have changed, and the window starts again from the start.
const RATE_SPAN: Duration = Duration::from_secs(5);

/// The least round trip is the least of the last 10 to 20 s; with none
/// since, the last one stands, as the path's delay does not drift fast.
const RTT_SPAN: Duration = Duration::from_secs(10);

/// The best sample of the last one or two spans, kept in two numbers: a
/// windowed filter that needs no list of samples.
#[derive(Debug, Clone, Copy)]
pub(super) struct Best<T> {
    span: Duration,
    /// Keep the largest (a rate) or the least (a round trip).
    largest: bool,
    /// The span that began then, and its best so far.
    current: Option<(Instant, T)>,
    /// The best of the span before it.
    previous: Option<T>,
}

impl<T: Copy + PartialOrd> Best<T> {
    pub(super) fn new(span: Duration, largest: bool) -> Self {
        Best { span, largest, current: None, previous: None }
    }

    fn better(&self, a: T, b: T) -> bool {
        if self.largest {
            a > b
        } else {
            a < b
        }
    }

    pub(super) fn add(&mut self, now: Instant, sample: T) {
        match self.current {
            Some((began, best)) if now.saturating_duration_since(began) < self.span => {
                if self.better(sample, best) {
                    self.current = Some((began, sample));
                }
            }
            Some((_, best)) => {
                self.previous = Some(best);
                self.current = Some((now, sample));
            }
            None => self.current = Some((now, sample)),
        }
    }

    /// The best of both spans, whatever their age.
    pub(super) fn best(&self) -> Option<T> {
        match (self.current.map(|(_, b)| b), self.previous) {
            (Some(a), Some(b)) => Some(if self.better(b, a) { b } else { a }),
            (a, b) => a.or(b),
        }
    }

    /// The best, when a sample came within the last two spans.
    pub(super) fn fresh(&self, now: Instant) -> Option<T> {
        let (began, _) = self.current?;
        (now.saturating_duration_since(began) < self.span * 2).then(|| self.best()).flatten()
    }
}

/// The connection's measures of its path.
#[derive(Debug)]
pub(super) struct Path {
    /// The start of the interval being counted, and its bytes.
    since: Option<Instant>,
    bytes: u64,
    /// Bytes a second.
    rate: Best<u64>,
    rtt: Best<Duration>,
    /// The channels that carried bulk in the last interval, 1 at least.
    sharing: u32,
}

impl Default for Path {
    fn default() -> Self {
        Path { since: None, bytes: 0, rate: Best::new(RATE_SPAN, true), rtt: Best::new(RTT_SPAN, false), sharing: 1 }
    }
}

impl Path {
    /// The path's rate, when one was measured lately.
    pub(super) fn rate(&self, now: Instant) -> Option<u64> {
        self.rate.fresh(now)
    }

    /// The path's least round trip.
    pub(super) fn rtt(&self) -> Option<Duration> {
        self.rtt.best()
    }

    pub(super) fn round_trip(&mut self, now: Instant, rtt: Duration) {
        self.rtt.add(now, rtt);
    }

    /// The length of an interval of the rate: a round trip, and
    /// [`INTERVAL`] at least.
    pub(super) fn interval(&self) -> Duration {
        self.rtt().map_or(INTERVAL, |rtt| rtt.max(INTERVAL))
    }

    pub(super) fn sharing(&self) -> u32 {
        self.sharing
    }

    pub(super) fn set_sharing(&mut self, channels: usize) {
        self.sharing = u32::try_from(channels).unwrap_or(u32::MAX).max(1);
    }

    /// `n` bytes came now; true when they closed an interval, whose rate is
    /// then a sample. The bytes of the message that opens an interval came
    /// at its start, so they are not counted in it.
    pub(super) fn count(&mut self, now: Instant, n: u64) -> bool {
        let Some(since) = self.since else {
            self.since = Some(now);
            self.bytes = 0;
            return false;
        };
        self.bytes += n;
        let took = now.saturating_duration_since(since);
        if took < self.interval() {
            return false;
        }
        let rate = (u128::from(self.bytes) * 1_000_000 / took.as_micros().max(1)) as u64;
        self.rate.add(now, rate);
        self.since = Some(now);
        self.bytes = 0;
        true
    }
}

/// The adjusts whose round trips are timed at once, at most: each adjust's
/// byte comes after the one before, so a few cover a round trip's adjusts.
const PROBES: usize = 16;

/// A round trip timed from an adjust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sample {
    /// When the adjust went out.
    pub(super) sent: Instant,
    /// From then to the message that carried the first byte that only it
    /// allowed.
    pub(super) took: Duration,
    /// The bytes of that message from that byte to its end: they came
    /// behind it, at the path's rate.
    pub(super) behind: u64,
}

/// A channel that took this much in an interval of the rate (100 ms at
/// least, so 80 kB/s) carries bulk: a terminal's echo and its usual output
/// take far less.
pub(super) const BUSY: u64 = 8 * 1024;

/// One channel's part: the bytes that came, the bytes that its windows
/// allowed, and the adjusts whose round trips are being timed.
#[derive(Debug)]
pub(super) struct Chan {
    received: u64,
    /// The bytes that the windows granted so far allow, counted from the
    /// channel's first: the server sends none past it.
    granted: u64,
    /// The target that russh was last given for this channel.
    pub(super) target: u32,
    /// An adjust went out for the message whose bytes are counted next.
    pub(super) adjusted: Option<Instant>,
    /// Each adjust's time, and the first byte that only it allowed, in the
    /// order of the bytes: that byte comes a round trip after it, or later
    /// when the server had window left or a queue held it.
    probes: VecDeque<(Instant, u64)>,
    /// The bytes since the last interval of the rate ended.
    fresh: u64,
    /// The last interval brought it [`BUSY`] bytes at least.
    pub(super) busy: bool,
}

impl Chan {
    /// A channel whose window starts at `initial`.
    pub(super) fn new(initial: u32) -> Self {
        Chan {
            received: 0,
            granted: u64::from(initial),
            target: initial,
            adjusted: None,
            probes: VecDeque::new(),
            fresh: 0,
            busy: false,
        }
    }

    /// The bytes that the windows allow and that have not come: in flight,
    /// or not yet sent.
    pub(super) fn outstanding(&self) -> u64 {
        self.granted.saturating_sub(self.received)
    }

    /// An interval of the rate ended: whether this channel carried bulk in
    /// it, and a new count.
    pub(super) fn close_interval(&mut self) -> bool {
        self.busy = self.fresh >= BUSY;
        self.fresh = 0;
        self.busy
    }

    /// `n` bytes came now: a round trip, when they carry the first byte
    /// that an adjust alone allowed (byte numbers from 0).
    pub(super) fn received(&mut self, n: u64, now: Instant) -> Option<Sample> {
        self.received += n;
        self.fresh += n;
        let mut rtt = None;
        while let Some(&(sent, first)) = self.probes.front() {
            if first >= self.received {
                break;
            }
            self.probes.pop_front();
            rtt = Some(Sample { sent, took: now.saturating_duration_since(sent), behind: self.received - first });
        }
        if let Some(sent) = self.adjusted.take() {
            // russh set the window to the target after these bytes.
            let allowed = self.granted;
            self.granted = self.received + u64::from(self.target);
            if allowed >= self.received {
                if self.probes.len() == PROBES {
                    self.probes.pop_front();
                }
                self.probes.push_back((sent, allowed));
            }
        }
        rtt
    }
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod tests;
