//! Flow control that keeps a key's echo near the idle echo while bulk data
//! flows (T-661), from the client's side of plain SSH, so that it holds
//! against any sshd, on every road, with nothing at the far end.
//!
//! The window that podssh grants each channel is the server's bound of
//! what it has in flight to podssh, and so of what waits in front of a key's
//! echo in each queue between (a relay holds what a window lets through:
//! T-062). While a key was typed in the last [`keys::TYPING`], a channel's
//! window is held to the path's rate times its least round trip plus
//! [`target::TYPING_MARGIN`]; idle, plus [`target::IDLE_MARGIN`]; a third
//! more, as it is topped up once a quarter is used (T-670); at most the
//! road's cap ([`road`], T-662), which the channels that carry bulk share.
//! The rate and the round trip are the connection's own,
//! end to end: the bytes that came, and the time from a window adjust to
//! the first byte that needed it. `TCP_INFO` would see one leg only, the
//! proxy's, and russh consumes the replies of its keepalives, which it
//! sends only when nothing comes, so neither serves here.
//!
//! A queue that never empties hides the path's own round trip: each sample
//! then holds the queue too, and the window would grow with it. So the
//! windows drain for a moment when the user starts to type, and each
//! [`DRAIN_EVERY`] of bulk ([`Drain`]), as BBR probes its least round trip.
//!
//! russh asks the handler for each channel's target at each data message
//! (`window_target`, vendor/patches/russh/); a window already granted is
//! never taken back, so a smaller target withholds the next adjusts. It asks
//! too for the room left under which it tops a window up ([`target::low`],
//! `window_low`, T-670), and each channel takes messages of [`PACKET`] at
//! most. podssh's own senders hold their writes while a key waits for its
//! echo ([`keys::turn`]), and the direct road's socket keeps 16 KiB unsent at
//! most where the kernel takes it ([`lowat`]).

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub mod keys;
/// `TCP_NOTSENT_LOWAT`, in podssh-ws, which sets it on each socket that it
/// dials (T-661).
pub use podssh_ws::lowat;
mod path;
pub mod road;
pub mod target;

pub use keys::{echo, key, keys, turn, Keys, Turn};
pub use road::Road;

use path::{Chan, Path};

/// The bytes a second of a rate sample are counted over this long at least,
/// and over a round trip where that is longer, so that a window's burst is
/// not read as the path's rate.
pub const INTERVAL: Duration = Duration::from_millis(100);

/// A drain each this long while bulk flows: the least round trip is the
/// least of the last 10 to 20 s.
pub const DRAIN_EVERY: Duration = Duration::from_secs(10);

/// A drain lasts this long at most, whatever was in flight. It ends at its
/// first clean round trip: a path whose drain is long (its queue holds
/// seconds) is a slow one, which [`target::FLOOR`] keeps full, so a drain
/// costs a fast path little and a slow one nothing.
pub const DRAIN_MAX: Duration = Duration::from_secs(10);

/// The largest data message that a server sends on a channel of podssh's,
/// asked at each channel's open (T-670; OpenSSH's client asks for 32 KiB).
/// podssh counts a message once the whole of it came, and a server sends a
/// grant smaller than a message as one, so a window of a message or two
/// moves one message at a time, each a round trip and its own time on the
/// path: while a key waits, a slow path's window, its round trip and 40 ms,
/// is 23 KB at 1 Mbit/s and 100 ms, under one message of 32 KiB. A message
/// costs about 40 bytes of its own, 0.5% of 8 KiB.
pub const PACKET: u32 = 8 * 1024;

/// The window flow of one connection, in its handler: what it measured of
/// its path, and each channel's part, by the channel's number.
#[derive(Debug)]
pub struct Pace {
    /// A hop's channel carries the next connection, whose own windows bound
    /// what is in flight in it: its window is the road's cap.
    carrier: bool,
    /// The most that a channel's window may be on this road.
    cap: u32,
    keys: &'static Keys,
    path: Path,
    chans: HashMap<u32, Chan>,
    drain: Drain,
    /// The channels that carried bulk in the last interval of the rate.
    pressing: usize,
    /// A key was typed lately, at the last target asked.
    was_typing: bool,
}

/// When the windows drain: each channel held to [`target::FLOOR`] until
/// what was in flight came and one round trip more, so that a window
/// adjust's next byte crosses an empty queue and times the path alone. An
/// adjust while a window is held is one with less than a held window left,
/// so its round trip is the first clean one, and ends the drain, once the
/// other channels that carry bulk have no more in flight either.
#[derive(Debug, Default, Clone, Copy)]
struct Drain {
    began: Option<Instant>,
    until: Option<Instant>,
    next: Option<Instant>,
}

impl Default for Pace {
    fn default() -> Self {
        Pace::new(false, crate::run::WINDOW)
    }
}

impl Pace {
    /// The pace of a connection to the destination, or of a `-J` hop's
    /// (`carrier`), whose channels' windows are at most `cap`.
    pub fn new(carrier: bool, cap: u32) -> Self {
        Pace {
            carrier,
            cap,
            keys: keys(),
            path: Path::default(),
            chans: HashMap::new(),
            drain: Drain::default(),
            pressing: 0,
            was_typing: false,
        }
    }

    /// The same, with the keys of `keys` in place of the process's: a test's.
    pub fn with_keys(self, keys: &'static Keys) -> Self {
        Pace { keys, ..self }
    }

    /// The target of channel `channel`'s window now: russh asks at each of
    /// its data messages, before it decides whether to adjust the window.
    pub fn target(&mut self, channel: u32, now: Instant) -> u32 {
        let typing = !self.carrier && self.keys.typing(now);
        // The first key after a pause, while bulk flows: the queue in front
        // of it drains, and the round trip is timed afresh.
        if typing && !self.was_typing && self.pressing > 0 {
            self.start_drain(now);
        }
        self.was_typing = typing;
        let inputs = target::Inputs {
            typing,
            draining: self.drain.until.is_some_and(|until| now < until),
            carrier: self.carrier,
            rate: self.path.rate(now),
            rtt: self.path.rtt(),
            sharing: self.path.sharing(),
            cap: self.cap,
        };
        let target = target::of(&inputs);
        self.chan(channel).target = target;
        target
    }

    /// The room left under which russh tops a window up to `target`, asked
    /// after [`Self::target`] at each data message (T-670).
    pub fn low(&self, target: u32, now: Instant) -> u32 {
        let measured = self.path.rate(now).is_some() && self.path.rtt().is_some();
        target::low(target, measured)
    }

    /// An adjust of `channel`'s window went out now, to the last target.
    pub fn adjusted(&mut self, channel: u32, now: Instant) {
        self.chan(channel).adjusted = Some(now);
    }

    /// `n` bytes came on `channel` now, after russh's adjust of them.
    pub fn received(&mut self, channel: u32, n: usize, now: Instant) {
        if let Some(sample) = self.chan(channel).received(n as u64, now) {
            // The message is whole once its last byte came: the bytes behind
            // the timed one took their time at the path's rate.
            let sending = self.path.rate(now).map_or(Duration::ZERO, |rate| {
                Duration::try_from_secs_f64(sample.behind as f64 / rate.max(1) as f64).unwrap_or(Duration::ZERO)
            });
            self.path.round_trip(now, sample.took.saturating_sub(sending).max(Duration::from_millis(1)));
            // Clean: its adjust went out once the drain held its channel's
            // window, and no other channel that carries bulk still had more
            // than a held window in flight, whose bytes queue in front of it.
            let held = self.drain.began.is_some_and(|began| sample.sent >= began);
            if self.draining(now) && held && self.others_drained(channel) {
                self.drain.until = Some(now);
            }
        }
        if !self.path.count(now, n as u64) {
            return;
        }
        // An interval ended: who shares the path, and whether to drain.
        self.pressing = self.chans.values_mut().map(Chan::close_interval).filter(|busy| *busy).count();
        self.path.set_sharing(self.pressing);
        if self.carrier || self.pressing == 0 {
            // No bulk: the next one starts the clock of the drains again.
            self.drain.next = None;
            return;
        }
        match self.drain.next {
            None => self.drain.next = Some(now + DRAIN_EVERY),
            Some(at) if now >= at => self.start_drain(now),
            Some(_) => {}
        }
    }

    /// `channel` closed: its part is gone.
    pub fn closed(&mut self, channel: u32) {
        self.chans.remove(&channel);
    }

    /// Whether the windows drain at `now`.
    pub fn draining(&self, now: Instant) -> bool {
        self.drain.until.is_some_and(|until| now < until)
    }

    /// Drain from `now` until the first clean round trip, [`DRAIN_MAX`] at
    /// most. Not until a guess of when what was in flight comes (T-670): the
    /// rate is the best of the last seconds, which a burst after a loss's
    /// stall raises, and an unmeasured round trip guessed none of the queue,
    /// so on a slow link that loses a packet in a hundred a drain ended a
    /// second before its queue had come, with no clean round trip, and the
    /// windows came back from a round trip that held that queue.
    fn start_drain(&mut self, now: Instant) {
        if self.draining(now) {
            return;
        }
        self.drain = Drain { began: Some(now), until: Some(now + DRAIN_MAX), next: Some(now + DRAIN_EVERY) };
    }

    /// No channel but `channel` that carries bulk has more than a held
    /// window in flight. A channel that carries none has nothing in flight
    /// to wait for: its window is room, not bytes.
    fn others_drained(&self, channel: u32) -> bool {
        let held = u64::from(target::FLOOR);
        self.chans.iter().all(|(id, c)| *id == channel || !c.busy || c.outstanding() <= held)
    }

    fn chan(&mut self, channel: u32) -> &mut Chan {
        // Each channel starts with the window that russh advertised for it.
        self.chans.entry(channel).or_insert_with(|| Chan::new(crate::run::WINDOW))
    }
}

#[cfg(test)]
mod drain_tests;

#[cfg(test)]
mod sim_tests;

#[cfg(test)]
mod wire_tests;
