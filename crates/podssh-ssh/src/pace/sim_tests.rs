//! T-661 on a fake path: a bottleneck with a deep buffer (it queues all it
//! is given), a server that sends a bulk channel as fast as its window lets
//! it, in messages no larger than the channel asked for, a key's echo queued
//! behind that, and russh's rule of the adjust in between (to the target
//! once less than the room that podssh gives is left, T-670). Today's fixed
//! window of 512 KiB, in OpenSSH's messages of 32 KiB and with russh's room
//! of half the window, is the reference. Time is the simulation's own, a
//! millisecond a step, and a lost packet comes from a seeded generator, so
//! each run gives the same figures.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::{Keys, Pace};
use crate::run::WINDOW;

/// The bulk channel's number.
const BULK: u32 = 2;
/// The largest data message of the server before T-670: OpenSSH's, as
/// podssh asked for russh's 32 KiB. Paced, the server sends
/// [`super::PACKET`] at most.
const TODAY_PACKET: u64 = 32 * 1024;
/// A key's echo on the wire.
const ECHO: u64 = 64;
/// A TCP segment's payload: what a lossy link loses (scripts/fake_shape.py).
const SEGMENT: u64 = 1448;

/// A path: its bottleneck's rate, in bytes a millisecond, and each way's
/// delay in milliseconds.
#[derive(Debug, Clone, Copy)]
struct Shape {
    rate: u64,
    down: u64,
    up: u64,
}

impl Shape {
    /// A key's echo with nothing in front of it.
    fn idle_echo(&self) -> u64 {
        self.up + self.down + ECHO.div_ceil(self.rate)
    }
}

/// A link that loses each segment with a chance, as scripts/fake_shape.py
/// does: a message with a lost segment comes a round trip late, two (200 ms
/// at least) when nothing follows it, and each message behind it waits, as
/// in one TCP stream. The generator is xorshift, seeded.
struct Loss {
    chance: f64,
    state: u64,
}

impl Loss {
    fn new(chance: f64, seed: u64) -> Self {
        Loss { chance, state: seed.max(1) }
    }

    fn next(&mut self) -> f64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        (x >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Whether a message of `size` bytes loses a segment.
    fn hits(&mut self, size: u64) -> bool {
        (0..size.div_ceil(SEGMENT)).any(|_| self.next() < self.chance)
    }
}

enum Down {
    Bulk(u64),
    /// The time that its key was typed.
    Echo(u64),
}

enum Up {
    Credit(u64),
    Key(u64),
}

struct Run {
    shape: Shape,
    /// `None`: today's window.
    pace: Option<Pace>,
    keys: &'static Keys,
    t0: Instant,
    /// At the bottleneck, in order, and the bytes of its head left to send.
    queue: VecDeque<Down>,
    head_left: u64,
    /// On the wire, each with the step that it arrives at.
    down: VecDeque<(u64, Down)>,
    up: VecDeque<(u64, Up)>,
    /// The bulk channel's window as the server has it, and as podssh does.
    credit: u64,
    remaining: u64,
    delivered: u64,
    echoes: Vec<u64>,
    /// The server's largest message.
    packet: u64,
    loss: Option<Loss>,
    /// The step that the last message down arrives at: none passes it.
    last: u64,
}

impl Run {
    fn new(shape: Shape, paced: bool, keys: &'static Keys) -> Self {
        let t0 = Instant::now();
        Run {
            shape,
            pace: paced.then(|| Pace::default().with_keys(keys)),
            keys,
            t0,
            queue: VecDeque::new(),
            head_left: 0,
            down: VecDeque::new(),
            up: VecDeque::new(),
            credit: u64::from(WINDOW),
            remaining: u64::from(WINDOW),
            delivered: 0,
            echoes: Vec::new(),
            packet: if paced { u64::from(super::PACKET) } else { TODAY_PACKET },
            loss: None,
            last: 0,
        }
    }

    /// A paced run on a road whose cap is `cap` (T-662).
    fn capped(shape: Shape, cap: u32, keys: &'static Keys) -> Self {
        let pace = Some(Pace::new(false, cap).with_keys(keys));
        Run { pace, packet: u64::from(super::PACKET), ..Run::new(shape, false, keys) }
    }

    /// The same run on a link that loses a segment with `chance`.
    fn lossy(self, chance: f64, seed: u64) -> Self {
        Run { loss: Some(Loss::new(chance, seed)), ..self }
    }

    fn at(&self, step: u64) -> Instant {
        self.t0 + Duration::from_millis(step)
    }

    /// Run until `end`, a key each `every` from `from` on.
    fn run(&mut self, end: u64, from: u64, every: u64) {
        for now in 0..end {
            if now >= from && (now - from).is_multiple_of(every) {
                self.keys.key(self.at(now));
                self.up.push_back((now + self.shape.up, Up::Key(now)));
            }
            self.step(now);
        }
    }

    /// T-660's `ping --under-load`: the download starts 200 ms after the
    /// last of the idle keys, and after a warm-up of 3 s, 40 keys go 150 ms
    /// apart beside it, until each came back (20 s at most).
    fn under_load(&mut self) {
        let before = self.t0.checked_sub(Duration::from_millis(200)).expect("an instant 200 ms before");
        self.keys.key(before);
        let mut typed = 0;
        for now in 0..20_000 {
            if now >= 3_000 && (now - 3_000).is_multiple_of(150) && typed < 40 {
                self.keys.key(self.at(now));
                self.up.push_back((now + self.shape.up, Up::Key(now)));
                typed += 1;
            }
            self.step(now);
            if self.echoes.len() == 40 {
                return;
            }
        }
    }

    fn step(&mut self, now: u64) {
        while self.up.front().is_some_and(|(at, _)| *at <= now) {
            match self.up.pop_front().map(|(_, what)| what) {
                Some(Up::Credit(bytes)) => self.credit += bytes,
                Some(Up::Key(typed)) => self.queue.push_back(Down::Echo(typed)),
                None => {}
            }
        }
        // The server has more than any window: it sends all that it may.
        while self.credit > 0 {
            let n = self.credit.min(self.packet);
            self.queue.push_back(Down::Bulk(n));
            self.credit -= n;
        }
        let mut budget = self.shape.rate;
        while budget > 0 {
            let Some(head) = self.queue.front() else { break };
            if self.head_left == 0 {
                self.head_left = match head {
                    Down::Bulk(n) => *n,
                    Down::Echo(_) => ECHO,
                };
            }
            let sent = budget.min(self.head_left);
            self.head_left -= sent;
            budget -= sent;
            if self.head_left == 0 {
                let done = self.queue.pop_front().expect("the head");
                let size = match done {
                    Down::Bulk(n) => n,
                    Down::Echo(_) => ECHO,
                };
                let trip = self.shape.down + self.shape.up;
                let lost = self.loss.as_mut().is_some_and(|loss| loss.hits(size));
                let held = match (lost, self.queue.is_empty()) {
                    (false, _) => 0,
                    (true, false) => trip,
                    (true, true) => (2 * trip).max(200),
                };
                let at = (now + self.shape.down + held).max(self.last);
                self.last = at;
                self.down.push_back((at, done));
            }
        }
        while self.down.front().is_some_and(|(at, _)| *at <= now) {
            match self.down.pop_front().map(|(_, what)| what) {
                Some(Down::Bulk(n)) => self.bulk(n, now),
                Some(Down::Echo(typed)) => self.echoes.push(now - typed),
                None => {}
            }
        }
    }

    /// The bulk channel's data at podssh, in the order of the patched russh:
    /// the target and the room, the adjust, then the bytes to the handler.
    fn bulk(&mut self, n: u64, now: u64) {
        let at = self.at(now);
        let (target, low) = match self.pace.as_mut() {
            Some(pace) => {
                let target = pace.target(BULK, at);
                (u64::from(target), u64::from(pace.low(target, at)))
            }
            None => (u64::from(WINDOW), u64::from(WINDOW) / 2),
        };
        if n <= self.remaining {
            self.remaining -= n;
        }
        // russh takes a room over the target as the target.
        if self.remaining < low.min(target) {
            self.up.push_back((now + self.shape.up, Up::Credit(target - self.remaining)));
            self.remaining = target;
            if let Some(pace) = self.pace.as_mut() {
                pace.adjusted(BULK, at);
            }
        }
        if let Some(pace) = self.pace.as_mut() {
            pace.received(BULK, n as usize, at);
        }
        self.delivered += n;
    }

    /// The median echo, in milliseconds.
    fn echo_p50(&self) -> u64 {
        p50(&self.echoes)
    }
}

/// The median of `echoes`.
fn p50(echoes: &[u64]) -> u64 {
    let mut sorted = echoes.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

/// T-660's deep-buffer shape: 10 Mbit/s and 60 ms. A download from the
/// start; from 5 s a key each 250 ms, to 25 s.
#[test]
fn on_a_deep_buffer_a_keys_echo_stays_near_the_idle_echo_while_a_download_runs() {
    static PACED: Keys = Keys::new();
    static TODAY: Keys = Keys::new();
    let shape = Shape { rate: 1250, down: 30, up: 30 };
    let mut paced = Run::new(shape, true, &PACED);
    paced.run(25_000, 5_000, 250);
    let mut today = Run::new(shape, false, &TODAY);
    today.run(25_000, 5_000, 250);

    let idle = shape.idle_echo();
    eprintln!(
        "idle echo {idle} ms; p50 paced {} ms, today {} ms; delivered paced {}, today {}",
        paced.echo_p50(),
        today.echo_p50(),
        paced.delivered,
        today.delivered
    );
    assert!(today.echo_p50() > 3 * idle, "the reference queues up to 512 KiB in front of each key");
    assert!(paced.echo_p50() <= 2 * idle, "echo p50 {} ms, idle {idle} ms", paced.echo_p50());
    assert!(paced.delivered * 10 >= today.delivered * 9, "{} of {}", paced.delivered, today.delivered);
}

/// 1 Mbit/s and 100 ms: today's window is 4 s of queue.
#[test]
fn on_a_slow_long_path_too() {
    static PACED: Keys = Keys::new();
    static TODAY: Keys = Keys::new();
    let shape = Shape { rate: 125, down: 50, up: 50 };
    let mut paced = Run::new(shape, true, &PACED);
    paced.run(40_000, 10_000, 300);
    let mut today = Run::new(shape, false, &TODAY);
    today.run(40_000, 10_000, 300);

    let idle = shape.idle_echo();
    eprintln!(
        "idle echo {idle} ms; p50 paced {} ms, today {} ms; delivered paced {}, today {}",
        paced.echo_p50(),
        today.echo_p50(),
        paced.delivered,
        today.delivered
    );
    assert!(today.echo_p50() > 10 * idle, "the reference queues up to 4 s in front of each key");
    assert!(paced.echo_p50() <= 2 * idle, "echo p50 {} ms, idle {idle} ms", paced.echo_p50());
    // A key each 300 ms for the whole run holds the bulk to a round trip and
    // 40 ms the whole time, 23 KB: in OpenSSH's messages of 32 KiB that was
    // one message a round trip, 72% of today's (T-661's Correction); in
    // messages of 8 KiB, topped up once a quarter is used, the path stays
    // full (T-670).
    assert!(paced.delivered * 10 >= today.delivered * 9, "{} of {}", paced.delivered, today.delivered);
}

/// T-660's run of `ping --under-load` on the slow link of its matrix, which
/// loses a segment in a hundred (scripts/fake_shape.py), on the direct
/// road. The first keys wait behind the window that the channel opened with
/// (T-661's Decision 8), until the drain at the first key lets it come; a
/// drain that ended at a guess of when it comes ended before it came, and
/// the window went back to the queue's round trip, seconds of it (T-670).
/// Each key after the drain waits for little; a loss holds the bytes behind
/// it a round trip, and the rate's best reads the burst after it (T-672),
/// so the bound is four idle echoes.
#[test]
fn on_a_slow_lossy_link_the_drain_waits_for_its_queue() {
    static PACED: Keys = Keys::new();
    static TODAY: Keys = Keys::new();
    let shape = Shape { rate: 125, down: 50, up: 50 };
    let mut paced = Run::capped(shape, super::Road::Direct.cap(), &PACED).lossy(0.01, 670);
    paced.under_load();
    let mut today = Run::new(shape, false, &TODAY).lossy(0.01, 670);
    today.under_load();

    let idle = shape.idle_echo();
    assert_eq!(paced.echoes.len(), 40, "each key came back: {:?}", paced.echoes);
    let after = p50(&paced.echoes[20..]);
    eprintln!(
        "idle echo {idle} ms; p50 paced {} ms, of the last 20 keys {after} ms, today {} ms; paced {:?}",
        paced.echo_p50(),
        today.echo_p50(),
        paced.echoes
    );
    assert!(today.echo_p50() > 10 * idle, "the reference queues up to 4 s in front of each key");
    assert!(paced.echo_p50() <= 8 * idle, "echo p50 {} ms, idle {idle} ms", paced.echo_p50());
    assert!(after <= 4 * idle, "the last 20 keys' p50 {after} ms, idle {idle} ms");
}

/// A window that bounds the flow, the road's cap on a long fat path where
/// nobody types: topped up once a quarter is used, three quarters of it
/// come each round trip, where russh's own rule, at half, let half of it
/// through (T-670), and the same 512 KiB moves a third more than today's.
#[test]
fn a_window_that_bounds_the_flow_lets_three_quarters_through_each_round_trip() {
    static PACED: Keys = Keys::new();
    static TODAY: Keys = Keys::new();
    let shape = Shape { rate: 12_500, down: 50, up: 50 };
    let mut paced = Run::capped(shape, super::Road::Other.cap(), &PACED);
    paced.run(20_000, u64::MAX, 1);
    let mut today = Run::new(shape, false, &TODAY);
    today.run(20_000, u64::MAX, 1);
    eprintln!("delivered: paced {}, today {}", paced.delivered, today.delivered);
    assert!(paced.delivered * 10 >= today.delivered * 13, "{} against {}", paced.delivered, today.delivered);
}

/// With no key, the paced window moves as much as today's.
#[test]
fn with_no_key_a_download_moves_as_today() {
    static PACED: Keys = Keys::new();
    static TODAY: Keys = Keys::new();
    let shape = Shape { rate: 1250, down: 30, up: 30 };
    let mut paced = Run::new(shape, true, &PACED);
    paced.run(20_000, u64::MAX, 1);
    let mut today = Run::new(shape, false, &TODAY);
    today.run(20_000, u64::MAX, 1);
    assert!(paced.echoes.is_empty());
    // The drains of the round trip cost a few per cent at most.
    assert!(paced.delivered * 100 >= today.delivered * 95, "{} of {}", paced.delivered, today.delivered);
}

/// The drains keep the least round trip that of the path, not of its queue:
/// after a minute of a download and keys, the window while typing is still
/// about the path's bytes of 100 ms, not of a growing queue.
#[test]
fn the_least_round_trip_does_not_grow_with_the_queue() {
    static KEYS: Keys = Keys::new();
    let shape = Shape { rate: 1250, down: 30, up: 30 };
    let mut run = Run::new(shape, true, &KEYS);
    run.run(60_000, 2_000, 200);
    let pace = run.pace.as_mut().expect("paced");
    let at = run.t0 + Duration::from_millis(60_000);
    assert!(!pace.draining(at), "no drain at 60 s: one began at 52 s or so, for less than a second");
    let target = pace.target(BULK, at);
    // 1.25 MB/s for 60 + 40 ms, and four thirds: 166666; a queue of 100 ms
    // more in the least round trip would give twice that.
    assert!((150_000..250_000).contains(&target), "{target}");
}

/// T-662: 100 Mbit/s and 100 ms, where nobody types: on the direct road the
/// window grows past today's 512 KiB, which holds a copy to about 5 MB/s, and
/// moves more than twice today's; on the default relay its cap of 1.5 MiB
/// still moves more than today's, and a road of the window of before moves
/// as today.
#[test]
fn where_nobody_types_a_window_grows_to_its_roads_cap() {
    static DIRECT: Keys = Keys::new();
    static RELAY: Keys = Keys::new();
    static OTHER: Keys = Keys::new();
    static TODAY: Keys = Keys::new();
    let shape = Shape { rate: 12_500, down: 50, up: 50 };
    let mut direct = Run::capped(shape, super::Road::Direct.cap(), &DIRECT);
    direct.run(20_000, u64::MAX, 1);
    let mut relay = Run::capped(shape, super::Road::Relay.cap(), &RELAY);
    relay.run(20_000, u64::MAX, 1);
    let mut other = Run::capped(shape, super::Road::Other.cap(), &OTHER);
    other.run(20_000, u64::MAX, 1);
    let mut today = Run::new(shape, false, &TODAY);
    today.run(20_000, u64::MAX, 1);
    eprintln!(
        "delivered: direct {}, relay {}, other {}, today {}",
        direct.delivered, relay.delivered, other.delivered, today.delivered
    );
    assert!(direct.delivered > 2 * today.delivered, "{} against {}", direct.delivered, today.delivered);
    assert!(relay.delivered > today.delivered * 3 / 2, "{} against {}", relay.delivered, today.delivered);
    assert!(other.delivered * 100 >= today.delivered * 95, "{} against {}", other.delivered, today.delivered);
    // The window of the direct road is never past its cap.
    let at = direct.t0 + Duration::from_millis(20_000);
    let pace = direct.pace.as_mut().expect("paced");
    assert!(pace.target(BULK, at) <= super::Road::Direct.cap());
}
