//! T-661 on a fake path: a bottleneck with a deep buffer (it queues all it
//! is given), a server that sends a bulk channel as fast as its window lets
//! it, a key's echo queued behind that, and russh's rule of the adjust in
//! between (to the target once less than half of it is left). Today's fixed
//! window of 512 KiB is the reference. Time is the simulation's own, a
//! millisecond a step, so each run gives the same figures.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::{Keys, Pace};
use crate::run::WINDOW;

/// The bulk channel's number.
const BULK: u32 = 2;
/// The largest data message of the server: OpenSSH's.
const PACKET: u64 = 32 * 1024;
/// A key's echo on the wire.
const ECHO: u64 = 64;

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
        }
    }

    fn at(&self, step: u64) -> Instant {
        self.t0 + Duration::from_millis(step)
    }

    /// Run until `end`, a key each `every` from `from` on.
    fn run(&mut self, end: u64, from: u64, every: u64) {
        for now in 0..end {
            if now >= from && (now - from) % every == 0 {
                self.keys.key(self.at(now));
                self.up.push_back((now + self.shape.up, Up::Key(now)));
            }
            self.step(now);
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
            let n = self.credit.min(PACKET);
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
                self.down.push_back((now + self.shape.down, done));
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
    /// the target, the adjust, then the bytes to the handler.
    fn bulk(&mut self, n: u64, now: u64) {
        let at = self.at(now);
        let target = match self.pace.as_mut() {
            Some(pace) => u64::from(pace.target(BULK, at)),
            None => u64::from(WINDOW),
        };
        if n <= self.remaining {
            self.remaining -= n;
        }
        if self.remaining < target / 2 {
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
        let mut sorted = self.echoes.clone();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }
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
    assert!(paced.delivered * 10 >= today.delivered * 9, "{} of {}", paced.delivered, today.delivered);
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
