//! The two halves of a link against each other with no I/O, through a
//! server of the test's that holds 32 packets for each receiver, drops the
//! oldest past them, as derper does, and drops others at random; the time is
//! simulated, a millisecond at each step. A planted sender that never sends
//! a segment again fails each test with drops.

use std::collections::VecDeque;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::time::Instant;

use super::packet::{self, Body, Packet};
use super::recv::Receiver;
use super::send::Sender;

const LINK: packet::LinkId = [7; packet::ID];
const MIB: usize = 1 << 20;

/// Numbers that a seed fixes, so that a failure comes again (xorshift64*).
struct Dice(u64);

impl Dice {
    fn roll(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn percent(&mut self) -> u64 {
        self.roll() % 100
    }
}

fn bytes(size: usize, seed: u64) -> Vec<u8> {
    let mut dice = Dice(seed);
    (0..size).map(|_| dice.roll() as u8).collect()
}

/// The way to one receiver: the packets on their way to the server, and
/// those that wait there for the receiver.
#[derive(Default)]
struct Way {
    transit: VecDeque<(Instant, Vec<u8>)>,
    queue: VecDeque<Vec<u8>>,
    dropped: usize,
}

/// A server: a delay to it, the packets that it writes to a receiver in a
/// step, a queue of `queue` packets for each receiver, and the drops at
/// random.
struct Server {
    ways: [Way; 2],
    delay: Duration,
    per_step: usize,
    queue: usize,
    drop_percent: u64,
    dice: Dice,
}

impl Server {
    fn new(drop_percent: u64, per_step: usize) -> Server {
        Server {
            ways: [Way::default(), Way::default()],
            delay: Duration::from_millis(5),
            per_step,
            queue: 32,
            drop_percent,
            dice: Dice(0x9e37_79b9_7f4a_7c15),
        }
    }

    fn send(&mut self, to: usize, packet: Vec<u8>, now: Instant) {
        if self.dice.percent() < self.drop_percent {
            self.ways[to].dropped += 1;
            return;
        }
        self.ways[to].transit.push_back((now + self.delay, packet));
    }

    fn deliver(&mut self, to: usize, now: Instant) -> Vec<Vec<u8>> {
        let way = &mut self.ways[to];
        while way.transit.front().is_some_and(|(at, _)| *at <= now) {
            let Some((_, packet)) = way.transit.pop_front() else { break };
            // A full queue drops its oldest packet, as derper's `sendPkt` does.
            if way.queue.len() == self.queue {
                way.queue.pop_front();
                way.dropped += 1;
            }
            way.queue.push_back(packet);
        }
        let n = way.queue.len().min(self.per_step);
        way.queue.drain(..n).collect()
    }

    fn dropped(&self) -> usize {
        self.ways.iter().map(|w| w.dropped).sum()
    }
}

/// One end: what it sends, what it got, and from when it reads.
struct End {
    send: Sender,
    recv: Receiver,
    source: Vec<u8>,
    written: usize,
    got: Sha256,
    got_bytes: usize,
    reads_from: Instant,
}

impl End {
    fn new(source: Vec<u8>, now: Instant) -> End {
        End {
            send: Sender::new(now),
            recv: Receiver::new(),
            source,
            written: 0,
            got: Sha256::new(),
            got_bytes: 0,
            reads_from: now,
        }
    }

    fn step(&mut self, now: Instant) -> Vec<Vec<u8>> {
        if self.written < self.source.len() {
            self.written += self.send.write(&self.source[self.written..]);
            if self.written == self.source.len() {
                self.send.finish();
            }
        }
        if now >= self.reads_from {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = self.recv.read(&mut buf);
                if n == 0 {
                    break;
                }
                self.got.update(&buf[..n]);
                self.got_bytes += n;
            }
        }
        let mut segments = Vec::new();
        self.send.poll(now, &mut segments);
        let mut out: Vec<Vec<u8>> = segments.iter().map(|s| packet::data(&LINK, s.seq, s.fin, &s.data)).collect();
        if let Some(ack) = self.recv.ack(now) {
            out.push(Packet { link: LINK, body: Body::Ack(ack) }.encode());
        }
        out
    }

    fn take(&mut self, bytes: &[u8], now: Instant) {
        match Packet::decode(bytes).expect("a packet of the link").body {
            Body::Data { seq, fin, data } => self.recv.on_data(seq, fin, data, now),
            Body::Ack(ack) => self.send.on_ack(&ack, now),
            other => panic!("a link sent {other:?}"),
        }
    }

    fn finished(&self) -> bool {
        self.recv.at_end() && self.send.ended()
    }
}

/// Each end sends `size` bytes to the other through `server`, the second
/// starting to read at `second_reads`: the simulated time it took, once each
/// end got the other's bytes whole, with their end.
fn exchange(size: usize, server: &mut Server, second_reads: Duration, limit: Duration) -> Result<Duration, String> {
    let start = Instant::now();
    let mut now = start;
    let mut ends = [End::new(bytes(size, 1), now), End::new(bytes(size, 2), now)];
    ends[1].reads_from = start + second_reads;
    while now.saturating_duration_since(start) < limit {
        for (i, end) in ends.iter_mut().enumerate() {
            for packet in server.deliver(i, now) {
                end.take(&packet, now);
            }
        }
        for (i, end) in ends.iter_mut().enumerate() {
            for packet in end.step(now) {
                server.send(1 - i, packet, now);
            }
        }
        if ends.iter().all(End::finished) {
            for (i, end) in ends.iter().enumerate() {
                let sent = Sha256::digest(&ends[1 - i].source);
                assert_eq!(end.got_bytes, size, "end {i} got every byte");
                assert_eq!(end.got.clone().finalize(), sent, "end {i} got the bytes that were sent");
            }
            return Ok(now.saturating_duration_since(start));
        }
        if let Some(i) = ends.iter().position(|end| end.send.dead(now)) {
            return Err(format!("end {i}'s link is dead at {:?}", now.saturating_duration_since(start)));
        }
        now += Duration::from_millis(1);
    }
    let got: Vec<usize> = ends.iter().map(|e| e.got_bytes).collect();
    Err(format!("not done within {limit:?}: the ends got {got:?} of {size} bytes"))
}

#[test]
fn eight_mib_go_each_way_with_no_loss() {
    let mut server = Server::new(0, 4);
    let took = exchange(8 * MIB, &mut server, Duration::ZERO, Duration::from_secs(60)).unwrap();
    assert!(took < Duration::from_secs(10), "{took:?}");
}

#[test]
fn eight_mib_go_each_way_with_five_percent_of_the_packets_dropped() {
    let mut server = Server::new(5, 4);
    let took = exchange(8 * MIB, &mut server, Duration::ZERO, Duration::from_secs(300)).unwrap();
    assert!(server.dropped() > 0, "the server dropped no packet, so the test proves nothing");
    assert!(took < Duration::from_secs(120), "{took:?}");
}

#[test]
fn a_tenth_dropped_and_lost_acknowledgements_and_ends_are_sent_again() {
    let mut server = Server::new(10, 4);
    exchange(256 * 1024, &mut server, Duration::ZERO, Duration::from_secs(300)).unwrap();
}

#[test]
fn a_slow_receiver_whose_queue_fills_still_gets_each_byte() {
    // One packet a step reaches each end: the server's queue fills, and
    // drops its oldest packets, as derper's does.
    let mut server = Server::new(0, 1);
    exchange(4 * MIB, &mut server, Duration::ZERO, Duration::from_secs(300)).unwrap();
}

#[test]
fn a_reader_that_stops_closes_the_window_and_its_link_lives_on() {
    let mut server = Server::new(0, 4);
    // The second end reads nothing for 90 s, three times the time after
    // which a link with no acknowledgement is dead.
    let took = exchange(4 * MIB, &mut server, Duration::from_secs(90), Duration::from_secs(300)).unwrap();
    assert!(took >= Duration::from_secs(90), "{took:?}");
}
