//! The round trip of a link, from the layer's own records (T-663). A spare
//! link opens once a question has waited three of them with no answer, 1 s
//! at least and 3 s at most ([`super::beside::spare_after`]), as osewa
//! suspects a link after the larger of three round trips and 1 s.
//!
//! Two questions of a link are timed, one of each at a time, as TCP times
//! one segment (RFC 6298): a `PING`, which its `PONG` of the same value
//! answers, and a batch of `DATA`, which an `ACK` or a `PONG` at or past its
//! end answers. The far end holds an `ACK` 200 ms at most, so the sample of
//! `DATA` is the round trip and that hold: the time that such a question
//! waits for its answer, which the spare's bound must outlast. `DATA` that a
//! resume sends again is timed on its own link, where no earlier copy can
//! answer it. Each link times its own, as the next may take another road.

use std::time::Duration;

// tokio's clock, which a test can pause.
use tokio::time::Instant;

use super::record::{kind, Record};

/// The part of a smoothed round trip that each new sample takes: RFC 6298's
/// 1/8.
const NEW_PART: u32 = 8;

/// The smoothed round trip of a link.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RoundTrip {
    smoothed: Option<Duration>,
}

impl RoundTrip {
    /// A question waited `sample` for its answer: the first sets the round
    /// trip, and each next moves it by an eighth.
    pub fn sample(&mut self, sample: Duration) {
        self.smoothed = Some(match self.smoothed {
            None => sample,
            Some(smoothed) => smoothed.saturating_mul(NEW_PART - 1).saturating_add(sample) / NEW_PART,
        });
    }

    /// The smoothed round trip, once a question of the link was answered.
    pub fn smoothed(&self) -> Option<Duration> {
        self.smoothed
    }
}

/// The questions of one link that are timed: one `PING` and one batch of
/// `DATA` at a time.
#[derive(Debug, Default)]
pub struct Timing {
    /// The value of a `PING`, and when it went out.
    ping: Option<(u64, Instant)>,
    /// The offset after a batch of `DATA`, and when it went out.
    data: Option<(u64, Instant)>,
}

impl Timing {
    /// A `PING` of `value` went out at `at`. It takes the place of one that
    /// waits: each `PING` has a value of its own, so an older one's `PONG`
    /// is then no sample.
    pub fn pinged(&mut self, value: u64, at: Instant) {
        self.ping = Some((value, at));
    }

    /// `DATA` up to the offset `end` went out at `at`: timed when no other
    /// batch is.
    pub fn sent(&mut self, end: u64, at: Instant) {
        if self.data.is_none() {
            self.data = Some((end, at));
        }
    }

    /// The far end's `record` came at `now`: each sample that it gives. A
    /// `PONG` answers its `PING`, and acknowledges `DATA` as an `ACK` does.
    pub fn answered(&mut self, record: &Record, now: Instant) -> [Option<Duration>; 2] {
        match record {
            Record::Pong { value, offset } => [self.ponged(*value, now), self.acked(*offset, now)],
            Record::Ack { offset } => [None, self.acked(*offset, now)],
            _ => [None, None],
        }
    }

    fn ponged(&mut self, value: u64, now: Instant) -> Option<Duration> {
        match self.ping {
            Some((pinged, at)) if pinged == value => {
                self.ping = None;
                Some(now.saturating_duration_since(at))
            }
            _ => None,
        }
    }

    fn acked(&mut self, offset: u64, now: Instant) -> Option<Duration> {
        match self.data {
            Some((end, at)) if offset >= end => {
                self.data = None;
                Some(now.saturating_duration_since(at))
            }
            _ => None,
        }
    }
}

/// The offset after the last `DATA` record among `records`, encoded records
/// end to end as the writer sends them; `None` with no `DATA`.
pub fn data_end(records: &[u8]) -> Option<u64> {
    let mut end = None;
    let mut rest = records;
    // A record: its type, a 32-bit length, the body; the body of `DATA`
    // starts with its 64-bit offset.
    while let Some(len) = rest.get(1..5) {
        let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
        let Some(record) = len.checked_add(5).and_then(|n| rest.get(..n)) else { break };
        if record[0] == kind::DATA && record.len() >= 13 {
            let offset = u64::from_be_bytes(record[5..13].try_into().ok()?);
            end = Some(offset.saturating_add((record.len() - 13) as u64));
        }
        rest = &rest[record.len()..];
    }
    end
}

#[cfg(test)]
mod tests {
    use super::super::link::Link;
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn the_first_sample_sets_the_round_trip_and_each_next_moves_it_by_an_eighth() {
        let mut round_trip = RoundTrip::default();
        assert_eq!(round_trip.smoothed(), None, "nothing answered yet");
        round_trip.sample(MS * 800);
        assert_eq!(round_trip.smoothed(), Some(MS * 800));
        round_trip.sample(Duration::ZERO);
        assert_eq!(round_trip.smoothed(), Some(MS * 700));
    }

    #[test]
    fn a_pong_answers_its_own_ping_and_acknowledges_the_data_before_it() {
        let t0 = Instant::now();
        let mut timing = Timing::default();
        timing.sent(100, t0);
        // A second batch waits for the first's answer: one timed at a time.
        timing.sent(200, t0 + MS * 10);
        timing.pinged(7, t0 + MS * 20);
        // An older `PING`'s `PONG`, which acknowledges too little: nothing.
        let stale = Record::Pong { value: 6, offset: 99 };
        assert_eq!(timing.answered(&stale, t0 + MS * 60), [None, None]);
        let pong = Record::Pong { value: 7, offset: 150 };
        assert_eq!(timing.answered(&pong, t0 + MS * 70), [Some(MS * 50), Some(MS * 70)]);
        // Each was answered once.
        assert_eq!(timing.answered(&pong, t0 + MS * 80), [None, None]);
    }

    #[test]
    fn an_ack_answers_the_batch_that_it_reaches_and_no_other_record_answers() {
        let t0 = Instant::now();
        let mut timing = Timing::default();
        timing.sent(64, t0);
        assert_eq!(timing.answered(&Record::Ack { offset: 63 }, t0 + MS * 100), [None, None]);
        assert_eq!(timing.answered(&Record::Ping { value: 1 }, t0 + MS * 150), [None, None]);
        assert_eq!(timing.answered(&Record::Ack { offset: 64 }, t0 + MS * 250), [None, Some(MS * 250)]);
    }

    #[test]
    fn a_batch_ends_where_its_last_data_record_ends() {
        let mut link = Link::new(0, 1000);
        let mut batch = Vec::new();
        link.send(b"hello", &mut batch).unwrap();
        link.send(b"abc", &mut batch).unwrap();
        assert_eq!(data_end(&batch), Some(1008));
        // A record of another kind first, as a resume's records may hold.
        let mut mixed = Record::Ping { value: 3 }.to_bytes().unwrap();
        mixed.extend_from_slice(&batch);
        assert_eq!(data_end(&mixed), Some(1008));
        assert_eq!(data_end(&Record::Ack { offset: 5 }.to_bytes().unwrap()), None, "no DATA");
        assert_eq!(data_end(&batch[..batch.len() - 1]), Some(1005), "a cut record is not read");
        assert_eq!(data_end(&[]), None);
    }
}
