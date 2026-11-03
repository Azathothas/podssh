//! The sections of `doctor` that run at once (T-511, the operator's ruling
//! Q73): each section writes into a part of its own, and a part's text goes
//! out once each part before it has ended, so the report keeps its order
//! and the time of a run is that of its longest part, not their sum. The
//! first part that has not ended, the head, goes out line by line as it
//! runs, as a run of one section at a time did, so a long check never looks
//! like a hang. At most `jobs` parts run together, started in the order of
//! the report: one is one at a time, as before.

use std::cell::RefCell;
use std::future::Future;
use std::io::Write;
use std::rc::Rc;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use super::Line;

/// What a part keeps once it has ended: its lines and their counts, for the
/// counts of the report and for `--json`.
#[derive(Default)]
pub(super) struct Ended {
    pub(super) lines: Vec<Line>,
    pub(super) ok: usize,
    pub(super) failed: usize,
    pub(super) unknown: usize,
}

/// The parts of one run. The runtime is one thread, so a part's writes and
/// the ends of the others never meet.
struct Board {
    /// The text of each part that is not the head yet.
    held: Vec<Vec<u8>>,
    ended: Vec<Option<Ended>>,
    /// The first part that has not ended: its text goes out as it comes.
    head: usize,
    /// To the writer of the report; dropped once each part has ended, which
    /// ends the writer.
    out: Option<UnboundedSender<Vec<u8>>>,
}

impl Board {
    fn send(&self, bytes: Vec<u8>) {
        if let (Some(out), false) = (&self.out, bytes.is_empty()) {
            // The writer goes only when each part has ended: never lost.
            let _ = out.send(bytes);
        }
    }

    /// Part `index` has ended: each part after it that ended already goes
    /// out in order, and the first one that still runs becomes the head.
    fn end(&mut self, index: usize, ended: Ended) {
        self.ended[index] = Some(ended);
        while self.head < self.ended.len() && self.ended[self.head].is_some() {
            self.head += 1;
            if self.head < self.held.len() {
                let text = std::mem::take(&mut self.held[self.head]);
                self.send(text);
            }
        }
        if self.head == self.ended.len() {
            self.out = None;
        }
    }
}

/// A part's way into the board: the writer of its text, which a part's
/// [`super::Report`] takes as its output.
pub(super) struct Seat {
    board: Rc<RefCell<Board>>,
    index: usize,
}

impl Write for Seat {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut board = self.board.borrow_mut();
        if board.head == self.index {
            board.send(buf.to_vec());
        } else {
            board.held[self.index].extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    /// The writer of the report flushes each chunk that it writes.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `count` parts, `start(i, seat)` for each, at most `jobs` at once and
/// started in their order, while their text goes to `out` in that order.
/// Each part's lines, in the order of the parts.
pub(super) async fn run<F, Fut>(out: &mut dyn Write, count: usize, jobs: usize, mut start: F) -> Vec<Ended>
where
    F: FnMut(usize, Seat) -> Fut,
    Fut: Future<Output = Ended>,
{
    let (sender, receiver) = unbounded_channel();
    let board = Rc::new(RefCell::new(Board {
        held: vec![Vec::new(); count],
        ended: (0..count).map(|_| None).collect(),
        head: 0,
        // With no part, nothing will end it: the writer ends at once.
        out: (count > 0).then_some(sender),
    }));
    let parts = async {
        let mut running = FuturesUnordered::new();
        let mut next = 0;
        loop {
            while running.len() < jobs.max(1) && next < count {
                let part = start(next, Seat { board: board.clone(), index: next });
                let at = next;
                running.push(async move { (at, part.await) });
                next += 1;
            }
            match running.next().await {
                Some((at, ended)) => board.borrow_mut().end(at, ended),
                None => break,
            }
        }
    };
    futures_util::future::join(parts, write_out(out, receiver)).await;
    let slots = std::mem::take(&mut board.borrow_mut().ended);
    slots.into_iter().map(Option::unwrap_or_default).collect()
}

/// The writer of the report: what has come, flushed, as each line of a
/// check is shown once it is known.
async fn write_out(out: &mut dyn Write, mut receiver: UnboundedReceiver<Vec<u8>>) {
    while let Some(bytes) = receiver.recv().await {
        let _ = out.write_all(&bytes);
        // A line comes in several pieces: one flush for those that are here.
        while let Ok(more) = receiver.try_recv() {
            let _ = out.write_all(&more);
        }
        let _ = out.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::super::Report;
    use super::*;
    use std::time::Duration;
    use tokio::time::Instant;

    /// A part of the tests: its section, then a line after `wait`.
    async fn part(seat: Seat, title: &str, wait: Duration) -> Ended {
        let mut seat = seat;
        let mut report = Report::new(&mut seat);
        report.section(title);
        report.ok("first", format!("{title} began"));
        tokio::time::sleep(wait).await;
        report.ok("second", format!("{title} ended"));
        report.ended()
    }

    /// The text of `out`, and the time each chunk came, from `began`.
    #[derive(Default)]
    struct Timed {
        text: Vec<u8>,
        at: Vec<Duration>,
        began: Option<Instant>,
    }

    impl Write for Timed {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.text.extend_from_slice(buf);
            self.at.push(self.began.map(|b| b.elapsed()).unwrap_or_default());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const WAITS: [(&str, u64); 3] = [("a", 3), ("b", 1), ("c", 2)];

    async fn three(jobs: usize) -> (String, Vec<Ended>, Duration, Timed) {
        let mut out = Timed { began: Some(Instant::now()), ..Timed::default() };
        let began = Instant::now();
        let ended = run(&mut out, WAITS.len(), jobs, |i, seat| {
            let (title, wait) = WAITS[i];
            part(seat, title, Duration::from_secs(wait))
        })
        .await;
        let text = String::from_utf8(out.text.clone()).unwrap();
        (text, ended, began.elapsed(), out)
    }

    /// At once, the run takes its longest part; one at a time, their sum;
    /// the text and the lines are in the order of the parts either way.
    #[tokio::test(start_paused = true)]
    async fn the_parts_run_at_once_and_keep_their_order() {
        let (text, ended, took, _) = three(3).await;
        assert_eq!(took, Duration::from_secs(3), "the longest part");
        let (one, _, sum, _) = three(1).await;
        assert_eq!(sum, Duration::from_secs(6), "one at a time: the sum");
        assert_eq!(text, one, "the same report either way");
        let order: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(order[0], "a");
        assert!(order[1].contains("a began") && order[2].contains("a ended"), "{text}");
        assert_eq!(order[3], "b");
        assert_eq!(order[6], "c");
        let sections: Vec<&str> = ended.iter().map(|e| e.lines[0].section.as_str()).collect();
        assert_eq!(sections, ["a", "b", "c"]);
        assert!(ended.iter().all(|e| e.ok == 2 && e.failed == 0 && e.unknown == 0));
    }

    /// The head's lines go out as they come: the first line of the first
    /// part before it ends, and a later part's text once the head has ended.
    #[tokio::test(start_paused = true)]
    async fn the_head_goes_out_line_by_line() {
        let (text, _, _, out) = three(3).await;
        assert_eq!(out.at[0], Duration::ZERO, "the head's section at once: {text}");
        let ended_a = text.find("a ended").unwrap();
        let first_b = text.find("b began").unwrap();
        assert!(ended_a < first_b, "{text}");
        // b ended at 1 s, held until a ended at 3 s.
        assert!(out.at.iter().all(|t| *t == Duration::ZERO || *t == Duration::from_secs(3)), "{:?}", out.at);
    }

    /// At most `jobs` run together: two at once, three parts of 1 s, 2 s.
    #[tokio::test(start_paused = true)]
    async fn jobs_bound_the_parts_that_run_together() {
        let mut out = Vec::new();
        let began = Instant::now();
        let ended = run(&mut out, 3, 2, |i, seat| part(seat, ["x", "y", "z"][i], Duration::from_secs(1))).await;
        assert_eq!(began.elapsed(), Duration::from_secs(2));
        assert_eq!(ended.len(), 3);
        // No part: nothing runs, and the writer ends.
        let none = run(&mut out, 0, 4, |i, seat| part(seat, ["x"][i], Duration::ZERO)).await;
        assert!(none.is_empty());
    }
}
