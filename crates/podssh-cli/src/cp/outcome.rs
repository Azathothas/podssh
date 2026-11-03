//! What a run of `cp`, `mv` or `scp` ended with: each file done, each item
//! skipped by design, and its failures. Each failure is said once, when it
//! comes (T-476): the first keeps the run's exit code, in the order of the
//! sources (T-297), and the end of the run says it again only when nothing
//! said it before, as for a connection that failed.

use podssh_ssh::Log;

use super::mirror;
use super::resume::Before;
use super::transfer::{Done, Failed};
use super::tree_copy;

/// What a run ended with: each file done, and the first failure.
#[derive(Default)]
pub(super) struct Outcome {
    pub(super) done: Vec<Done>,
    /// The first failure: its code is the run's.
    pub(super) failed: Option<(String, Failed)>,
    /// The first failure was said when it came.
    pub(super) said: bool,
    /// Each failure after the first, said when it came: with `--jsonl`,
    /// an `error` object each.
    pub(super) more: Vec<(String, Failed)>,
    /// Each device, FIFO or socket of a tree, not copied and no failure
    /// (T-476), with its kind.
    pub(super) skipped: Vec<(String, &'static str)>,
    /// The first leg of a move between servers: each source as it was.
    pub(super) recorded: Vec<Before>,
    /// The actions of a dry run (T-143), in their order.
    pub(super) planned: Vec<tree_copy::Planned>,
    /// What `--delete` removed (T-144), and what waits for the end of the
    /// run.
    pub(super) deleted: Vec<String>,
    pub(super) pending: Vec<mirror::Pending>,
    /// The files that `podssh run` did not send again (T-192).
    pub(super) unchanged: usize,
}

impl Outcome {
    /// A failure of `name`, said now: the first is kept for the exit code,
    /// each later one for `--jsonl`.
    pub(super) fn fail(&mut self, log: &Log, name: String, failed: Failed) {
        log.error(&failed.message);
        if self.failed.is_none() {
            self.failed = Some((name, failed));
            self.said = true;
        } else {
            self.more.push((name, failed));
        }
    }

    /// Each failure, the first first.
    pub(super) fn failures(&self) -> impl Iterator<Item = &(String, Failed)> {
        self.failed.iter().chain(&self.more)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exitmap::Fault;

    #[test]
    fn each_failure_is_kept_and_the_first_gives_the_code() {
        let log = Log::new(podssh_ssh::LogLevel::Quiet);
        let mut outcome = Outcome::default();
        outcome.fail(&log, "a".into(), Failed::new(Fault::NoInput, "a: missing".into()));
        outcome.fail(&log, "b".into(), Failed::new(Fault::CantCreate, "b: not written".into()));
        assert!(outcome.said, "said when it came");
        assert_eq!(outcome.failed.as_ref().map(|(_, f)| f.fault), Some(Fault::NoInput));
        let names: Vec<&str> = outcome.failures().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
    }
}
