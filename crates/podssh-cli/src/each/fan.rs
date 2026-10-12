//! The fan-out of `podssh each` (T-183): at most N hosts at once, each to its
//! end, and none started after a failure with `--fail-fast`; and the rule
//! that makes one exit status of theirs. Both are plain functions of the
//! hosts' ends, so that a test gives them any order with no network.

use std::future::Future;

use futures_util::stream::{FuturesUnordered, StreamExt};

/// How one host ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The command's exit status, as `podssh ssh` gives it: 128 + N for a
    /// signal, 255 for a session that ended with none.
    Status(i32),
    /// No connection, or no login: what said so first.
    Failed(String),
    /// `--fail-fast` started no new host after a failure.
    NotStarted,
}

impl Ended {
    /// Its part of the exit status: a host that could not connect or log in
    /// is 255, as `podssh ssh` exits; one that never started is none.
    pub fn code(&self) -> Option<i32> {
        match self {
            Ended::Status(code) => Some(*code),
            Ended::Failed(_) => Some(podssh_ssh::EXIT_FAILURE),
            Ended::NotStarted => None,
        }
    }

    /// Whether it failed: a status other than 0, or no session.
    pub fn failed(&self) -> bool {
        self.code().is_some_and(|code| code != 0)
    }
}

/// The exit status of a run: the largest status of the hosts, so 0 only when
/// each host gave 0, and 255 when one could not connect or log in, whatever
/// the order in which they ended.
pub fn exit_status(ends: &[Ended]) -> i32 {
    ends.iter().filter_map(Ended::code).max().unwrap_or(0)
}

/// Run `start(i)` for each `i` below `count`, `parallel` at once, each to its
/// end; with `fail_fast`, no new one starts after one failed, and the ones
/// that run still end. Each host's end, in the order of the hosts.
pub async fn fan_out<F, Fut>(count: usize, parallel: usize, fail_fast: bool, mut start: F) -> Vec<Ended>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Ended>,
{
    let mut ends = vec![Ended::NotStarted; count];
    let mut running = FuturesUnordered::new();
    let (mut next, mut failed) = (0, false);
    loop {
        while running.len() < parallel.max(1) && next < count && !(fail_fast && failed) {
            let one = start(next);
            let at = next;
            running.push(async move { (at, one.await) });
            next += 1;
        }
        match running.next().await {
            Some((at, end)) => {
                failed |= end.failed();
                ends[at] = end;
            }
            None => return ends,
        }
    }
}

/// The lines of the summary: each host, and its status or why it has none.
pub fn summary(labels: &[String], ends: &[Ended]) -> Vec<String> {
    let width = labels.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    let failed = ends.iter().filter(|e| e.failed()).count();
    let skipped = ends.iter().filter(|e| **e == Ended::NotStarted).count();
    let mut lines = vec![format!(
        "{} hosts: {} gave 0, {failed} failed, {skipped} not started",
        labels.len(),
        labels.len() - failed - skipped
    )];
    for (label, end) in labels.iter().zip(ends) {
        let said = match end {
            Ended::Status(code) => code.to_string(),
            Ended::Failed(why) => format!("255, no session: {why}"),
            Ended::NotStarted => "not started (--fail-fast)".to_string(),
        };
        lines.push(format!("  {label:width$}  {said}"));
    }
    lines
}
