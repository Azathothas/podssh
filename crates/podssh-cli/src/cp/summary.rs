//! The summary of a run of `cp`, `mv` and `podssh run`'s copy (T-472): one
//! line on stderr at the default level, which `-q` silences, also after a
//! failure and before its error; with `--jsonl` a `summary` object on stdout
//! in its place. At the default level a copy that succeeds said nothing of
//! what it sent, left as it was or took, and the run has counted it. `scp`
//! and `sftp` keep the output of OpenSSH's, with no summary.

use std::time::Duration;

use super::gauge::bytes;
use super::Outcome;

/// What a run did, as its summary counts it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// The files copied, and their bytes.
    pub copied: usize,
    pub bytes: u64,
    /// The files that `podssh run` found as they are here.
    pub unchanged: usize,
    /// The items skipped by design: a device, a FIFO or a socket (T-476).
    pub skipped: usize,
    /// Each failure, said when it came.
    pub failed: usize,
}

impl Counts {
    pub(super) fn of(outcome: &Outcome) -> Counts {
        Counts {
            copied: outcome.done.len(),
            bytes: outcome.done.iter().map(|done| done.bytes).sum(),
            unchanged: outcome.unchanged,
            skipped: outcome.skipped.len(),
            failed: outcome.failures().count(),
        }
    }
}

/// The line: `3 copied (3.1 MiB), 2 unchanged, 1 skipped, 1 failed, in 12.0
/// s (264.5 KiB/s)`. Each count of zero is left out but the first, and so
/// are the bytes and the rate when no byte went.
pub fn line(counts: &Counts, took: Duration) -> String {
    let mut text = format!("{} copied", counts.copied);
    if counts.copied > 0 {
        text.push_str(&format!(" ({})", bytes(counts.bytes)));
    }
    for (n, what) in [(counts.unchanged, "unchanged"), (counts.skipped, "skipped"), (counts.failed, "failed")] {
        if n > 0 {
            text.push_str(&format!(", {n} {what}"));
        }
    }
    let secs = took.as_secs_f64();
    text.push_str(&format!(", in {secs:.1} s"));
    if counts.bytes > 0 && secs > 0.0 {
        text.push_str(&format!(" ({}/s)", bytes((counts.bytes as f64 / secs) as u64)));
    }
    text
}

/// The `summary` object of `--jsonl`, with each count, zero or not.
pub fn json(counts: &Counts, took: Duration) -> serde_json::Value {
    serde_json::json!({
        "event": "summary",
        "copied": counts.copied,
        "bytes": counts.bytes,
        "unchanged": counts.unchanged,
        "skipped": counts.skipped,
        "failed": counts.failed,
        "seconds": (took.as_secs_f64() * 10.0).round() / 10.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_leaves_out_each_count_of_zero_but_the_first() {
        let all = Counts { copied: 3, bytes: 3_250_586, unchanged: 2, skipped: 1, failed: 1 };
        assert_eq!(
            line(&all, Duration::from_secs(12)),
            "3 copied (3.1 MiB), 2 unchanged, 1 skipped, 1 failed, in 12.0 s (264.5 KiB/s)"
        );
        let none = Counts { unchanged: 3, ..Counts::default() };
        assert_eq!(line(&none, Duration::from_millis(400)), "0 copied, 3 unchanged, in 0.4 s");
        let one = Counts { copied: 1, bytes: 34, ..Counts::default() };
        assert_eq!(line(&one, Duration::from_secs(2)), "1 copied (34 B), in 2.0 s (17 B/s)");
        let failed = Counts { failed: 1, ..Counts::default() };
        assert_eq!(line(&failed, Duration::ZERO), "0 copied, 1 failed, in 0.0 s");
    }

    #[test]
    fn the_object_holds_each_count() {
        let counts = Counts { copied: 2, bytes: 10, ..Counts::default() };
        let object = json(&counts, Duration::from_millis(1250));
        assert_eq!(object["event"], "summary");
        assert_eq!((object["copied"].as_u64(), object["bytes"].as_u64()), (Some(2), Some(10)));
        assert_eq!((object["unchanged"].as_u64(), object["failed"].as_u64()), (Some(0), Some(0)));
        assert_eq!(object["seconds"].as_f64(), Some(1.3));
    }
}
