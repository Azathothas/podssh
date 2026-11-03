//! What a run of `cp`, `mv` or `scp` prints at its end: each action of a dry
//! run (T-143, T-144), each file done, each delete, each item skipped and
//! each failure, as text or as `--jsonl` objects; the summary of `cp` and
//! `mv` (T-472); and its exit code. A failure said when it came is not said
//! again (T-476).

use std::io::Write;
use std::time::Duration;

use podssh_ssh::Log;

use super::summary::{self, Counts};
use super::{digest, Outcome};

/// Print each action of a dry run, each file done and the failure; the exit
/// code. `took` is how long the run took, when it gives a summary.
pub(super) fn report(outcome: &Outcome, jsonl: bool, out: &mut dyn Write, log: &Log, took: Option<Duration>) -> i32 {
    for (action, from, to) in &outcome.planned {
        if jsonl {
            let line = serde_json::json!({ "event": "plan", "action": action, "source": from, "destination": to });
            let _ = writeln!(out, "{line}");
        } else {
            let line = match *action {
                "mkdir" => format!("mkdir {to}"),
                "copy" => format!("copy {from} -> {to}"),
                "link" => format!("link {from} -> {to}"),
                "hardlink" => format!("hardlink {from} -> {to}"),
                "delete" => format!("delete {to}"),
                _ => format!("skip {from}: {to}"),
            };
            let _ = writeln!(out, "{line}");
        }
    }
    for path in &outcome.deleted {
        if jsonl {
            let _ = writeln!(out, "{}", serde_json::json!({ "event": "deleted", "path": path }));
        } else {
            log.verbose(&format!("deleted {path}"));
        }
    }
    if !outcome.deleted.is_empty() {
        log.info(&format!("{} deleted, which the source does not have", outcome.deleted.len()));
    }
    for done in &outcome.done {
        let sha256 = done.sum.as_ref().map(digest::hex);
        if jsonl {
            let mut line = serde_json::json!({
                "event": "done",
                "source": done.source,
                "destination": done.destination,
                "bytes": done.bytes,
                "sha256": sha256,
                "verified_by": done.verified_by,
                "atomic": !done.not_atomic,
            });
            if let Some(removed) = done.removed {
                line["source_removed"] = removed.into();
            }
            // With --delta: the blocks that went, or why the whole file went.
            if let Some(delta) = &done.delta {
                line["delta"] = delta.json();
            }
            let _ = writeln!(out, "{line}");
        } else {
            let how = match &sha256 {
                Some(hex) => format!("{} bytes, SHA-256 {hex} (far side: {})", done.bytes, done.verified_by),
                None => format!("{} bytes, renamed on the server", done.bytes),
            };
            let source = match done.removed {
                Some(true) => "; the source is gone",
                Some(false) => "; the source stays",
                None => "",
            };
            log.verbose(&format!("{} -> {}: {how}{source}", done.source, done.destination));
        }
    }
    if jsonl {
        // Each device, FIFO or socket that a tree skipped (T-476), and each
        // failure, the first first: each was said when it came.
        for (source, kind) in &outcome.skipped {
            let line = serde_json::json!({ "event": "skipped", "source": source, "why": kind });
            let _ = writeln!(out, "{line}");
        }
        for (source, failed) in outcome.failures() {
            let line = serde_json::json!({
                "event": "error",
                "source": source,
                "message": failed.message,
                "code": failed.fault.code(),
            });
            let _ = writeln!(out, "{line}");
        }
    }
    // The summary, at the default level, before the error that nothing said
    // yet, so that the error stays the last line.
    if let Some(took) = took {
        let counts = Counts::of(outcome);
        if jsonl {
            let _ = writeln!(out, "{}", summary::json(&counts, took));
        } else {
            log.info(&summary::line(&counts, took));
        }
    }
    let Some((_, failed)) = &outcome.failed else { return 0 };
    // Once: a failure said when it came is not said again (T-476).
    if !outcome.said {
        log.error(&failed.message);
    }
    failed.fault.code()
}
