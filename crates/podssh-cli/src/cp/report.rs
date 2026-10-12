//! What a run of `cp`, `mv` or `scp` prints at its end: each action of a dry
//! run (T-143, T-144), each file done, each delete, and the failure, as text
//! or as `--jsonl` objects; and its exit code.

use std::io::Write;

use podssh_ssh::Log;

use super::{digest, Outcome};

/// Print each action of a dry run, each file done and the failure; the exit
/// code.
pub(super) fn report(outcome: &Outcome, jsonl: bool, out: &mut dyn Write, log: &Log) -> i32 {
    for (action, from, to) in &outcome.planned {
        if jsonl {
            let line = serde_json::json!({ "event": "plan", "action": action, "source": from, "destination": to });
            let _ = writeln!(out, "{line}");
        } else {
            let line = match *action {
                "mkdir" => format!("mkdir {to}"),
                "copy" => format!("copy {from} -> {to}"),
                "link" => format!("link {from} -> {to}"),
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
    let Some((source, failed)) = &outcome.failed else { return 0 };
    if jsonl {
        let line = serde_json::json!({
            "event": "error",
            "source": source,
            "message": failed.message,
            "code": failed.fault.code(),
        });
        let _ = writeln!(out, "{line}");
    }
    log.error(&failed.message);
    failed.fault.code()
}
