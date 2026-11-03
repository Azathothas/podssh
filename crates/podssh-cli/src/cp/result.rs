//! `--result-file FILE` of `cp`, `mv` and `scp`, and the parts that `run`
//! and `sftp` share (T-486, GitHub #97): one JSON object at the end of each
//! run, with the keys of `ssh --result-file` in their meaning
//! ([`crate::ssh::result`]), and `verb`, `error`, the files and their bytes
//! each way. The facts come from the run's own outcome and from the record
//! of its own scope (`podssh_ssh::outcome::Scope`), never from the
//! process's, as a copy past the relay's limits opens more than one session.

use std::time::Duration;

use podssh_ssh::outcome::{Facts, Record};
use serde_json::{json, Value};

use super::delta::Delta;
use super::plan::Direction;
use super::summary::Counts;
use super::transfer::{Cause, Done, Failed};
use super::Outcome;
use crate::exitmap::Fault;

/// What a run did, for its record: filled as it goes, read at its end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Did {
    /// The files, when the run got as far as its copy and kept its counts.
    pub copied: Option<Copied>,
    /// The class of its failure, when the run knew it; else the exit code
    /// tells it ([`crate::ssh::result::refused`]).
    pub failure: Option<&'static str>,
    /// The words of its failure.
    pub error: Option<String>,
}

/// The files of a copy, and their bytes each way through this host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Copied {
    pub sent: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub deleted: usize,
    pub failed: usize,
    pub up: u64,
    pub down: u64,
    /// The sources that `mv` removed once their copy was verified.
    pub removed: Vec<String>,
}

impl Copied {
    /// What the outcome of a copy that went `direction` holds.
    pub(super) fn of(outcome: &Outcome, direction: Direction) -> Copied {
        let moved: u64 = outcome.done.iter().map(moved).sum();
        // Between servers the bytes come down and go up again, unless the
        // server copied or renamed the file within itself.
        let (up, down) = match direction {
            Direction::Up => (moved, 0),
            Direction::Down => (0, moved),
            Direction::Across if outcome.through => (moved, moved),
            Direction::Across => (0, 0),
        };
        Copied {
            sent: outcome.done.len(),
            unchanged: outcome.unchanged,
            skipped: outcome.skipped.len(),
            deleted: outcome.deleted.len(),
            failed: outcome.failures().count(),
            up,
            down,
            removed: outcome.done.iter().filter(|d| d.removed == Some(true)).map(|d| d.source.clone()).collect(),
        }
    }

    /// The copy of `podssh run`, up alone, from the counts of its summary
    /// (T-472): the bytes of the files that it sent.
    pub(crate) fn up(counts: &Counts) -> Copied {
        Copied {
            sent: counts.copied,
            unchanged: counts.unchanged,
            skipped: counts.skipped,
            failed: counts.failed,
            up: counts.bytes,
            ..Copied::default()
        }
    }

    /// The keys `files` and `transferred`.
    fn json(&self) -> (Value, Value) {
        let files = json!({
            "sent": self.sent,
            "unchanged": self.unchanged,
            "skipped": self.skipped,
            "deleted": self.deleted,
            "failed": self.failed,
        });
        (files, json!({ "up": self.up, "down": self.down }))
    }
}

/// The bytes of a file that went through this host: its size, or with
/// `--delta` the blocks that went; none for a rename or a hard link.
pub(crate) fn moved(done: &Done) -> u64 {
    if done.verified_by == "rename" || done.verified_by.starts_with("a hard link to") {
        return 0;
    }
    match &done.delta {
        Some(Delta::Sent { bytes, .. }) => *bytes,
        _ => done.bytes,
    }
}

/// The class of a copy's failure: where the connection failed, the class
/// of T-054 that the session's record says (`connect`, `relay`, `host-key`,
/// `auth`); else `copy` (a source, a destination, or a step that the server
/// refused, as no SFTP after the login), `verify` (the digests differ),
/// `session` (the session broke), `timeout`, `usage` or `config`.
pub(crate) fn class(failed: &Failed, facts: &Facts) -> &'static str {
    match failed.fault {
        Fault::Usage => "usage",
        Fault::Config => "config",
        Fault::TimedOut => "timeout",
        Fault::RelayUnreachable | Fault::Auth => match facts.failure {
            Some(class) => class,
            // Past the login, the server lacks what the copy needs.
            None if facts.method.is_some() => "copy",
            None if failed.fault == Fault::Auth => "auth",
            None => "connect",
        },
        Fault::SessionFault => match failed.cause {
            Cause::Digests => "verify",
            Cause::Broke | Cause::Spent => facts.failure.filter(|c| *c == "relay").unwrap_or("session"),
            Cause::Answer => "copy",
        },
        _ => "copy",
    }
}

/// The object of a run of `verb` (`cp`, `mv`, `scp`, `run` or `sftp`): the
/// keys that each of them gives, and the files when the run copies.
pub(crate) fn object(
    verb: &str,
    exit: i32,
    took: Duration,
    record: &Record,
    did: &Did,
) -> serde_json::Map<String, Value> {
    // A run that knew no class of its failure ended before its work: the
    // exit code tells why, as for `ssh`.
    let failure = did.failure.or_else(|| if exit == 0 { None } else { crate::ssh::result::refused(exit) });
    let mut object = crate::ssh::result::common(verb, exit, took, &record.facts, failure, did.error.as_deref());
    if verb != "sftp" {
        let (files, transferred) = did.copied.as_ref().map(Copied::json).unzip();
        object.insert("files".into(), files.into());
        object.insert("transferred".into(), transferred.into());
    }
    if verb == "mv" {
        object.insert("removed".into(), did.copied.as_ref().map(|c| c.removed.clone()).into());
    }
    object
}

/// The object of `cp`, `mv` or `scp`: theirs, and `bytes` null, as a copy
/// runs no command whose streams `bytes` counts in `ssh`'s.
pub(crate) fn copy_object(verb: &str, exit: i32, took: Duration, record: &Record, did: &Did) -> Value {
    let mut object = object(verb, exit, took, record, did);
    object.insert("bytes".into(), Value::Null);
    Value::Object(object)
}

#[cfg(test)]
#[path = "result_tests.rs"]
mod tests;
