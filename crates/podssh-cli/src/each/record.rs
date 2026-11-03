//! The record of a run of `podssh each` (T-484, GitHub #94): one JSON
//! object with each host's status, failure and streams, for
//! `--result-file FILE` and, with `--json`, on stdout. Each host's facts
//! are its session's own (`podssh_ssh::outcome::scoped`), with the keys of
//! `ssh --result-file` in their meaning: a record of the process would hold
//! two hosts' facts at once.

use std::path::PathBuf;

use serde_json::{json, Value};

use super::fan::Ended;
use super::host::Ran;
use crate::mcp::text;
use crate::ssh::result;

/// The version of the object's form.
pub const SCHEMA: u32 = 1;

/// The record of one host: `label` as the list names it, its login
/// `destination`, how it `ended`, what its session did (none when it did
/// not start), and its files of `--output-dir`.
pub(crate) fn host(
    label: &str,
    destination: &str,
    ended: &Ended,
    ran: Option<&Ran>,
    files: Option<&[PathBuf; 3]>,
) -> Value {
    let facts = ran.map(|r| r.record.facts.clone()).unwrap_or_default();
    // A host with no session failed to connect, unless its session said
    // more; one with a status has the class that its session said, if any.
    let failure = match ended {
        Ended::Failed(_) => Some(facts.failure.unwrap_or("connect")),
        Ended::Status(_) => facts.failure,
        Ended::NotStarted => None,
    };
    let end = facts.end.or(failure.map(|_| "failed"));
    let error = match ended {
        Ended::Failed(why) => Some(why.as_str()),
        _ => None,
    };
    let files = files.map(|[out, err, status]| {
        json!({ "stdout": out.display().to_string(), "stderr": err.display().to_string(),
            "status": status.display().to_string() })
    });
    let mut record = json!({
        "host": label,
        "destination": destination,
        "exit": ended.code(),
        "status": facts.status,
        "signal": result::signal(&facts),
        "end": end,
        "failure": failure,
        "error": error,
        "duration_ms": ran.map(|r| r.took.as_millis() as u64),
        "bytes": ran.map(|r| result::bytes(&r.record)),
        "relay": result::relay(&facts),
        "files": files,
    });
    // With --json and no --output-dir, the streams, as `ssh_exec` gives
    // them: UTF-8 when they are, else base64, and whether more came.
    if let Some(kept) = ran.and_then(|r| r.kept.as_ref()) {
        let (stdout, stdout_encoding) = text(&kept.stdout);
        let (stderr, stderr_encoding) = text(&kept.stderr);
        let streams = json!({
            "stdout": stdout,
            "stdout_encoding": stdout_encoding,
            "stderr": stderr,
            "stderr_encoding": stderr_encoding,
            "truncated": kept.stdout.truncated || kept.stderr.truncated,
        });
        if let (Some(into), Some(streams)) = (record.as_object_mut(), streams.as_object()) {
            into.extend(streams.clone());
        }
    }
    record
}

/// The record of the run: its exit, each host's record in the order of the
/// list, and the counts of the summary.
pub(crate) fn object(exit: i32, hosts: Vec<Value>, ends: &[Ended]) -> Value {
    let failed = ends.iter().filter(|e| e.failed()).count();
    let not_started = ends.iter().filter(|e| **e == Ended::NotStarted).count();
    json!({
        "schema": SCHEMA,
        "podssh": env!("CARGO_PKG_VERSION"),
        "exit": exit,
        "hosts": hosts,
        "counts": {
            "hosts": ends.len(),
            "ok": ends.len() - failed - not_started,
            "failed": failed,
            "not_started": not_started,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use podssh_ssh::outcome::{Facts, Record};

    use super::*;
    use crate::each::out::Kept;
    use crate::mcp::Captured;

    fn ran(facts: Facts, kept: Option<Kept>) -> Ran {
        Ran { record: Record { stdin: 0, stdout: 4, stderr: 5, facts }, took: Duration::from_millis(12), kept }
    }

    #[test]
    fn a_host_with_a_status_has_its_session_s_facts() {
        let facts = Facts { status: Some(3), end: Some("status"), ..Facts::default() };
        let r = host("web1", "u@web1:22", &Ended::Status(3), Some(&ran(facts, None)), None);
        assert_eq!(
            (&r["exit"], &r["status"], &r["end"], &r["failure"]),
            (&json!(3), &json!(3), &json!("status"), &Value::Null)
        );
        assert_eq!((&r["error"], &r["duration_ms"], &r["files"]), (&Value::Null, &json!(12), &Value::Null));
        assert_eq!(r["bytes"], json!({ "stdin": 0, "stdout": 4, "stderr": 5 }));
        assert!(r.get("stdout").is_none(), "no streams without --json");
    }

    #[test]
    fn a_host_with_no_session_failed_with_its_words_and_class() {
        let refused = Facts { failure: Some("auth"), ..Facts::default() };
        let r = host("k", "k@h:22", &Ended::Failed("Permission denied".into()), Some(&ran(refused, None)), None);
        assert_eq!((&r["exit"], &r["end"], &r["failure"]), (&json!(255), &json!("failed"), &json!("auth")));
        assert_eq!(r["error"], json!("Permission denied"));
        // No class said: no connection.
        let r = host("c", "c@h:22", &Ended::Failed("refused".into()), Some(&ran(Facts::default(), None)), None);
        assert_eq!(r["failure"], json!("connect"));
        // Not started: no part of the exit, and nothing else.
        let r = host("n", "n@h:22", &Ended::NotStarted, None, None);
        assert_eq!(
            (&r["exit"], &r["end"], &r["bytes"], &r["duration_ms"]),
            (&Value::Null, &Value::Null, &Value::Null, &Value::Null)
        );
    }

    #[test]
    fn the_streams_are_text_or_base64_and_say_a_cut() {
        let kept = Kept {
            stdout: Captured { bytes: b"out\n".to_vec(), truncated: false },
            stderr: Captured { bytes: vec![0xff, 0x00], truncated: true },
        };
        let r = host("a", "a@h:22", &Ended::Status(0), Some(&ran(Facts::default(), Some(kept))), None);
        assert_eq!((&r["stdout"], &r["stdout_encoding"]), (&json!("out\n"), &json!("utf-8")));
        assert_eq!(
            (&r["stderr"], &r["stderr_encoding"], &r["truncated"]),
            (&json!("/wA="), &json!("base64"), &json!(true))
        );
        let mut more = Kept::default();
        more.take(&vec![b'x'; crate::each::out::KEPT + 3], false);
        assert_eq!((more.stdout.bytes.len(), more.stdout.truncated), (crate::each::out::KEPT, true));
    }

    #[test]
    fn the_run_counts_its_hosts() {
        let ends = [Ended::Status(0), Ended::Status(3), Ended::Failed("x".into()), Ended::NotStarted];
        let o = object(255, Vec::new(), &ends);
        assert_eq!((&o["schema"], &o["exit"]), (&json!(1), &json!(255)));
        assert_eq!(o["counts"], json!({ "hosts": 4, "ok": 1, "failed": 2, "not_started": 1 }));
        let files = crate::each::out::paths(std::path::Path::new("d"), "u@h:22");
        let r = host("u@h:22", "u@h:22", &Ended::Status(0), None, Some(&files));
        assert!(r["files"]["status"].as_str().is_some_and(|p| p.ends_with("u@h%3A22.status")), "{r}");
    }
}
