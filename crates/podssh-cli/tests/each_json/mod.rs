//! `podssh each --result-file` and `--json` (T-484, GitHub #94) against the
//! test's SSH server on the loopback: each host's exit, status, end, failure
//! and words in one object, in the order of the list; two hosts that fail at
//! once in two ways each name their own failure (the planted defect, each
//! host's facts read from the process's record, fails it); and with
//! `--json` each host's stdout and stderr byte for byte, bytes that are not
//! UTF-8 as base64, and no line with a label. The test's server runs one
//! command on each host, so the statuses differ by user: `cat` gives 0, and
//! 127 for a `bare-...` user, whose host has none.

use std::path::Path;

use serde_json::{json, Value};

use super::{direct, each, run, scratch, server};

/// The flags of a run on the loopback, and `extra`.
fn with(home: &Path, extra: &[&str]) -> Vec<String> {
    let mut flags = direct(home, true);
    flags.extend(extra.iter().map(|s| s.to_string()));
    flags
}

/// The records of the hosts in `r`.
fn hosts(r: &Value) -> &Vec<Value> {
    r["hosts"].as_array().unwrap_or_else(|| panic!("no hosts: {r}"))
}

#[test]
fn the_result_file_gives_each_host_its_status_and_failure_in_order() {
    let home = scratch("result");
    let (_runtime, port, closed) = server(&home);
    let file = home.join("result.json");
    let flags = with(&home, &["--result-file", &file.display().to_string()]);
    let labels = [format!("a@127.0.0.1:{port}"), format!("bare-b@127.0.0.1:{port}"), format!("c@127.0.0.1:{closed}")];
    let (code, out, err) = run(&home, &flags, &labels, "cat");
    assert_eq!(code, 255, "{err}");
    // The lines stay as they are: the summary is there, and stdout holds
    // only the hosts' lines, of which `cat` with no input wrote none.
    assert!(out.is_empty() && err.contains("podssh each: 3 hosts: 1 gave 0, 2 failed"), "{out}{err}");
    assert!(err.contains(&format!("{}: sh: cat: not found", labels[1])), "{err}");
    let text = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("no result file ({e}): {err}"));
    let r: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"));
    assert_eq!((&r["schema"], &r["exit"], &r["podssh"]), (&json!(1), &json!(255), &json!(env!("CARGO_PKG_VERSION"))));
    assert_eq!(r["counts"], json!({ "hosts": 3, "ok": 1, "failed": 2, "not_started": 0 }));
    let h = hosts(&r);
    let named: Vec<&str> = h.iter().filter_map(|h| h["host"].as_str()).collect();
    assert_eq!(named, labels.iter().map(String::as_str).collect::<Vec<_>>(), "in the order of the list");
    assert_eq!(h[0]["destination"], json!(format!("a@127.0.0.1:{port}")));
    let ends = |h: &Value| (h["exit"].clone(), h["status"].clone(), h["end"].clone(), h["failure"].clone());
    assert_eq!(ends(&h[0]), (json!(0), json!(0), json!("status"), Value::Null), "{text}");
    assert_eq!(ends(&h[1]), (json!(127), json!(127), json!("status"), Value::Null), "{text}");
    assert_eq!(ends(&h[2]), (json!(255), Value::Null, json!("failed"), json!("connect")), "{text}");
    assert!(h[2]["error"].as_str().is_some_and(|e| !e.is_empty()), "the closed port's words: {text}");
    assert_eq!((&h[0]["error"], &h[0]["relay"]), (&Value::Null, &Value::Null), "--direct has no relay");
    assert!(h[1]["bytes"]["stderr"].as_u64().is_some_and(|n| n > 0), "{text}");
    assert!(h.iter().all(|h| h["duration_ms"].is_u64() && h.get("stdout").is_none()), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
    }
}

/// A refused key and a closed port at once: each host's record has its
/// own class and words, not the other's (T-183's Done: a lost session's
/// words named another host's error, as the record was the process's).
#[test]
fn two_hosts_that_fail_at_once_each_name_their_own_failure() {
    let home = scratch("two-failures");
    let (_runtime, port, closed) = server(&home);
    let flags = with(&home, &["--json"]);
    let labels = [format!("key-x@127.0.0.1:{port}"), format!("c@127.0.0.1:{closed}")];
    for order in [[0, 1], [1, 0]] {
        let given = [labels[order[0]].clone(), labels[order[1]].clone()];
        let (code, out, err) = run(&home, &flags, &given, "true");
        assert_eq!(code, 255, "{err}");
        let r: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
        let of = |label: &str| hosts(&r).iter().find(|h| h["host"] == json!(label)).cloned().unwrap();
        let (key, port) = (of(&labels[0]), of(&labels[1]));
        assert_eq!((&key["end"], &key["failure"]), (&json!("failed"), &json!("auth")), "{out}");
        assert_eq!((&port["end"], &port["failure"]), (&json!("failed"), &json!("connect")), "{out}");
        let (key_said, port_said) = (key["error"].as_str().unwrap_or(""), port["error"].as_str().unwrap_or(""));
        assert!(!key_said.is_empty() && !port_said.is_empty() && key_said != port_said, "{out}");
        assert!(!key_said.contains(&closed.to_string()), "the refused key names the closed port: {out}");
    }
}

#[test]
fn json_holds_each_host_s_streams_byte_for_byte_and_no_line() {
    let home = scratch("json");
    let (_runtime, port, _) = server(&home);
    let flags = with(&home, &["--json"]);
    let labels = [format!("a@127.0.0.1:{port}"), format!("b@127.0.0.1:{port}")];
    // `exit 3` writes `out` on stdout and `err!` on stderr.
    let (code, out, err) = run(&home, &flags, &labels, "exit 3");
    assert_eq!(code, 3, "{err}");
    let r: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("stdout is the object alone ({e}): {out}"));
    for h in hosts(&r) {
        assert_eq!((&h["exit"], &h["status"]), (&json!(3), &json!(3)), "{out}");
        assert_eq!((&h["stdout"], &h["stdout_encoding"]), (&json!("out\n"), &json!("utf-8")), "{out}");
        assert_eq!((&h["stderr"], &h["truncated"]), (&json!("err!\n"), &json!(false)), "{out}");
        assert_eq!(h["bytes"], json!({ "stdin": 0, "stdout": 4, "stderr": 5 }), "{out}");
    }
    assert!(!err.lines().any(|l| labels.iter().any(|h| l == format!("{h}: err!"))), "a line with a label: {err}");
    // Bytes that are not UTF-8 come as base64, each byte kept.
    let (code, out, err) = run(&home, &flags, &labels[..1], "bytes ff00");
    assert_eq!(code, 0, "{err}");
    let r: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
    assert_eq!((&hosts(&r)[0]["stdout"], &hosts(&r)[0]["stdout_encoding"]), (&json!("/wA="), &json!("base64")));
    // With --output-dir the bytes go to the files, which the record names.
    let dir = home.join("out");
    let with_dir = with(&home, &["--json", "--output-dir", &dir.display().to_string()]);
    let (code, out, err) = run(&home, &with_dir, &labels, "exit 3");
    assert_eq!(code, 3, "{err}");
    let r: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
    let h = &hosts(&r)[0];
    assert!(h.get("stdout").is_none(), "{out}");
    let named = h["files"]["stdout"].as_str().unwrap_or_default();
    assert_eq!(std::fs::read(named).unwrap_or_default(), b"out\n", "{out}");
}

#[test]
fn json_and_the_result_file_refuse_what_they_cannot_hold() {
    let home = scratch("json-refused");
    for (args, says) in [
        (&["--interactive", "--json", "a"][..], "--json"),
        (&["--interactive", "--result-file", "r.json", "a"][..], "--result-file"),
        (&["--result-file", "-", "a", "--", "true"][..], "--result-file -"),
    ] {
        let (code, out, err) = each(&home, args, true);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains(says) && out.is_empty(), "{args:?}: {err}");
    }
    assert!(!home.join("r.json").exists(), "a refusal wrote a record");
}
