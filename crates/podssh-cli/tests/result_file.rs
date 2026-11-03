//! `--result-file` of `cp`, `mv`, `scp`, `run` and `sftp` (T-486, GitHub
//! #97) against the test's SSH server, whose commands run in sh and whose
//! subsystem sftp is OpenSSH's `sftp-server` in the far home
//! (`job_harness`): each verb's object, with the keys of `ssh
//! --result-file` in their meaning, and one list of keys and their types
//! for the six verbs (the planted defect, the bytes of a copy under
//! `bytes`, fails it). With no `sftp-server` on this host, each test says
//! so and passes.
#![cfg(unix)]

mod cleanup;
mod job_harness;
mod ssh_harness;

use std::path::Path;
use std::time::{Duration, SystemTime};

use job_harness::{scratch, Far};
use serde_json::{json, Value};

/// Each key of the six verbs' objects, and its type when it is not null.
const KEYS: &[(&str, &str)] = &[
    ("schema", "number"),
    ("verb", "string"),
    ("exit", "number"),
    ("status", "number"),
    ("signal", "object"),
    ("end", "string"),
    ("failure", "string"),
    ("error", "string"),
    ("duration_ms", "number"),
    ("relay", "object"),
    ("bytes", "object"),
    ("files", "object"),
    ("transferred", "object"),
    ("removed", "array"),
    ("commands", "object"),
    ("failed_command", "string"),
];

/// The keys of each object among them: `bytes` is a command's streams in
/// each verb, as in `ssh`'s.
const INNER: &[(&str, &[&str])] = &[
    ("bytes", &["stdin", "stdout", "stderr"]),
    ("files", &["sent", "unchanged", "skipped", "deleted", "failed"]),
    ("transferred", &["up", "down"]),
    ("commands", &["run", "failed"]),
    ("signal", &["name", "core_dumped"]),
];

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Whether the object of `verb` holds the one list of keys and types.
fn holds_the_list(verb: &str, r: &Value) {
    let object = r.as_object().unwrap_or_else(|| panic!("{verb}: no object: {r}"));
    for (key, value) in object {
        let (_, want) = KEYS.iter().find(|(k, _)| k == key).unwrap_or_else(|| panic!("{verb}: {key} is in no list"));
        assert!(value.is_null() || kind(value) == *want, "{verb}: {key} is {}: {r}", kind(value));
        if let (Some(fields), Some((_, inner))) = (value.as_object(), INNER.iter().find(|(k, _)| k == key)) {
            let mut got: Vec<&str> = fields.keys().map(String::as_str).collect();
            let mut want = inner.to_vec();
            got.sort_unstable();
            want.sort_unstable();
            assert_eq!(got, want, "{verb}: the keys of {key}: {r}");
        }
    }
    for key in ["schema", "exit", "failure", "duration_ms", "relay"] {
        assert!(object.contains_key(key), "{verb}: no {key}: {r}");
    }
}

/// The far host, or `None` with no `sftp-server` here, said.
fn far(name: &str) -> Option<Far> {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return None;
    }
    Some(Far::new(name, std::env::var("PATH").unwrap_or_default(), None))
}

/// `podssh VERB --result-file FILE ARGS...` against `far`: the exit code,
/// stdout, stderr, and the object of FILE, whose mode is 0600.
fn ran(far: &Far, verb: &str, args: &[&str]) -> (i32, String, String, Value) {
    use std::os::unix::fs::PermissionsExt;
    let file = far.local.join(format!("{verb}-{}.json", rand_tag()));
    let path = file.display().to_string();
    let mut all = vec!["--result-file", path.as_str()];
    all.extend_from_slice(args);
    let (code, out, err) = far.podssh(verb, &all);
    let text = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{verb}: no result file ({e}): {err}"));
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{verb}: {mode:o}");
    let value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{verb}: {e}: {text}"));
    (code, out, err, value)
}

fn rand_tag() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// A project of three files under `dir`.
fn project(dir: &Path) {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("a.txt"), b"a\n").unwrap();
    std::fs::write(dir.join("b.txt"), b"bb\n").unwrap();
    std::fs::write(dir.join("src").join("c.txt"), b"ccc\n").unwrap();
}

#[test]
fn a_copy_gives_its_files_and_their_bytes_each_way() {
    let Some(far) = far("result-cp") else { return };
    let port = far.port.to_string();
    project(&far.local.join("proj"));
    let cp = |args: &[&str]| {
        let mut all = vec!["--timeout", "120s", "-P", port.as_str()];
        all.extend_from_slice(args);
        ran(&far, "cp", &all)
    };
    let (code, _, err, r) = cp(&["-r", "proj", "a@127.0.0.1:"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        (&r["verb"], &r["exit"], &r["failure"], &r["bytes"]),
        (&json!("cp"), &json!(0), &Value::Null, &Value::Null)
    );
    assert_eq!((&r["files"]["sent"], &r["transferred"]), (&json!(3), &json!({ "up": 9, "down": 0 })), "{r}");
    assert!(r.get("removed").is_none(), "{r}");
    // One file changed, newer than its copy: -u sends it alone, and leaves
    // the two others, which the record counts as skipped.
    let changed = far.local.join("proj").join("b.txt");
    std::fs::write(&changed, b"bb, and more\n").unwrap();
    let later = SystemTime::now() + Duration::from_secs(120);
    std::fs::OpenOptions::new().write(true).open(&changed).unwrap().set_modified(later).unwrap();
    let (code, _, err, r) = cp(&["-r", "-u", "proj", "a@127.0.0.1:"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!((&r["files"]["sent"], &r["files"]["skipped"]), (&json!(1), &json!(2)), "{r}");
    assert_eq!(r["transferred"], json!({ "up": 13, "down": 0 }), "{r}");
    // Down, the bytes come the other way.
    let (code, _, err, r) = cp(&["a@127.0.0.1:proj/a.txt", "back.txt"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(r["transferred"], json!({ "up": 0, "down": 2 }), "{r}");
    // A source that is not there: its class and its words.
    let (code, _, err, r) = cp(&["a@127.0.0.1:nosuch", "x.txt"]);
    assert_ne!(code, 0, "{err}");
    assert_eq!((&r["failure"], &r["files"]["failed"]), (&json!("copy"), &json!(1)), "{r}");
    assert!(r["error"].as_str().is_some_and(|e| e.contains("nosuch")), "{r}");
    // mv names the sources that it removed; scp is cp's object.
    std::fs::write(far.local.join("moveme"), b"move\n").unwrap();
    let (code, _, err, r) = ran(&far, "mv", &["--timeout", "120s", "-P", port.as_str(), "moveme", "a@127.0.0.1:moved"]);
    assert_eq!(code, 0, "{err}");
    let removed = r["removed"].as_array().cloned().unwrap_or_default();
    assert!(removed.len() == 1 && removed[0].as_str().is_some_and(|s| s.ends_with("moveme")), "{r}");
    let (code, _, err, r) = ran(&far, "scp", &["-P", port.as_str(), "back.txt", "a@127.0.0.1:scp.txt"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!((&r["verb"], &r["files"]["sent"], &r["transferred"]["up"]), (&json!("scp"), &json!(1), &json!(2)));
}

#[test]
fn run_gives_its_command_s_end_beside_its_copy() {
    let Some(far) = far("result-run") else { return };
    let port = far.port.to_string();
    let proj = far.local.join("proj");
    project(&proj);
    let from = proj.display().to_string();
    let (code, out, err, r) =
        ran(&far, "run", &["--from", from.as_str(), "-p", port.as_str(), "a@127.0.0.1", "--", "echo ran; exit 3"]);
    assert_eq!((code, out.as_str()), (3, "ran\n"), "{err}");
    let ends = (&r["verb"], &r["exit"], &r["status"], &r["end"], &r["failure"]);
    assert_eq!(ends, (&json!("run"), &json!(3), &json!(3), &json!("status"), &Value::Null), "{r}");
    assert_eq!((&r["files"]["sent"], &r["transferred"]["up"]), (&json!(3), &json!(9)), "{r}");
    assert_eq!(r["bytes"]["stdout"], json!(4), "the command's stdout: {r}");
    // As it was: no file goes again, and the record counts them unchanged.
    let (code, _, err, r) =
        ran(&far, "run", &["--from", from.as_str(), "-p", port.as_str(), "a@127.0.0.1", "--", "exit 0"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!((&r["files"]["sent"], &r["files"]["unchanged"]), (&json!(0), &json!(3)), "{r}");
}

#[test]
fn sftp_names_the_command_that_ended_the_batch() {
    let Some(far) = far("result-sftp") else { return };
    let port = far.port.to_string();
    let batch = far.local.join("batch");
    std::fs::write(&batch, "pwd\n-get gone-too\nget nosuch\npwd\n").unwrap();
    let batch = batch.display().to_string();
    let (code, _, err, r) = ran(&far, "sftp", &["-P", port.as_str(), "-b", batch.as_str(), "a@127.0.0.1"]);
    assert_ne!(code, 0, "{err}");
    assert_eq!((&r["verb"], &r["exit"]), (&json!("sftp"), &json!(code)), "{r}");
    assert_eq!(r["commands"], json!({ "run": 3, "failed": 2 }), "the last pwd did not run: {r}");
    assert_eq!((&r["failed_command"], &r["failure"]), (&json!("get nosuch"), &json!("copy")), "{r}");
    assert!(r.get("files").is_none() && r["bytes"].is_null(), "{r}");
}

/// The six verbs, each against the same far host: one list of keys, each
/// key of one type, and `bytes` the streams of a command wherever it is
/// an object.
#[test]
fn the_six_verbs_hold_one_list_of_keys_and_types() {
    let Some(far) = far("result-keys") else { return };
    let port = far.port.to_string();
    project(&far.local.join("proj"));
    let from = far.local.join("proj").display().to_string();
    std::fs::write(far.local.join("batch"), "pwd\n").unwrap();
    std::fs::write(far.local.join("m.txt"), b"m\n").unwrap();
    let runs: [(&str, Vec<&str>); 6] = [
        ("ssh", vec!["-p", port.as_str(), "a@127.0.0.1", "echo out; exit 3"]),
        ("cp", vec!["--timeout", "120s", "-P", port.as_str(), "proj/a.txt", "a@127.0.0.1:k.txt"]),
        ("mv", vec!["--timeout", "120s", "-P", port.as_str(), "m.txt", "a@127.0.0.1:m.txt"]),
        ("scp", vec!["-P", port.as_str(), "proj/b.txt", "a@127.0.0.1:s.txt"]),
        ("run", vec!["--from", from.as_str(), "-p", port.as_str(), "a@127.0.0.1", "--", "exit 0"]),
        ("sftp", vec!["-P", port.as_str(), "-b", "batch", "a@127.0.0.1"]),
    ];
    for (verb, args) in &runs {
        let (_, _, err, r) = ran(&far, verb, args);
        holds_the_list(verb, &r);
        assert!(r["failure"].is_null(), "{verb}: {err} {r}");
    }
}

/// `-` is refused before anything connects, as stdout is the run's; `cp`
/// and `mv` with a `--timeout`, which they need with no terminal.
#[test]
fn dash_is_refused_by_each_verb() {
    let home = scratch("result-dash");
    let copy = ["--timeout", "10s", "--result-file", "-", "a@127.0.0.1:x", "y"];
    let runs: [(&str, &[&str]); 5] = [
        ("cp", &copy),
        ("mv", &copy),
        ("scp", &copy),
        ("run", &["--result-file", "-", "a@127.0.0.1", "--", "true"]),
        ("sftp", &["--result-file", "-", "a@127.0.0.1"]),
    ];
    for (verb, args) in runs {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_podssh"))
            .arg(verb)
            .args(args)
            .current_dir(&home)
            .env("PODSSH_SSH_CONFIG", "none")
            .env("PODSSH_SETTINGS", "none")
            .env("PODSSH_OFFLINE", "1")
            .env("HOME", &home)
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{verb}: {err}");
        assert!(err.contains("--result-file -"), "{verb}: {err}");
    }
}
