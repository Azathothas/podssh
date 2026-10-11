//! `--result-file FILE` (T-054): at the end of each run of `podssh ssh`, one
//! JSON object in FILE, so that a script tells the remote command's status
//! from a failure of podssh, and reads the signal, the bytes and the relay,
//! with no parsing of stderr. The command's output never goes into it; its
//! stdout and stderr stay as they are.

use std::io::Write;
use std::time::Instant;

use serde_json::{json, Value};

/// The version of the object's form.
pub const SCHEMA: u32 = 1;

/// The object of a run that started at `started` and exits with `exit`.
pub fn object(exit: i32, started: Instant) -> Value {
    let record = podssh_ssh::outcome::record();
    let f = &record.facts;
    // With no session and no cause said, a refusal of the command line or
    // of the configuration ended the run, or podssh got no session.
    let failure = f.failure.or(match (f.end, exit) {
        (Some(_), _) | (None, 0) => None,
        (None, 64) => Some("usage"),
        (None, 78) => Some("config"),
        (None, 70) => Some("not-built"),
        (None, _) => Some("connect"),
    });
    let end = f.end.or(failure.map(|_| "failed"));
    // A control master carries the bytes of a run that goes through it.
    let bytes = (!f.shared).then(|| json!({ "stdin": record.stdin, "stdout": record.stdout, "stderr": record.stderr }));
    let relay = f.relay_host.as_ref().map(|host| {
        let (code, reason) = f.relay_close.clone().unwrap_or_default();
        json!({ "host": host, "close_code": code, "reason": (!reason.is_empty()).then_some(reason) })
    });
    json!({
        "schema": SCHEMA,
        "exit": exit,
        "status": f.status,
        "signal": f.signal.as_ref().map(|(name, core)| json!({ "name": name, "core_dumped": core })),
        "end": end,
        "failure": failure,
        "bytes": bytes,
        "duration_ms": started.elapsed().as_millis() as u64,
        "relay": relay,
    })
}

/// The verdict of the end-to-end channel to a node (T-088), which says more
/// than the session saw: a refused key is `auth`, a node out of reach
/// `relay`, and another fault `session`.
pub fn channel_failed(fault: &crate::exitmap::Fault) {
    use crate::exitmap::Fault;
    podssh_ssh::outcome::failure_is(match fault {
        Fault::Auth => "auth",
        Fault::RelayUnreachable => "relay",
        _ => "session",
    });
}

/// Write `object` to `path`, made readable by its owner alone; a failure is
/// a line on stderr, and the exit code stays the run's.
pub fn write(path: &str, object: &Value, err: &mut dyn Write) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(path).and_then(|mut file| {
        file.write_all(object.to_string().as_bytes())?;
        file.write_all(b"\n")
    });
    if let Err(e) = written {
        let _ = writeln!(err, "podssh ssh: --result-file {path}: {e}");
    }
}
