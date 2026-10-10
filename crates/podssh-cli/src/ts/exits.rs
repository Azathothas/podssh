//! The exit of `podssh ts` for each failure of the node, and its message on stderr.

use std::io::Write;

use podssh_ts::classify::{classify_1008, Fault as Close};
use podssh_ts::node::NodeError;

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::exitmap::Fault;

/// What a key that the relay refuses needs.
const ALLOWLIST_HINT: &str =
    "Add this node's key to the relay's allowlist, or pass --ts-wait-allowlist DURATION\nto wait for its admission, with the same --ts-state file.";

/// Map a node failure to its exit, and say it. A close 1008 "not authorized" of the relay, read
/// from the DERP link's state (T-105) or from the text of a call of the fork, is a refused key: 77,
/// with what it needs; another closed session is 70.
pub fn node_error_exit(e: &NodeError, err: &mut dyn Write) -> i32 {
    match e {
        NodeError::Config(c) => {
            let _ = writeln!(err, "podssh ts: bad configuration: {c}");
            EXIT_USAGE
        }
        NodeError::KeyExpired | NodeError::KeyNotUtf8 => {
            let _ = writeln!(err, "podssh ts: the auth key is unusable: {e:?}");
            Fault::Auth.code()
        }
        NodeError::NetmapPending => no_map(err),
        NodeError::NotYet(what) => {
            let _ = writeln!(err, "podssh ts: not yet: {what}");
            EXIT_NOT_IMPLEMENTED
        }
        NodeError::DerpRefused { reason } => closed("the relay closed the DERP link", reason, err),
        NodeError::DerpPending { last, refused: true } => {
            let _ = writeln!(
                err,
                "podssh ts: the relay refused this node's key until the end of the wait ({}).\n{ALLOWLIST_HINT}",
                last.as_deref().map(safe).unwrap_or_default()
            );
            Fault::Auth.code()
        }
        NodeError::DerpPending { last, refused: false } => {
            let why = last.as_deref().map(safe).unwrap_or_else(|| "no attempt ended".to_string());
            let _ = writeln!(err, "podssh ts: the relay's DERP link did not come up within the wait ({why}).");
            Fault::Capability.code()
        }
        NodeError::Fork(text) => closed("the tailnet engine failed", text, err),
    }
}

/// A close, or a failure whose text may hold one: 77 for "not authorized", else 70.
fn closed(what: &str, reason: &str, err: &mut dyn Write) -> i32 {
    let _ = writeln!(err, "podssh ts: {what}: {}", safe(reason));
    match classify_1008(Some(reason)) {
        Close::NotAuthorized => {
            let _ = writeln!(err, "The relay refused this node's key (1008 \"not authorized\").\n{ALLOWLIST_HINT}");
            Fault::Auth.code()
        }
        Close::Session => EXIT_NOT_IMPLEMENTED,
    }
}

/// A relay's words, made safe for a terminal.
fn safe(text: &str) -> String {
    podssh_ws::text::one_line(text)
}

/// No network map within the wait: 78. A key that the relay refuses is said apart now (T-105), so
/// this is the control server's silence.
pub fn no_map(err: &mut dyn Write) -> i32 {
    let _ = writeln!(
        err,
        "podssh ts: no network map came from the control server within the wait.\nPass --ts-wait-allowlist DURATION to wait longer, with the same --ts-state file\nso that the node keeps its key."
    );
    Fault::Capability.code()
}
