//! The stored pairs of the reverse road, as `podssh node` and `podssh relay`
//! use them: the pair under a label, or a refusal that names the remedy; the
//! exit code of each failure, by the table of `exitmap`; the trust store; and
//! an expiry in UTC. No message holds a token.

use std::path::Path;

use podssh_relay::pair::{self, Pair, PairContext, PairError};
use podssh_relay::relay::Relay;
use podssh_ws::client::ConnectError;
use podssh_ws::dial::{DialError, ProxyChoice};
use podssh_ws::Trust;

use crate::exitmap::Fault;
use crate::relay_settings::Refusal;

/// Bound on each request to the relay's control host.
pub(crate) const REQUEST_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Milliseconds since the Unix epoch, now.
pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// `2026-10-12T08:10:00Z`, for milliseconds since the epoch.
pub(crate) fn utc(ms: i64) -> String {
    crate::doctor::clock::format_utc(ms.div_euclid(1000))
}

/// A label that the store takes, or a usage error that says why.
pub(crate) fn check_label(label: &str) -> Result<(), Refusal> {
    pair::file_name(label).map(|_| ()).map_err(|e| Refusal::usage(e.to_string()))
}

/// The pair stored under `label`, if it has not expired.
pub(crate) fn stored(label: &str) -> Result<Pair, Refusal> {
    match pair::load(label) {
        Ok(Some(pair)) => usable(pair, label),
        Ok(None) => Err(Refusal::config(format!(
            "no pair is stored under {label:?}; make one with `podssh relay pair {label}`"
        ))),
        Err(e) => Err(refusal(&e)),
    }
}

/// A pair from a file of the store's form, as `--pair-file` gives it.
pub(crate) fn from_file(path: &str) -> Result<Pair, Refusal> {
    pair::read_file(Path::new(path)).map_err(|e| Refusal::config(format!("--pair-file {path}: {e}")))
}

/// `pair`, unless it has expired: then the remedy, with the code of an
/// expired pair (77).
pub(crate) fn usable(pair: Pair, label: &str) -> Result<Pair, Refusal> {
    if pair.expires_ms <= now_ms() {
        return Err(Refusal {
            message: format!(
                "the pair under {label:?} expired at {}; make a new one with `podssh relay pair {label}`",
                utc(pair.expires_ms)
            ),
            code: Fault::PairExpired.code(),
        });
    }
    Ok(pair)
}

/// The exit code and the message of a pairing call that failed.
pub(crate) fn refusal(e: &PairError) -> Refusal {
    let code = match e {
        PairError::BadLabel(_) => Fault::Usage.code(),
        PairError::Forbidden => Fault::Auth.code(),
        PairError::Store(_) => Fault::Config.code(),
        PairError::Connect(c) => connect_code(c),
        _ => Fault::RelayUnreachable.code(),
    };
    Refusal { message: e.to_string(), code }
}

/// A connection that failed, as `podssh proxy` reads it: a setting (78), a
/// refusal (77), else no relay (69).
fn connect_code(e: &ConnectError) -> i32 {
    match e {
        ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_)) => Fault::Config.code(),
        ConnectError::Refused { status: 401 | 403, .. }
        | ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => Fault::Auth.code(),
        _ => Fault::RelayUnreachable.code(),
    }
}

/// `--ca-file`, else `SSL_CERT_FILE`, else podssh's own roots, as for
/// `podssh proxy`.
pub(crate) fn trust(ca_file: Option<&str>) -> Trust {
    let file =
        ca_file.map(str::to_string).or_else(|| std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty()));
    match file {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    }
}

/// How a pairing call reaches `relay`.
pub(crate) fn context<'a>(relay: &'a Relay, trust: &'a Trust, proxy: &'a ProxyChoice) -> PairContext<'a> {
    PairContext { relay, trust, proxy, timeout: REQUEST_LIMIT }
}

/// A refusal before any request when `PODSSH_OFFLINE` is set.
pub(crate) fn online() -> Result<(), Refusal> {
    if podssh_relay::open::offline() {
        return Err(Refusal {
            message: "not attempted: PODSSH_OFFLINE is set".into(),
            code: Fault::RelayUnreachable.code(),
        });
    }
    Ok(())
}

/// The operator's part for `label`: from `--pair-file` (a pair, or its
/// operator's part), else from the pair stored under `label`. Refused when it
/// has expired.
pub(crate) fn operator_part(label: &str, pair_file: Option<&str>) -> Result<pair::OperatorPart, Refusal> {
    let part = match pair_file {
        Some(path) => pair::read_operator_file(Path::new(path))
            .map_err(|e| Refusal::config(format!("--pair-file {path}: {e}")))?,
        None => match pair::load(label) {
            Ok(Some(found)) => pair::OperatorPart::of(&found),
            Ok(None) => {
                return Err(Refusal::config(format!(
                    "no pair is stored under {label:?}; make one with `podssh relay pair {label}`, or give its \
                     operator's file with --pair-file FILE"
                )))
            }
            Err(e) => return Err(refusal(&e)),
        },
    };
    if part.expires_ms <= now_ms() {
        return Err(Refusal {
            message: format!(
                "the pair under {label:?} expired at {}; make a new one with `podssh relay pair {label}`",
                utc(part.expires_ms)
            ),
            code: Fault::PairExpired.code(),
        });
    }
    Ok(part)
}

/// How a session of the reverse road ended after `ready`, in words, the same
/// for `podssh operator` and `podssh ssh node://NAME`. With no Close (`1006`)
/// the link broke, and the relay drops links at random (T-255); a node that
/// lost its link connects again. In both cases a new session may work.
pub(crate) fn session_end(code: u16, reason: &str) -> String {
    match code {
        1006 => format!("the link to the relay ended with no Close ({reason}); a new session may work"),
        1011 if reason.trim().eq_ignore_ascii_case("node disconnected") => {
            "the node's link to the relay ended (relay close 1011: node disconnected); the node connects again, \
             so a new session may work"
                .to_string()
        }
        _ => format!("the relay ended the session (relay close {code}): {reason}"),
    }
}

/// A connection to the relay that failed for a pair: its code, and for a
/// refused token the remedy.
pub(crate) fn connect_refusal(e: &ConnectError, label: &str) -> Refusal {
    let message = match e {
        ConnectError::Refused { status: 403, .. } => format!(
            "the relay refused the pair (403): it was stopped, or has expired; make a new one with \
             `podssh relay pair {label}`"
        ),
        other => other.to_string(),
    };
    Refusal { message, code: connect_code(e) }
}

#[cfg(test)]
mod tests {
    use super::session_end;

    #[test]
    fn a_session_that_ends_with_no_close_is_the_link_and_may_work_again() {
        let text = session_end(1006, "the relay closed the connection without a WebSocket Close");
        assert!(text.starts_with("the link to the relay ended with no Close ("), "{text}");
        assert!(text.ends_with("; a new session may work"), "{text}");
        assert!(!text.contains("relay close 1006"), "no Close came, so none is named: {text}");
    }

    #[test]
    fn a_node_that_lost_its_link_is_named_and_may_work_again() {
        for reason in ["node disconnected", " Node Disconnected "] {
            let text = session_end(1011, reason);
            assert!(
                text.starts_with("the node's link to the relay ended (relay close 1011: node disconnected)"),
                "{text}"
            );
            assert!(text.ends_with("so a new session may work"), "{text}");
        }
    }

    #[test]
    fn each_other_end_keeps_the_relays_code_and_reason() {
        assert_eq!(session_end(1011, "write failed"), "the relay ended the session (relay close 1011): write failed");
        assert_eq!(session_end(1013, "slow"), "the relay ended the session (relay close 1013): slow");
    }
}
