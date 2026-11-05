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

/// The operator's part of the pair stored under `label`, unless it has
/// expired, or the part that a pairing by code kept under it (T-086).
pub(crate) fn stored_part(label: &str) -> Result<pair::OperatorPart, Refusal> {
    match pair::load(label) {
        Ok(Some(found)) => usable(found, label).map(|kept| pair::OperatorPart::of(&kept)),
        Ok(None) => operator_part(label, None),
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
/// refusal (77), else no relay (69). A relay that reads another dialect of
/// the reverse road (426, T-643) is 78, as for a node: a retry repeats it.
fn connect_code(e: &ConnectError) -> i32 {
    match e {
        ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_)) => Fault::Config.code(),
        ConnectError::Refused { status: 426, .. } => Fault::Config.code(),
        ConnectError::Refused { status: 401 | 403, .. }
        | ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => Fault::Auth.code(),
        _ => Fault::RelayUnreachable.code(),
    }
}

/// `--ca-file`, else `SSL_CERT_FILE`, else podssh's own roots, as for
/// `podssh proxy`.
pub(crate) fn trust(ca_file: Option<&str>) -> Trust {
    let file = crate::settings::ca_file(ca_file);
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
/// operator's part), else from the pair stored under `label`, else from the
/// operator's part that a pairing by code kept under it (T-086). Refused
/// when it has expired; past the end that it names, its relay is asked
/// first, as the pair's owner may have renewed it there (T-592).
pub(crate) fn operator_part(label: &str, pair_file: Option<&str>) -> Result<pair::OperatorPart, Refusal> {
    let part = match pair_file {
        Some(path) => pair::read_operator_file(Path::new(path))
            .map_err(|e| Refusal::config(format!("--pair-file {path}: {e}")))?,
        None => match pair::load(label) {
            Ok(Some(found)) => pair::OperatorPart::of(&found),
            Ok(None) => match pair::part::load(label) {
                Ok(Some(part)) => part,
                Ok(None) => {
                    return Err(Refusal::config(format!(
                        "no pair is stored under {label:?}; make one with `podssh relay pair {label}`, take its \
                         part with `podssh relay join {label}` and the code that its node's host shows, or give \
                         its operator's file with --pair-file FILE"
                    )))
                }
                Err(e) => return Err(refusal(&e)),
            },
            Err(e) => return Err(refusal(&e)),
        },
    };
    if part.expires_ms <= now_ms() {
        return renewed(part, label);
    }
    Ok(part)
}

/// A part past the end that its file names: podssh's relay role may have
/// renewed the pair, whose tokens stay (T-592), so its relay's status is
/// asked once, and the later end that it names is taken. Offline, or where
/// the relay refuses the token or names no later end (a relay of the
/// contract names none), the refusal of an expired pair (77), as before.
fn renewed(mut part: pair::OperatorPart, label: &str) -> Result<pair::OperatorPart, Refusal> {
    let named = utc(part.expires_ms);
    let expired = |also: String| Refusal {
        message: format!(
            "the pair under {label:?} expired at {named}{also}; make a new one with `podssh relay pair {label}`"
        ),
        code: Fault::PairExpired.code(),
    };
    if podssh_relay::open::offline() {
        return Err(expired(String::new()));
    }
    match ended_at(&part) {
        Ok(Some(expires)) if expires > now_ms() => {
            part.expires_ms = expires;
            Ok(part)
        }
        Ok(_) | Err(PairError::Forbidden) => Err(expired(String::new())),
        Err(e) => Err(expired(format!(", by its file, and its relay could not say whether it was renewed: {e}"))),
    }
}

/// The end that the relay names in its status of `part`, asked in a thread
/// of its own with the trust of `SSL_CERT_FILE` or the settings, as a caller
/// may run inside a runtime.
fn ended_at(part: &pair::OperatorPart) -> Result<Option<i64>, PairError> {
    std::thread::scope(|scope| {
        let asking = scope.spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| PairError::Store(format!("could not start the async runtime: {e}")))?;
            let (trust, proxy) = (trust(None), ProxyChoice::FromEnvironment);
            let ctx = context(&part.relay, &trust, &proxy);
            runtime.block_on(pair::renew::status(&ctx, part)).map(|status| status.expires)
        });
        asking.join().unwrap_or_else(|_| Err(PairError::Store("the status's thread ended in a panic".into())))
    })
}

/// How a session of the reverse road ended after `ready`, in words, the same
/// for `podssh operator` and `podssh ssh node://NAME`. With no Close (`1006`)
/// the link broke, and the relay drops links at random (T-255); a node that
/// lost its link connects again; `1012` is a relay that restarts, as podssh's
/// relay role closes each socket before a planned stop, and its node comes
/// back once the relay does. In each case a new session may work.
pub(crate) fn session_end(code: u16, reason: &str) -> String {
    match code {
        1006 => format!("the link to the relay ended with no Close ({reason}); a new session may work"),
        1011 if reason.trim().eq_ignore_ascii_case("node disconnected") => {
            "the node's link to the relay ended (relay close 1011: node disconnected); the node connects again, \
             so a new session may work"
                .to_string()
        }
        1012 => format!(
            "the relay is restarting (relay close 1012: {reason}); the node connects again once it is back, so a \
             new session may work"
        ),
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
    fn a_relay_that_restarts_is_named_and_may_work_again() {
        let text = session_end(1012, "relay restarting");
        assert!(text.starts_with("the relay is restarting (relay close 1012: relay restarting)"), "{text}");
        assert!(text.ends_with("so a new session may work"), "{text}");
    }

    #[test]
    fn each_other_end_keeps_the_relays_code_and_reason() {
        assert_eq!(session_end(1011, "write failed"), "the relay ended the session (relay close 1011): write failed");
        assert_eq!(session_end(1013, "slow"), "the relay ended the session (relay close 1013): slow");
    }

    /// T-643: an operator whose dialect the relay does not read exits 78,
    /// as a node does, with the relay's sentence.
    #[test]
    fn a_dialect_that_the_relay_does_not_read_is_78_with_its_words() {
        let words = "reverse: the operator speaks the reverse road's dialect 2, and the relay reads dialect 1 alone: \
                     update the relay";
        let refused = podssh_ws::ConnectError::Refused { status: 426, body: words.into() };
        let refusal = super::connect_refusal(&refused, "lab");
        assert_eq!(refusal.code, 78);
        assert!(refusal.message.ends_with("update the relay"), "{}", refusal.message);
    }
}
