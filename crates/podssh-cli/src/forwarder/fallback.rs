//! The fallback to the forwarders that the binary names (T-370), by the
//! operator's ruling Q56: when each relay host failed, podssh tries them in
//! order, after the relay hosts and before the run ends, and says so on
//! stderr with each one's name; the Wisp demo server last, never first, by
//! the ruling Q65 (T-438). Only where the relay was podssh's own
//! choice: not for relay hosts that the user names (`--relay-host`,
//! `PODSSH_RELAY`, `RelayHost`), whose road stays theirs alone, nor with
//! `-4` or `-6`, nor when `PODSSH_FORWARDER_FALLBACK`, or
//! `ForwarderFallback` of the settings file, says no. A failure that a
//! forwarder would share (a bad setting, a target that cannot go) ends the
//! run as before, and so does a relay host's answer about the target (its
//! 502, or its refusal of the target by policy), which no forwarder mends:
//! the fallback follows only a failure where no relay host answered about
//! the target (Q69, T-509). Each forwarder has [`EACH_WAIT`]. No relay
//! token goes to a forwarder.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::open::{Failure, OpenError};
use podssh_relay::relay::RelayList;
use podssh_ssh::Log;
use podssh_ws::forwarder::{builtin, Carried, Dial, ForwarderError, Template};
use podssh_ws::{ConnectError, Trust};

use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;
use crate::settings::Defaults;
use crate::ssh::transport::{NotReached, Reached};

/// The variable that turns the fallback off.
pub const FALLBACK_ENV: &str = "PODSSH_FORWARDER_FALLBACK";

/// The bound of each forwarder's attempt in the fallback, its dial and its
/// first word together, so that a run with no road ends within the time its
/// line names.
pub const EACH_WAIT: Duration = Duration::from_secs(10);

/// The variable of the process.
pub fn env_value() -> Option<String> {
    std::env::var(FALLBACK_ENV).ok()
}

/// yes or no, as the variable and the settings file write it.
pub fn word(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "yes" | "on" | "true" | "1" => Some(true),
        "no" | "off" | "false" | "0" => Some(false),
        _ => None,
    }
}

/// Whether the fallback is on: the variable, else the settings file, else
/// yes. Another word is a configuration error (78).
pub fn on_from(env: Option<String>, file: &Defaults) -> Result<bool, Refusal> {
    if let Some(value) = env.filter(|v| !v.trim().is_empty()) {
        return word(&value).ok_or_else(|| Refusal::config(format!("{FALLBACK_ENV}={value}: yes or no")));
    }
    match &file.forwarder_fallback {
        Some(v) => {
            word(&v.text).ok_or_else(|| Refusal::config(format!("{}: ForwarderFallback {:?}: yes or no", v.at, v.text)))
        }
        None => Ok(true),
    }
}

/// Whether a relay host of `failure` answered about the target: its 502
/// (it could not reach the target, or resolve its name), or its refusal of
/// the target by its policy (a blocked range, a port not allowed). Each
/// forwarder would get the target for nothing, as none reaches it better.
/// A refused token, a 5xx of the relay's own, a dial, TLS, a time-out and
/// an upgrade say nothing of the target.
pub fn answered(failure: &Failure) -> bool {
    failure.attempts.iter().any(|(_, e)| about_the_target(e))
}

fn about_the_target(e: &OpenError) -> bool {
    match e {
        // The relay dials the target before its upgrade: its 502 is the
        // target's, as the record of failures takes it.
        OpenError::Connect { error: ConnectError::Refused { status: 502, .. }, .. } => true,
        OpenError::Connect { error: ConnectError::Refused { status: 400 | 403, body }, .. } => {
            podssh_relay::open::is_policy_refusal(body)
        }
        _ => false,
    }
}

/// Why the fallback does not follow a failure of `relays`, or `None` when
/// it does. `code` is the relay's failure, as `proxy` exits with it: an
/// unavailable relay, or a refusal of it, a forwarder may not share;
/// `answered`, whether a relay host answered about the target.
pub fn not_after(relays: &RelayList, family: Option<u8>, code: i32, answered: bool) -> Option<&'static str> {
    if relays.explicit {
        Some("the relay hosts are the user's")
    } else if family.is_some() {
        Some("-4 and -6 ask the relay for a family")
    } else if !matches!(code, EX_UNAVAILABLE | EX_NOPERM) {
        Some("the failure would be a forwarder's too")
    } else if answered {
        Some("a relay host answered about the target, which no forwarder reaches better")
    } else if podssh_relay::open::offline() {
        Some("PODSSH_OFFLINE is set")
    } else if !on_from(env_value(), crate::settings::here()).unwrap_or(false) {
        Some("it is turned off")
    } else {
        None
    }
}

/// The line that says the fallback, before its first dial: what goes to
/// whom, and the bound of the wait.
pub fn announce(target: &str) -> String {
    format!(
        "each relay host failed: podssh sends {target} to the public forwarders of other products, in order: {}, \
         {} s at most each; {FALLBACK_ENV}=no turns this off",
        builtin::words(),
        EACH_WAIT.as_secs()
    )
}

/// One forwarder's session in the fallback, its dial and its first word
/// within [`EACH_WAIT`].
pub async fn bounded(template: &Template, host: &str, port: u16, dial: &Dial<'_>) -> Result<Carried, ForwarderError> {
    match tokio::time::timeout(EACH_WAIT, podssh_ws::forwarder::open(template, host, port, dial)).await {
        Ok(opened) => opened,
        Err(_) => Err(ForwarderError::Answer(format!("no session within {} s", EACH_WAIT.as_secs()))),
    }
}

/// The one line of a fallback that no forwarder carried: each forwarder's
/// reason, in order.
pub fn none_carried(target: &str, what: &str, failures: &[String]) -> String {
    format!("no forwarder carried the {what} to {target}: {}", failures.join("; "))
}

/// The stream to `host:port` through the forwarders that the binary names,
/// once each relay host failed with `failed`, none of them with a word
/// about the target (`answered`, [`answered`]); else `failed`. Its lines
/// are said first, as the forwarders' lines follow them; the code stays the
/// relay's, so a run that none carries ends as it did.
pub async fn after_relay(
    failed: NotReached,
    answered: bool,
    relays: &RelayList,
    family: Option<u8>,
    trust: &Trust,
    (host, port): (&str, u16),
    log: &Arc<Log>,
) -> Result<Reached, NotReached> {
    if let Some(why) = not_after(relays, family, failed.code, answered) {
        log.verbose(&format!("the public forwarders are not tried: {why}"));
        return Err(failed);
    }
    for line in &failed.lines {
        log.error(line);
    }
    log.info(&announce(&podssh_ws::dial::authority(host, port)));
    let code = failed.code;
    match super::reach::carry(&super::builtins(), trust, host, port, log, true).await {
        Ok(reached) => Ok(reached),
        Err(_) => Err(NotReached { lines: Vec::new(), code }),
    }
}

/// `podssh proxy`'s fallback: the pipe through the forwarders that the
/// binary names once each relay host failed with `code`, none of them with
/// a word about the target (`answered`); else `code`.
pub async fn after_relay_pipe(
    code: i32,
    answered: bool,
    relays: &RelayList,
    (host, port): (&str, u16),
    trust: &Trust,
    err: &mut dyn Write,
) -> i32 {
    if not_after(relays, None, code, answered).is_some() {
        return code;
    }
    let _ = writeln!(err, "podssh: {}", announce(&podssh_ws::dial::authority(host, port)));
    let opened = super::pipe::open(&super::builtins(), host, port, trust, true, &mut |line: &str| {
        let _ = writeln!(err, "podssh: {line}");
    })
    .await;
    match opened {
        Ok((end, name)) => {
            let target = podssh_ws::dial::authority(host, port);
            let _ = writeln!(err, "podssh: the forwarder {name} carries the pipe to {target}, in place of the relay");
            super::pipe::carry(end, err).await
        }
        Err(_) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exitmap::sysexits::EX_CONFIG;
    use crate::settings::Value;

    #[test]
    fn the_fallback_is_on_unless_the_variable_or_the_file_says_no() {
        let none = Defaults::default();
        assert_eq!(on_from(None, &none), Ok(true));
        assert_eq!(on_from(Some("  ".into()), &none), Ok(true), "an empty variable is no variable");
        assert_eq!(on_from(Some("No".into()), &none), Ok(false));
        let off = Defaults { forwarder_fallback: Some(Value { text: "no".into(), at: "f:2".into() }), ..none.clone() };
        assert_eq!(on_from(None, &off), Ok(false));
        assert_eq!(on_from(Some("yes".into()), &off), Ok(true), "the variable beats the file");
        let bad = on_from(Some("maybe".into()), &none).unwrap_err();
        assert!(bad.code == EX_CONFIG && bad.message == "PODSSH_FORWARDER_FALLBACK=maybe: yes or no", "{bad}");
        let file = Defaults { forwarder_fallback: Some(Value { text: "sure".into(), at: "f:2".into() }), ..none };
        assert!(on_from(None, &file).unwrap_err().message.starts_with("f:2: ForwarderFallback "));
    }

    /// The fallback follows a relay of podssh's own choice that failed as a
    /// forwarder may not, and nothing else.
    #[test]
    fn the_fallback_follows_only_the_relay_of_podssh_s_choice() {
        let ours = podssh_relay::relay::select_relays(None, None, &[]).unwrap();
        let theirs = podssh_relay::relay::select_relays(Some("r.example"), None, &[]).unwrap();
        assert!(not_after(&theirs, None, EX_UNAVAILABLE, false).unwrap().contains("the user's"));
        assert!(not_after(&ours, Some(6), EX_UNAVAILABLE, false).unwrap().contains("-4 and -6"));
        assert!(not_after(&ours, None, EX_CONFIG, false).unwrap().contains("a forwarder's too"));
        assert!(not_after(&ours, None, crate::exitmap::sysexits::EX_USAGE, false).is_some());
        assert!(not_after(&ours, None, EX_UNAVAILABLE, true).unwrap().contains("answered about the target"));
        assert!(not_after(&ours, None, EX_NOPERM, true).unwrap().contains("answered about the target"));
        let line = announce("192.0.2.1:22");
        let said = "each relay host failed: podssh sends 192.0.2.1:22 to the public forwarders of other products";
        assert!(line.starts_with(said), "{line}");
        assert!(line.contains("in order: mudlet, ssheasy, mudix, wisp, 10 s at most each;"), "{line}");
        assert!(line.ends_with("PODSSH_FORWARDER_FALLBACK=no turns this off"), "{line}");
    }

    fn failure(attempts: Vec<OpenError>) -> Failure {
        Failure { attempts: attempts.into_iter().enumerate().map(|(i, e)| (format!("r{i}.example"), e)).collect() }
    }

    fn refused(status: u16, body: &str) -> OpenError {
        let error = ConnectError::Refused { status, body: body.into() };
        OpenError::Connect { error, origin: podssh_relay::token::Origin::Minted }
    }

    /// Q69 (T-509): the relay's 502 about the target and its refusal of the
    /// target by policy end the run, on any host of the round; a refused
    /// token, the relay's own 5xx, a time-out and a dial do not.
    #[test]
    fn only_a_failure_where_no_relay_host_answered_about_the_target_is_followed() {
        for answer in [
            refused(502, "relay: cannot reach 192.0.2.1:22: connect timed out"),
            refused(502, "relay: nope.invalid does not resolve"),
            refused(400, "blocked address range"),
            refused(403, "forward: github.com:25 not in the ALLOW list"),
        ] {
            assert!(answered(&failure(vec![answer])), "an answer about the target");
        }
        // One host that answered about the target is enough, first or last.
        assert!(answered(&failure(vec![refused(502, "relay: cannot reach x:22"), OpenError::Deadline])));
        assert!(answered(&failure(vec![OpenError::Deadline, refused(400, "blocked address range")])));
        for silent in [
            refused(403, "invalid token"),
            refused(401, ""),
            refused(503, "paused"),
            refused(530, "error code: 1034"),
            refused(429, "slow down"),
            OpenError::Deadline,
            OpenError::Connect {
                error: ConnectError::Tls("UnknownIssuer".into()),
                origin: podssh_relay::token::Origin::Cache,
            },
            OpenError::Token(podssh_relay::token::TokenError::RateLimited { retry_after: None }),
        ] {
            assert!(!answered(&failure(vec![silent])), "no word about the target");
        }
    }
}
