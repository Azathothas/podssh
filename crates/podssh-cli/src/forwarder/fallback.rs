//! The fallback to the forwarders that the binary names (T-370), by the
//! operator's ruling Q56: when each relay host failed, podssh tries them in
//! order, after the relay hosts and before the run ends, and says so on
//! stderr with each one's name. Only where the relay was podssh's own
//! choice: not for relay hosts that the user names (`--relay-host`,
//! `PODSSH_RELAY`, `RelayHost`), whose road stays theirs alone, nor with
//! `-4` or `-6`, nor when `PODSSH_FORWARDER_FALLBACK`, or
//! `ForwarderFallback` of the settings file, says no. A failure that a
//! forwarder would share (a bad setting, a target that cannot go) ends the
//! run as before. No relay token goes to a forwarder.

use std::io::Write;
use std::sync::Arc;

use podssh_relay::relay::RelayList;
use podssh_ssh::Log;
use podssh_ws::forwarder::builtin;
use podssh_ws::Trust;

use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;
use crate::settings::Defaults;
use crate::ssh::transport::{NotReached, Reached};

/// The variable that turns the fallback off.
pub const FALLBACK_ENV: &str = "PODSSH_FORWARDER_FALLBACK";

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

/// Why the fallback does not follow a failure of `relays`, or `None` when
/// it does. `code` is the relay's failure, as `proxy` exits with it: an
/// unavailable relay, or a refusal of it, a forwarder may not share.
pub fn not_after(relays: &RelayList, family: Option<u8>, code: i32) -> Option<&'static str> {
    if relays.explicit {
        Some("the relay hosts are the user's")
    } else if family.is_some() {
        Some("-4 and -6 ask the relay for a family")
    } else if !matches!(code, EX_UNAVAILABLE | EX_NOPERM) {
        Some("the failure would be a forwarder's too")
    } else if podssh_relay::open::offline() {
        Some("PODSSH_OFFLINE is set")
    } else if !on_from(env_value(), crate::settings::here()).unwrap_or(false) {
        Some("it is turned off")
    } else {
        None
    }
}

/// The line that says the fallback, before its first dial.
pub fn announce() -> String {
    format!(
        "each relay host failed: podssh tries the public forwarders of other products that it names, in order: {}; \
         they publish no limit and can stop at any time ({FALLBACK_ENV} set to no turns this off)",
        builtin::words()
    )
}

/// The stream to `host:port` through the forwarders that the binary names,
/// once each relay host failed with `failed`; else `failed`. Its lines are
/// said first, as the forwarders' lines follow them; the code stays the
/// relay's, so a run that none carries ends as it did.
pub async fn after_relay(
    failed: NotReached,
    relays: &RelayList,
    family: Option<u8>,
    trust: &Trust,
    host: &str,
    port: u16,
    log: &Arc<Log>,
) -> Result<Reached, NotReached> {
    if not_after(relays, family, failed.code).is_some() {
        return Err(failed);
    }
    for line in &failed.lines {
        log.error(line);
    }
    log.info(&announce());
    let code = failed.code;
    match super::reach::carry(&super::builtins(), trust, host, port, log, true).await {
        Ok(reached) => Ok(reached),
        Err(_) => Err(NotReached { lines: Vec::new(), code }),
    }
}

/// `podssh proxy`'s fallback: the pipe through the forwarders that the
/// binary names once each relay host failed with `code`; else `code`.
pub async fn after_relay_pipe(
    code: i32,
    relays: &RelayList,
    host: &str,
    port: u16,
    trust: &Trust,
    err: &mut dyn Write,
) -> i32 {
    if not_after(relays, None, code).is_some() {
        return code;
    }
    let _ = writeln!(err, "podssh: {}", announce());
    let opened = super::pipe::open(&super::builtins(), host, port, trust, &mut |line: &str| {
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
        assert!(not_after(&theirs, None, EX_UNAVAILABLE).unwrap().contains("the user's"));
        assert!(not_after(&ours, Some(6), EX_UNAVAILABLE).unwrap().contains("-4 and -6"));
        assert!(not_after(&ours, None, EX_CONFIG).unwrap().contains("a forwarder's too"));
        assert!(not_after(&ours, None, crate::exitmap::sysexits::EX_USAGE).is_some());
        assert!(announce().contains("mudlet, ssheasy, mudix"));
    }
}
