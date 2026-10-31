//! The roads of `http-listen:` (T-367), each opened with a request's target:
//! the end, or why not, as the status that the client hears. A refusal of a
//! policy is 403 with its words: the relay's (`not in the ALLOW list`), an
//! upstream proxy's, or an SSH server's (administratively prohibited); a
//! dial past its limit is 504; another failure 502, with its reason. The
//! exit code beside it is the one that the road gives in each command.

use podssh_relay::open::OpenError;
use podssh_ws::{ConnectError, DialError};

use super::address::Address;
use super::pump::End;
use super::remote::Settings;
use crate::exitmap::sysexits::EX_UNAVAILABLE;

/// Why a road did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreached {
    /// The exit code of the road, as the other commands give it.
    pub code: i32,
    /// The status that the client hears.
    pub status: u16,
    /// Why, in words for the client's answer.
    pub reason: String,
}

/// Open `address`, a template filled in: the end, or why not, once `say` has
/// each line of the road.
pub async fn reach(address: &Address, settings: &Settings, say: &mut dyn FnMut(&str)) -> Result<End, Unreached> {
    match address {
        Address::Relay { host, port } => relay(host, *port, settings, say).await,
        Address::Tcp { host, port } => tcp(host, *port, say).await,
        Address::Ssh { hops, host, port } => ssh(hops, host, *port, settings, say).await,
        other => {
            let reason = format!("{other:?} is not a road of a template");
            Err(Unreached { code: crate::exit_codes::EXIT_SOFTWARE, status: 502, reason })
        }
    }
}

async fn relay(host: &str, port: u16, settings: &Settings, say: &mut dyn FnMut(&str)) -> Result<End, Unreached> {
    let usage = |reason: String| Unreached { code: crate::exit_codes::EXIT_USAGE, status: 400, reason };
    let path = podssh_relay::relay::forward_path(host, port).map_err(usage)?;
    let Some(relays) = settings.relays.as_ref() else {
        return Err(usage("no relay hosts were read for relay:%h:%p".into()));
    };
    let road = super::relay::Road { relays, trust: &settings.trust, failover: settings.failover };
    let opened = super::relay::session(&road, host, port, &path, say).await;
    opened.map_err(|failure| {
        let lines = failure.lines(&podssh_ws::dial::authority(host, port));
        for line in &lines {
            say(line);
        }
        let (status, reason) = relay_status(failure.last(), lines.first().map_or("", String::as_str));
        Unreached { code: crate::proxy::sysexit(failure.last()), status, reason }
    })
}

/// The status of the relay's failure: its policy's refusal is 403, with its
/// words; its 502, a target that it could not reach, is 502 with its words;
/// a limit that passed is 504.
fn relay_status(last: &OpenError, first: &str) -> (u16, String) {
    match last {
        OpenError::Connect { error: ConnectError::Refused { status: 400 | 403, body }, .. }
            if podssh_relay::open::is_policy_refusal(body) =>
        {
            (403, body.clone())
        }
        OpenError::Connect { error: ConnectError::Refused { status: 502, body }, .. } => (502, body.clone()),
        last if timed_out(last) => (504, first.to_string()),
        _ => (502, first.to_string()),
    }
}

/// Whether the relay's attempt ran past a limit: the host's, or a step's.
fn timed_out(last: &OpenError) -> bool {
    match last {
        OpenError::Deadline => true,
        OpenError::Connect { error, .. } => {
            matches!(error, ConnectError::Timeout { .. } | ConnectError::Dial(DialError::Timeout { .. }))
        }
        _ => false,
    }
}

async fn tcp(host: &str, port: u16, say: &mut dyn FnMut(&str)) -> Result<End, Unreached> {
    super::remote::tcp_dial(host, port).await.map_err(|e| {
        let reason = super::remote::tcp_failure(host, port, e.as_ref());
        say(&reason);
        let code = e.as_ref().map_or(EX_UNAVAILABLE, super::remote::dial_code);
        Unreached { code, status: dial_status(e.as_ref()), reason }
    })
}

/// The status of a dial of `tcp:` that failed. An upstream proxy's 407 is
/// 502 here: the client's credentials are not the ones that it lacks.
fn dial_status(e: Option<&DialError>) -> u16 {
    match e {
        Some(DialError::Timeout { .. }) => 504,
        Some(DialError::ProxyRefused { status: 403, .. }) => 403,
        _ => 502,
    }
}

async fn ssh(
    hops: &[String],
    host: &str,
    port: u16,
    settings: &Settings,
    say: &mut dyn FnMut(&str),
) -> Result<End, Unreached> {
    let mut lines = Vec::new();
    let mut keep = |line: &str| lines.push(line.to_string());
    let opened = super::ssh::open(hops, host, port, &settings.ssh, &mut keep).await;
    for line in &lines {
        say(line);
    }
    opened.map_err(|code| {
        let reason = lines.last().cloned().unwrap_or_default();
        Unreached { code, status: ssh_status(&reason), reason }
    })
}

/// The status of an SSH road that failed, by the last line: russh names a
/// server's refusal of the channel by its reason, and OpenSSH gives this one
/// for a target that its `PermitOpen` or `AllowTcpForwarding` refuses.
fn ssh_status(reason: &str) -> u16 {
    if reason.contains("AdministrativelyProhibited") {
        403
    } else if reason.contains("timed out") {
        504
    } else {
        502
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(status: u16, body: &str) -> OpenError {
        let error = ConnectError::Refused { status, body: body.into() };
        OpenError::Connect { error, origin: podssh_relay::token::Origin::Minted }
    }

    #[test]
    fn the_relay_s_policy_is_403_with_its_words_and_its_limit_504() {
        let policy = relay_status(&refused(403, "not in the ALLOW list: 10.0.0.1:22"), "line");
        assert_eq!(policy, (403, "not in the ALLOW list: 10.0.0.1:22".to_string()));
        assert_eq!(relay_status(&refused(400, "blocked range"), "line").0, 403);
        assert_eq!(relay_status(&refused(403, "missing or wrong token"), "line"), (502, "line".to_string()));
        let unreachable = relay_status(&refused(502, "relay: cannot reach a:1: refused"), "line");
        assert_eq!(unreachable, (502, "relay: cannot reach a:1: refused".to_string()));
        assert_eq!(relay_status(&OpenError::Deadline, "past 45 s").0, 504);
        let step = ConnectError::Timeout { step: "the TLS handshake", after: std::time::Duration::from_secs(20) };
        let step = OpenError::Connect { error: step, origin: podssh_relay::token::Origin::Minted };
        assert_eq!(relay_status(&step, "line").0, 504);
    }

    #[test]
    fn a_dial_past_its_limit_is_504_and_a_proxy_s_407_is_no_407_of_ours() {
        let after = std::time::Duration::from_secs(20);
        let timeout = DialError::Timeout { step: "connecting to a:1".into(), after };
        assert_eq!(dial_status(Some(&timeout)), 504);
        let refused = |status| {
            let (proxy, target, reason) = ("p".to_string(), "a:1".to_string(), "r".to_string());
            DialError::ProxyRefused { proxy, target, status, reason }
        };
        assert_eq!(dial_status(Some(&refused(403))), 403);
        assert_eq!(dial_status(Some(&refused(407))), 502);
        assert_eq!(dial_status(None), 502, "PODSSH_OFFLINE");
        assert_eq!(ssh_status("could not open: Failed to open channel (AdministrativelyProhibited)"), 403);
        assert_eq!(ssh_status("could not open: Failed to open channel (ConnectFailed)"), 502);
    }
}
