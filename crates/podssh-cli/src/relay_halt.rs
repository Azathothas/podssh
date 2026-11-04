//! `podssh relay halt NAME [--reason TEXT]` and `podssh relay resume NAME`
//! (T-647, GitHub #145): the pair stored under NAME, halted or resumed at
//! podssh's relay role by its stop token, which the owner alone holds. A
//! halt closes each session of the pair once, and each operator's upgrade
//! then hears `503` with the reason, while the pair's node keeps its socket,
//! and so the pair's name; a resume takes the next operator on that socket.
//! The halt lives in the relay's memory alone. The default relay halts no
//! pair, as its contract has no such request, and is said so (69). stdout
//! carries one line, the label and the state, never a token.

use std::io::Write;

use podssh_relay::pair::halt::{self, Halted, Resumed};
use podssh_relay::pair::{self, Pair, PairError};
use podssh_ws::dial::ProxyChoice;

use crate::exitmap::Fault;
use crate::pairs;
use crate::relay_cmd::{block_on, RelayArgs};
use crate::relay_settings::Refusal;

/// Halt the pair stored under `label` at the relay that made it.
pub(crate) fn halt(args: &RelayArgs, label: &str, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Refusal> {
    let reason = args.reason.as_deref().map(str::trim).filter(|words| !words.is_empty());
    if let Some(words) = reason {
        halt::check_reason(words).map_err(|why| Refusal::usage(format!("--reason: {why}")))?;
    }
    let stored = stored(args, label, "halt")?;
    let (trust, proxy) = (pairs::trust(args.ca_file.as_deref()), ProxyChoice::FromEnvironment);
    let ctx = pairs::context(&stored.relay, &trust, &proxy);
    match block_on(halt::halt(&ctx, &stored, reason))? {
        Ok(Halted::Now { sessions }) => {
            let closed = match sessions {
                1 => "1 session closed".to_string(),
                n => format!("{n} sessions closed"),
            };
            let _ = writeln!(out, "{label}: halted; {closed}");
            let _ = writeln!(
                err,
                "podssh relay: each operator of {label:?} hears 503 with {} until `podssh relay resume {label}`; \
                 its node keeps its socket and its name; a restart of the relay ends the halt",
                if reason.is_some() { "your reason" } else { "no reason" }
            );
            Ok(())
        }
        Ok(Halted::Already { since }) => {
            let _ = writeln!(out, "{label}: halted already, since {}", pairs::utc(since));
            let first = "the first halt holds, with its reason; resume, then halt, for new words";
            let _ = writeln!(err, "podssh relay: {first}");
            Ok(())
        }
        Ok(Halted::NotServed) => Err(not_served(label, &stored)),
        Err(e) => Err(refused(e)),
    }
}

/// Resume the pair stored under `label` at the relay that made it.
pub(crate) fn resume(args: &RelayArgs, label: &str, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Refusal> {
    let stored = stored(args, label, "resume")?;
    let (trust, proxy) = (pairs::trust(args.ca_file.as_deref()), ProxyChoice::FromEnvironment);
    let ctx = pairs::context(&stored.relay, &trust, &proxy);
    match block_on(halt::resume(&ctx, &stored))? {
        Ok(Resumed::Now) => {
            let _ = writeln!(out, "{label}: resumed");
            let _ = writeln!(err, "podssh relay: its node takes the next operator on the socket that it holds");
            Ok(())
        }
        Ok(Resumed::NotHalted) => {
            let _ = writeln!(out, "{label}: not halted");
            Ok(())
        }
        Ok(Resumed::NotServed) => Err(not_served(label, &stored)),
        Err(e) => Err(refused(e)),
    }
}

/// The live pair stored under `label`, for `verb`, once the flags of a new
/// pair are refused and the network may be used.
fn stored(args: &RelayArgs, label: &str, verb: &str) -> Result<Pair, Refusal> {
    pairs::check_label(label)?;
    if args.relay_host.is_some() {
        return Err(Refusal::usage(format!(
            "--relay-host does not go with {verb}: it asks the relay that made the pair stored under {label:?}"
        )));
    }
    let stored = match pair::load(label) {
        Ok(Some(stored)) => stored,
        Ok(None) => return Err(Refusal::config(format!("no pair is stored under {label:?}"))),
        Err(e) => return Err(pairs::refusal(&e)),
    };
    // A pair that ended has no tokens left.
    let stored = pairs::usable(stored, label)?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    pairs::online()?;
    Ok(stored)
}

/// A refused stop token is a pair that was stopped or ended (77).
fn refused(e: PairError) -> Refusal {
    match e {
        PairError::Forbidden => Refusal {
            message: "the relay refused the stop token (403): the pair was stopped, or it ended".into(),
            code: Fault::Auth.code(),
        },
        e => pairs::refusal(&e),
    }
}

/// The words of a relay that halts no pair (69), with the ways that work on
/// each relay.
fn not_served(label: &str, stored: &Pair) -> Refusal {
    Refusal {
        message: format!(
            "the relay {} halts no pair: it has no {}NAME, as the relay's contract has none; `podssh relay revoke \
             {label}` ends the pair, and a stop of its node keeps its operators out",
            stored.relay.host,
            halt::HALT
        ),
        code: Fault::RelayUnreachable.code(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_pair() -> Pair {
        let (name, token) = (format!("p-{}", "0".repeat(32)), "a".repeat(64));
        let body = format!(
            r#"{{"name":"{name}","node_token":"{token}","connect_token":"{token}","stop_token":"{token}","expires":3600000}}"#
        );
        let relay = podssh_relay::relay::Relay { host: "relay.test".into(), port: 443 };
        pair::parse(&relay, body.as_bytes(), 0).unwrap()
    }

    #[test]
    fn a_relay_with_no_halt_says_the_ways_that_work_with_69() {
        let refusal = not_served("lab", &stored_pair());
        assert_eq!(refusal.code, 69);
        assert!(refusal.message.starts_with("the relay relay.test halts no pair"), "{}", refusal.message);
        assert!(refusal.message.contains("podssh relay revoke lab"), "{}", refusal.message);
        assert!(!refusal.message.contains(&"a".repeat(64)), "no token: {}", refusal.message);
    }

    #[test]
    fn a_halt_takes_one_short_line_and_no_relay_host() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let long = RelayArgs { reason: Some("a".repeat(201)), ..RelayArgs::default() };
        let refusal = halt(&long, "lab", &mut out, &mut err).unwrap_err();
        assert_eq!(refusal.code, 64, "{}", refusal.message);
        let lines = RelayArgs { reason: Some("two\nlines".into()), ..RelayArgs::default() };
        assert_eq!(halt(&lines, "lab", &mut out, &mut err).unwrap_err().code, 64);
        let host = RelayArgs { relay_host: Some("r.example".into()), ..RelayArgs::default() };
        for verb in ["halt", "resume"] {
            let refusal = stored(&host, "lab", verb).unwrap_err();
            assert_eq!(refusal.code, 64, "{verb}: {}", refusal.message);
            let said = format!("--relay-host does not go with {verb}");
            assert!(refusal.message.starts_with(&said), "{}", refusal.message);
        }
        assert!(out.is_empty(), "nothing on stdout");
    }
}
