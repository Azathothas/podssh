//! `podssh relay pair --renew NAME` (T-592): the pair stored under NAME,
//! renewed at its relay for 72 h from now, its three tokens the same, so
//! that each operator's file keeps working and its node goes on with no new
//! pair. podssh's relay role renews by the stop token, which the owner alone
//! holds (`POST /v1/renew/<name>`); the default relay renews no pair, as its
//! contract has no such request, and is said so with the way of T-395: the
//! next pair in the last 24 h. stdout carries one line, as `relay pair`'s:
//! the label and the new end, never a token. The operator's file is never
//! touched: its tokens hold, and its end is asked of the relay past it.

use std::io::Write;

use podssh_relay::pair::renew::{self, Renewed};
use podssh_relay::pair::{self, Pair, PairError};
use podssh_ws::dial::ProxyChoice;

use crate::exitmap::Fault;
use crate::pairs;
use crate::relay_cmd::{block_on, RelayArgs};
use crate::relay_settings::Refusal;

/// Renew the pair stored under `label` at the relay that made it.
pub(crate) fn run(args: &RelayArgs, label: &str, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Refusal> {
    pairs::check_label(label)?;
    let given = [(args.operator_file.is_some(), "--operator-file"), (args.relay_host.is_some(), "--relay-host")];
    if let Some((_, flag)) = given.into_iter().find(|(on, _)| *on) {
        let why = match flag {
            "--operator-file" => "writes a new pair's file, where a renewal keeps the pair that its operators hold",
            _ => "names the relay of a new pair, where a renewal asks the relay that made the stored one",
        };
        return Err(Refusal::usage(format!("--renew does not go with {flag}: it {why}")));
    }
    let stored = match pair::load(label) {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return Err(Refusal::config(format!(
                "no pair is stored under {label:?}; make one with `podssh relay pair {label}`"
            )))
        }
        Err(e) => return Err(pairs::refusal(&e)),
    };
    // A renewal keeps a pair that lives: one that ended has no tokens left.
    let stored = pairs::usable(stored, label)?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    pairs::online()?;
    let (trust, proxy) = (pairs::trust(args.ca_file.as_deref()), ProxyChoice::FromEnvironment);
    let ctx = pairs::context(&stored.relay, &trust, &proxy);
    match block_on(renew::renew(&ctx, &stored))? {
        Ok(Renewed::Until(until)) => kept(label, &stored, until, out, err),
        Ok(Renewed::NotServed) => Err(not_served(label, &stored)),
        Err(PairError::Forbidden) => Err(Refusal {
            message: "the relay refused the stop token (403): the pair was stopped, or it ended".into(),
            code: Fault::Auth.code(),
        }),
        Err(e) => Err(pairs::refusal(&e)),
    }
}

/// The renewed pair in the store, with its tokens; one line on stdout, and
/// on stderr what holds.
fn kept(label: &str, stored: &Pair, until: i64, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Refusal> {
    let host = &stored.relay.host;
    if let Err(e) = pair::store(label, &stored.with_expiry(until)) {
        return Err(Refusal::config(format!(
            "the relay {host} renewed the pair until {}, but the store took no write ({e}); its copy names the old \
             end, which a new start of its node reads",
            pairs::utc(until)
        )));
    }
    let _ = writeln!(out, "{label}: expires {}", pairs::utc(until));
    let _ = writeln!(
        err,
        "podssh relay: the pair under {label:?} is renewed at {host}: its tokens are the same, so each operator's \
         file holds, and its node goes on"
    );
    Ok(())
}

/// The words of a relay that renews no pair (69), with the way that works
/// on each relay: the next pair in the last 24 h, which the node takes.
fn not_served(label: &str, stored: &Pair) -> Refusal {
    Refusal {
        message: format!(
            "the relay {} renews no pair: it has no {}NAME, as the relay's contract has none, so the pair ends at \
             {}; in its last 24 h, `podssh relay pair {label} --operator-file NEW` makes the next pair, which its \
             node takes at the expiry, and NEW goes to each operator",
            stored.relay.host,
            renew::PATH,
            pairs::utc(stored.expires_ms)
        ),
        code: Fault::RelayUnreachable.code(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_with_no_renewal_says_the_way_of_the_next_pair_with_69() {
        let (name, token) = (format!("p-{}", "0".repeat(32)), "a".repeat(64));
        let body = format!(
            r#"{{"name":"{name}","node_token":"{token}","connect_token":"{token}","stop_token":"{token}","expires":3600000}}"#
        );
        let relay = podssh_relay::relay::Relay { host: "relay.test".into(), port: 443 };
        let stored = pair::parse(&relay, body.as_bytes(), 0).unwrap();
        let refusal = not_served("lab", &stored);
        assert_eq!(refusal.code, 69);
        assert!(refusal.message.starts_with("the relay relay.test renews no pair"), "{}", refusal.message);
        assert!(refusal.message.contains("podssh relay pair lab --operator-file NEW"), "{}", refusal.message);
        assert!(!refusal.message.contains(&token), "no token: {}", refusal.message);
    }

    #[test]
    fn a_renewal_takes_no_flag_of_a_new_pair() {
        let args = |file: Option<&str>, host: Option<&str>| RelayArgs {
            operator_file: file.map(str::to_string),
            relay_host: host.map(str::to_string),
            renew: true,
            ..RelayArgs::default()
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let given = [(args(Some("x"), None), "--operator-file"), (args(None, Some("r.example")), "--relay-host")];
        for (given, flag) in given {
            let refusal = run(&given, "lab", &mut out, &mut err).unwrap_err();
            assert_eq!(refusal.code, 64, "{flag}: {}", refusal.message);
            assert!(refusal.message.starts_with(&format!("--renew does not go with {flag}")), "{}", refusal.message);
        }
        assert!(out.is_empty(), "nothing on stdout");
    }
}
