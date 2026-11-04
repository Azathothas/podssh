//! `podssh relay status NAME` and `status --pair-file FILE [NAME]` (T-083,
//! T-591): whether a pair's node is online, its sessions, and the pair's
//! expiry, from the pair stored under NAME, or from a file of the pair or of
//! its operator's part alone, as an operator's host holds it: the relay
//! answers the status to the connect token, which that part holds. In the
//! pair's last day the expiry says how long is left. `--json` gives the same
//! as one object, for a check. The expiry is the one that the relay names
//! where it names one (podssh's relay role, whose renewal moves it, T-592),
//! else the file's; and the owner's halt, with its words, where podssh's
//! relay role says it (T-647).

use std::io::Write;

use podssh_relay::pair;
use podssh_ws::dial::ProxyChoice;
use serde_json::json;

use crate::pairs;
use crate::relay_cmd::{block_on, RelayArgs};
use crate::relay_settings::Refusal;

/// The status of the pair of `label`, or of the file of `--pair-file`, in
/// which NAME is only the label shown: one line on stdout, or with `--json`
/// one JSON object.
pub(crate) fn pair(args: &RelayArgs, label: Option<&str>, out: &mut dyn Write) -> Result<(), Refusal> {
    if let Some(label) = label {
        pairs::check_label(label)?;
    }
    // Before the part: a file past its end asks its relay (T-592).
    crate::pins::apply(args.relay_addr.as_deref())?;
    let (shown, part) = match (args.pair_file.as_deref(), label) {
        (Some(file), _) => {
            let shown = label.unwrap_or(file).to_string();
            let part = pairs::operator_part(&shown, Some(file))?;
            (shown, part)
        }
        // The pair under NAME, or the part that a pairing by code kept (T-086).
        (None, Some(label)) => (label.to_string(), pairs::stored_part(label)?),
        (None, None) => {
            return Err(Refusal::usage("missing NAME: `podssh relay status NAME`, or --pair-file FILE"));
        }
    };
    pairs::online()?;
    let (trust, proxy) = (pairs::trust(args.ca_file.as_deref()), ProxyChoice::FromEnvironment);
    let ctx = pairs::context(&part.relay, &trust, &proxy);
    let presence = block_on(pair::renew::status(&ctx, &part))?.map_err(|e| pairs::refusal(&e))?;
    // The end that podssh's relay role names, which a renewal moves past the
    // file's (T-592); a relay of the contract names none.
    let expires_ms = presence.expires.unwrap_or(part.expires_ms);
    let left_ms = expires_ms.saturating_sub(pairs::now_ms()).max(0);
    let _ = if args.json {
        let mut doc = json!({
            "schema": 1,
            "podssh": crate::help::version(),
            "label": shown,
            "online": presence.online,
            "sessions": presence.sessions,
            "expires": pairs::utc(expires_ms),
            "seconds_left": left_ms / 1000,
            "halted": presence.halted,
        });
        if let Some(why) = &presence.halt_reason {
            doc["halt_reason"] = json!(podssh_ws::text::one_line(why));
        }
        writeln!(out, "{doc}")
    } else {
        let until = expiry(expires_ms, left_ms);
        let state = match (presence.online, presence.sessions) {
            (true, 1) => "online, 1 session".to_string(),
            (true, n) => format!("online, {n} sessions"),
            (false, _) => "offline".to_string(),
        };
        writeln!(out, "{shown}: {state}{}; {until}", halted(presence.halted, presence.halt_reason.as_deref()))
    };
    Ok(())
}

/// The words of its owner's halt, which podssh's relay role says (T-647):
/// `, halted: WHY`, or nothing for a pair that is not halted. The relay's
/// words come on one line, with no control character.
fn halted(halted: bool, why: Option<&str>) -> String {
    match (halted, why.map(podssh_ws::text::one_line).filter(|w| !w.is_empty())) {
        (true, Some(why)) => format!(", halted: {why}"),
        (true, None) => ", halted".to_string(),
        (false, _) => String::new(),
    }
}

/// `expires AT`, or in the pair's last day, in which its next pair may be
/// made (`node_expiry::RENEW_WINDOW`), `expires in 5 h, at AT`.
pub(crate) fn expiry(expires_ms: i64, left_ms: i64) -> String {
    let window = i64::try_from(crate::node_expiry::RENEW_WINDOW.as_millis()).unwrap_or(i64::MAX);
    let at = pairs::utc(expires_ms);
    if left_ms < window {
        format!("expires in {}, at {at}", crate::node_expiry::left_words(left_ms))
    } else {
        format!("expires {at}")
    }
}

#[cfg(test)]
mod tests {
    use super::{expiry, halted};

    #[test]
    fn a_halt_is_said_with_its_owners_words_on_one_line() {
        assert_eq!(halted(false, None), "");
        assert_eq!(halted(true, None), ", halted");
        assert_eq!(halted(true, Some(" \n ")), ", halted");
        assert_eq!(halted(true, Some("a new\ndisk")), ", halted: a new disk");
    }

    const HOUR: i64 = 3_600_000;

    #[test]
    fn the_last_day_says_how_long_is_left() {
        // 2026-10-12T08:10:00Z.
        let at = 1_791_792_600_000;
        assert_eq!(expiry(at, 30 * HOUR), "expires 2026-10-12T08:10:00Z");
        assert_eq!(expiry(at, 24 * HOUR), "expires 2026-10-12T08:10:00Z");
        assert_eq!(expiry(at, 5 * HOUR), "expires in 5 h, at 2026-10-12T08:10:00Z");
        assert_eq!(expiry(at, 23 * HOUR - 60_000), "expires in 22 h 59 min, at 2026-10-12T08:10:00Z");
        assert_eq!(expiry(at, 30_000), "expires in less than a minute, at 2026-10-12T08:10:00Z");
    }
}
