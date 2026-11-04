//! The net in `podssh status` (T-435), as `tailscale status` lists a
//! tailnet, read with no connection: the document held, its name, serial,
//! owner, end, file and count of members; with `--net`, each member, its
//! roles, key, tickets and routes, and the road that last reached it from
//! this host (`super::reached`), or the race that last found none.

use serde_json::{json, Value};

use super::doc::Member;
use super::reached::{self, Entry, Records};
use super::{now, sign, store};

/// The field `net` of the line: null when this host holds no net or the net
/// is off; the fault when its file does not read, which never stops the
/// line; else the net, with its members when `members` asks for them.
pub fn status_value(members: bool) -> Value {
    let held = match store::held() {
        Ok(Some(held)) => held,
        Ok(None) => return Value::Null,
        Err(why) => return json!({ "error": why }),
    };
    let doc = &held.signed.doc;
    let mut value = json!({
        "name": doc.name,
        "serial": doc.serial,
        "owner": sign::owner_fingerprint(&doc.owner),
        "expires_ms": doc.expires.saturating_mul(1000),
        "ended": doc.expires <= now(),
        "file": held.path.display().to_string(),
        "count": doc.members.len(),
    });
    if members {
        let (records, now_ms) = (reached::load(), crate::pairs::now_ms());
        value["members"] = doc.members.iter().map(|member| member_value(member, &records, now_ms)).collect();
    }
    value
}

/// One member, and what the races from this host last found of it: the road
/// that won and when, the race that found none and why, and which of the two
/// came last (`reached`, `missed`, or null with neither).
fn member_value(member: &Member, records: &Records, now_ms: i64) -> Value {
    let entry = records.get(&member.name);
    let ago = |at_ms: i64| now_ms.saturating_sub(at_ms).max(0) / 1000;
    let reached = entry.and_then(|e| e.reached.as_ref());
    let reached = reached.map(|r| json!({ "road": r.road, "ms": r.ms, "ago_s": ago(r.at_ms) }));
    let missed = entry.and_then(|e| e.missed.as_ref()).map(|m| json!({ "why": m.why, "ago_s": ago(m.at_ms) }));
    let last = match entry.and_then(Entry::last_reached) {
        Some(true) => json!("reached"),
        Some(false) => json!("missed"),
        None => Value::Null,
    };
    json!({
        "name": member.name,
        "roles": member.roles,
        "key": member.key.fingerprint(),
        "tickets": member.tickets.keys().collect::<Vec<_>>(),
        "routes": member.routes,
        "reached": reached,
        "missed": missed,
        "last": last,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use podssh_relay::identity::{Identity, KeyName};

    use super::super::reached::{Missed, Reached};
    use super::*;

    const NOW: i64 = 1_793_577_600_000;

    fn lab() -> Member {
        let key = KeyName::parse(&Identity::from_seed(&[7; 32]).public().hex()).expect("a key");
        let tickets = BTreeMap::from([("derp".to_string(), "a ticket".to_string())]);
        Member {
            name: "lab".into(),
            key,
            roles: vec!["node".into(), "exit".into()],
            tickets,
            routes: Vec::new(),
            relay: None,
        }
    }

    /// A member that no race reached has no road; then the road that won,
    /// with its time and its age; then a race that found none, which is the
    /// last word, the road that won beside it.
    #[test]
    fn a_member_shows_the_road_that_last_reached_it_or_the_race_that_missed() {
        let member = lab();
        let mut records = Records::new();
        let none = member_value(&member, &records, NOW);
        assert_eq!((&none["reached"], &none["missed"], &none["last"]), (&Value::Null, &Value::Null, &Value::Null));
        assert_eq!(none["roles"], json!(["node", "exit"]));
        assert_eq!(none["tickets"], json!(["derp"]), "the kinds of tickets, never a ticket");
        assert!(none["key"].as_str().is_some_and(|k| k.starts_with("SHA256:")), "{none}");
        let reached = Reached { road: "the pair's road".into(), ms: 12.5, at_ms: NOW - 5000 };
        records.insert("lab".into(), Entry { reached: Some(reached.clone()), missed: None });
        let seen = member_value(&member, &records, NOW);
        assert_eq!(seen["reached"], json!({ "road": "the pair's road", "ms": 12.5, "ago_s": 5 }));
        assert_eq!(seen["last"], "reached");
        let missed = Missed { why: "no road reached the node".into(), at_ms: NOW - 1000 };
        records.insert("lab".into(), Entry { reached: Some(reached), missed: Some(missed) });
        let stopped = member_value(&member, &records, NOW);
        assert_eq!(stopped["last"], "missed", "{stopped}");
        assert_eq!(stopped["missed"], json!({ "why": "no road reached the node", "ago_s": 1 }));
        assert_eq!(stopped["reached"]["road"], "the pair's road", "the road that won stays");
    }
}
