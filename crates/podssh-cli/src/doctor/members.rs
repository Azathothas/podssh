//! The section `net` (T-435), as `tailscale netcheck` says what a host
//! reaches of its tailnet: the net that this host holds, read with no
//! connection, then its member relays, the members with the role `relay`,
//! which carry sessions between two other members (T-434). Each is asked
//! `/health` at its host, one TLS connection through the proxy, verified
//! with doctor's trust, as the relay section asks the relay hosts; one after
//! another, at most [`MOST`]. A member's host is the field `relay` of its
//! object in the document (T-617), read as it is, as a field that this
//! podssh does not know stays in the document whole.

use podssh_relay::relay::Relay;
use podssh_ws::{ProxyChoice, Trust};
use serde_json::Value;

use super::relay_checks::TIMEOUT;
use super::Report;
use crate::net::doc::Doc;
use crate::net::store;

/// The most member relays asked in one run.
pub(super) const MOST: usize = 8;

/// A member with the role `relay`: its name, and its host, or why it has
/// none that can be asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MemberRelay {
    pub(super) name: String,
    pub(super) host: Result<Relay, String>,
}

/// The members of `doc` with the role `relay`, in its order; no other.
pub(super) fn relays_of(doc: &Doc) -> Vec<MemberRelay> {
    let objects: &[Value] = doc.field("members").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let relays = doc.members.iter().filter(|member| member.has_role("relay"));
    relays
        .map(|member| {
            let named = |object: &&Value| object.get("name").and_then(Value::as_str) == Some(member.name.as_str());
            let host = match objects.iter().find(named).and_then(|object| object.get("relay")) {
                None => Err("the net's document names no host of its relay role".to_string()),
                Some(Value::String(text)) => podssh_relay::relay::parse_relay(text)
                    .map_err(|why| format!("its host in the net's document, {text:?}, does not read: {why}")),
                Some(_) => Err("its host in the net's document is not text".to_string()),
            };
            MemberRelay { name: member.name.clone(), host }
        })
        .collect()
}

/// The net's line, and the net, when this host holds one that is in force.
fn net_line(report: &mut Report<'_>) -> Option<Doc> {
    match store::place() {
        Err(why) => {
            report.fail("net", format!("{}: {why}", store::ENV));
            return None;
        }
        Ok(store::Place::Off) => {
            report.ok("net", format!("off: {}=no, so no member, name or door comes from a net", store::ENV));
            return None;
        }
        Ok(_) => {}
    }
    let held = match store::held() {
        Ok(Some(held)) => held,
        Ok(None) => {
            report.ok("net", "this host holds no net: podssh net take FILE or podssh net join brings one");
            return None;
        }
        Err(why) => {
            report.fail("net", why);
            return None;
        }
    };
    let doc = held.signed.doc.clone();
    match doc.expires <= crate::net::now() {
        true => {
            report.fail("net", format!("{}; its owner renews it with podssh net renew", crate::net::summary(&held)))
        }
        false => report.ok("net", crate::net::summary(&held)),
    }
    Some(doc)
}

/// The section's lines: the net, then each member relay that it names.
pub(super) async fn check(report: &mut Report<'_>, trust: &Trust) {
    let Some(doc) = net_line(report) else { return };
    let relays = relays_of(&doc);
    if relays.is_empty() {
        return report.ok("member relays", format!("no member of the net {} has the role relay", doc.name));
    }
    for member in relays.iter().take(MOST) {
        let label = format!("member relay {}", member.name);
        let relay = match &member.host {
            Ok(relay) => relay,
            Err(why) => {
                report.unknown(&label, why.clone());
                continue;
            }
        };
        match podssh_relay::health::fetch(relay, trust, &ProxyChoice::FromEnvironment, TIMEOUT).await {
            Ok(found) => report.ok(&label, found.line(&relay.host)),
            Err(e) => report.fail(&label, format!("{}: {e}", podssh_ws::dial::authority(&relay.host, relay.port))),
        }
    }
    more_line(report, relays.len());
}

/// The member relays past [`MOST`], not asked.
fn more_line(report: &mut Report<'_>, count: usize) {
    if count > MOST {
        report.unknown("member relays", format!("{} more not asked: at most {MOST} in one run", count - MOST));
    }
}

/// With `PODSSH_OFFLINE`: the net's line, each member relay not asked, and
/// the report's end.
pub(super) fn offline(mut report: Report<'_>) -> i32 {
    report.section("net");
    if let Some(doc) = net_line(&mut report) {
        let relays = relays_of(&doc);
        for member in relays.iter().take(MOST) {
            report.unknown(&format!("member relay {}", member.name), "not asked: PODSSH_OFFLINE is set");
        }
        more_line(&mut report, relays.len());
    }
    report.finish()
}

#[cfg(test)]
mod tests {
    use podssh_relay::identity::Identity;
    use serde_json::json;

    use super::*;

    fn hex(seed: u8) -> String {
        Identity::from_seed(&[seed; 32]).public().hex()
    }

    /// A document of four members, by hand: a relay with a host, one with a
    /// host that does not read, one with none, and a node that has a host
    /// but no role relay.
    fn doc() -> Doc {
        // The owner of the captured vectors of `net/testdata`.
        let owner = include_str!("../net/testdata/owner.pub").split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        let members = json!([
            { "name": "hub", "key": hex(1), "roles": ["node", "relay"], "relay": "relay.example:8443" },
            { "name": "bad", "key": hex(2), "roles": ["relay"], "relay": "no host!" },
            { "name": "bare", "key": hex(3), "roles": ["relay"] },
            { "name": "lab", "key": hex(4), "roles": ["node"], "relay": "lab.example" },
        ]);
        let value = json!({
            "podssh-net": 1, "name": "home", "serial": 3, "issued": 1_793_577_600_i64, "expires": 4_102_444_800_i64,
            "owner": owner, "members": members, "requires": [],
        });
        Doc::parse(value.to_string().as_bytes()).expect("the document")
    }

    /// Only the members with the role relay are asked, each by the host that
    /// the document names; one with no host, or one that does not read, is
    /// not asked, and says why.
    #[test]
    fn only_a_member_with_the_role_relay_is_asked_by_its_host() {
        let relays = relays_of(&doc());
        let names: Vec<&str> = relays.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["hub", "bad", "bare"], "lab has no role relay");
        assert_eq!(relays[0].host, Ok(Relay { host: "relay.example".into(), port: 8443 }));
        assert!(relays[1].host.as_ref().is_err_and(|why| why.contains("does not read")), "{:?}", relays[1]);
        assert_eq!(relays[2].host, Err("the net's document names no host of its relay role".into()));
    }

    /// Past the bound, a line says how many were not asked.
    #[test]
    fn the_member_relays_past_the_bound_are_counted() {
        let mut out = Vec::new();
        let mut report = Report::new(&mut out);
        more_line(&mut report, MOST + 3);
        more_line(&mut report, MOST);
        let _ = report.finish();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("3 more not asked: at most 8 in one run"), "{text}");
        assert!(text.contains("0 ok, 0 FAIL, 1 ????"), "{text}");
    }
}
