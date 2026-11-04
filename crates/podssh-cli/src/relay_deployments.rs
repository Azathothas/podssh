//! The list of deployments in the binary (T-346): the keys that it trusts
//! beside those compiled in (the settings file's `RelayKeys`,
//! `PODSSH_RELAY_KEYS`, and the members of the net that carry the role
//! `relay`), the hosts of other deployments that follow the default list,
//! and what `relay info`, `relay status`, `status` and `doctor` say of the
//! lists kept. The form, the check and the cache are
//! `podssh_relay::pool::signed` and `podssh_relay::pool::kept`. The net's
//! relay members whose host the document names (T-617) go to
//! `podssh_relay::pool::members`, which asks each for its list once a day,
//! and `relay status` says what each gave.

use podssh_relay::identity::KeyName;
use podssh_relay::pool::kept::{self, Seen, Taken};
use podssh_relay::pool::members;
use podssh_relay::pool::signed::{self, Checked, Deployment, Keys, Signed};
use podssh_relay::relay::{self, RelayList, DEFAULT_RELAY_HOST};
use podssh_relay::token::relay_name;
use serde_json::{json, Value};

use crate::net::doc::{Doc, Member};
use crate::net::store::Held;
use crate::relay_settings::Refusal;
use crate::settings::Defaults;

/// Give the library the keys of the settings file and of the net, once
/// `PODSSH_RELAY_KEYS` is checked: a word of it that is no key is 78; and
/// the net's relay members with a host, for their asks (T-617).
pub fn install(file: &Defaults) -> Result<(), Refusal> {
    if let Ok(text) = std::env::var(signed::KEYS_ENV) {
        signed::parse_keys(&text).map_err(|why| Refusal::config(format!("{}: {why}", signed::KEYS_ENV)))?;
    }
    let mut keys: Vec<(KeyName, String)> = Vec::new();
    for value in &file.relay_keys {
        // The file's values were checked as the file was read.
        for key in signed::parse_keys(&value.text).unwrap_or_default() {
            keys.push((key, format!("RelayKeys at {}", value.at)));
        }
    }
    let net = net_now();
    keys.extend(net.iter().flat_map(net_keys));
    signed::set_by_settings(keys);
    members::set_by_net(net.iter().flat_map(net_hosts).collect());
    Ok(())
}

/// The net that this host holds, while its document holds. A net that
/// cannot be read gives none, and stops nothing.
fn net_now() -> Option<Held> {
    crate::net::store::held_or_none().filter(|held| held.signed.doc.expires > crate::net::now())
}

/// The keys of the members of `held` with the role `relay`: such a member's
/// role signs its list with the key that the net names for it.
fn net_keys(held: &Held) -> Vec<(KeyName, String)> {
    let doc = &held.signed.doc;
    let relays = doc.members.iter().filter(|m| m.has_role("relay"));
    relays.map(|m| (m.key.clone(), format!("the member {} of the net {}", m.name, doc.name))).collect()
}

/// The relay members of `held` whose host the document names, as the
/// library asks them (T-617). A host that this podssh does not read is left
/// unused, as a word of a later podssh would be.
fn net_hosts(held: &Held) -> Vec<members::Member> {
    let doc = &held.signed.doc;
    doc.members.iter().filter(|m| m.has_role("relay")).filter_map(|m| asked_member(doc, m)).collect()
}

/// `m` as the library asks it, when its host is one that this podssh reads.
fn asked_member(doc: &Doc, m: &Member) -> Option<members::Member> {
    let host = relay::parse_relay(m.relay.as_deref()?).ok()?;
    Some(members::Member { name: m.name.clone(), net: doc.name.clone(), key: m.key.clone(), host })
}

/// The default list of a command that measures, `relay status`, with the
/// lists of the net's relay members that are due asked first (T-617), as a
/// session asks them; a list that the user named, as it is.
pub fn asked((relays, trust): (RelayList, podssh_ws::Trust)) -> (RelayList, podssh_ws::Trust) {
    let refreshed = crate::relay_cmd::block_on(members::refreshed(&relays, &trust));
    (refreshed.unwrap_or(relays), trust)
}

/// The default list followed by the hosts of the other deployments that a
/// list kept names; a list that the user named stays as it is.
pub fn joined(list: RelayList) -> RelayList {
    if list.explicit {
        return list;
    }
    relay::with_others(list, kept::other_hosts(crate::pairs::now_ms()))
}

fn utc(secs: i64) -> String {
    crate::pairs::utc(secs.saturating_mul(1000))
}

/// A list that holds, in words: its key, why the key is trusted, its serial
/// and its end.
fn signed_words(c: &Checked) -> String {
    format!("signed by {} ({}), serial {}, until {}", c.signed.key, c.by, c.doc.serial, utc(c.doc.not_after))
}

/// One deployment of a list that holds, as `--json` gives it.
fn deployment_value(d: &Deployment, c: &Checked) -> Value {
    let hosts: Vec<String> = d.hosts.iter().map(relay_name).collect();
    let signed = json!({
        "key": c.signed.key.fingerprint(), "by": c.by, "serial": c.doc.serial, "not_after": c.doc.not_after,
    });
    json!({ "name": d.name, "hosts": hosts, "signed": signed })
}

/// What `relay info` says of the field `signed` of the first host's
/// `/relays.json`, as lines and as `--json`'s `signed_list`: none, or the
/// list and its deployments, kept when it holds, as a session's refresh of
/// the pool keeps it; or why it is not used.
pub fn info(doc: &Value) -> (Vec<String>, Value) {
    let Some(value) = doc.get("signed").filter(|v| !v.is_null()) else {
        let line = "signed list: none, so only hosts of the default's domain join the default list";
        return (vec![line.into()], Value::Null);
    };
    let taken = Signed::of_value(value)
        .and_then(|s| kept::take(&s, &Keys::of_process(), crate::pairs::now_ms()).map_err(|why| why.to_string()));
    match taken {
        Ok(taken) => {
            let c = taken.checked();
            let how = match &taken {
                Taken::Kept(_) => "kept; its deployments follow the default list",
                Taken::Same(_) => "the list kept already",
            };
            let mut lines = vec![format!("signed list: {}; {how}", signed_words(c))];
            lines.extend(c.doc.deployments.iter().map(|d| format!("  deployment {}: {}", d.name, d.shown())));
            let deployments: Vec<Value> = c.doc.deployments.iter().map(|d| deployment_value(d, c)).collect();
            (lines, json!({ "used": true, "deployments": deployments }))
        }
        Err(why) => (vec![format!("signed list: not used: {why}")], json!({ "used": false, "why": why })),
    }
}

/// The deployments of the run's list, each with whether its list was signed,
/// for `relay status --json` and `status`: the default with its pool, which
/// needs no signature as its hosts share its domain, then each deployment of
/// each list kept that holds, and each list kept that does not, with why. A
/// list that the user named is one deployment of its own.
pub fn status_value(relays: &RelayList) -> Value {
    if relays.explicit {
        let hosts: Vec<String> = relays.hosts.iter().map(relay_name).collect();
        return json!([{ "name": "named", "hosts": hosts, "signed": null }]);
    }
    let pool: Vec<String> = relays.hosts.iter().filter(|r| kept::of_default(r)).map(relay_name).collect();
    let mut out = vec![json!({ "name": "default", "hosts": pool, "signed": false })];
    for seen in kept::seen(&Keys::of_process(), crate::pairs::now_ms()) {
        match seen.held {
            Ok(c) => out.extend(c.doc.deployments.iter().map(|d| deployment_value(d, &c))),
            Err((key, why)) => out.push(json!({
                "name": null, "hosts": [], "signed": { "key": key.map(|k| k.fingerprint()), "used": false,
                "why": why.to_string() },
            })),
        }
    }
    Value::Array(out)
}

/// The lines of `relay status` after its hosts': one for each deployment of
/// the default list, and one for each list kept that does not hold now.
pub fn status_lines(relays: &RelayList) -> Vec<String> {
    if relays.explicit {
        return Vec::new();
    }
    let pool = relays.hosts.iter().filter(|r| kept::of_default(r)).count().saturating_sub(1);
    let mut lines = vec![format!(
        "deployment default: {DEFAULT_RELAY_HOST} and {pool} hosts of its pool, unsigned, as they share its domain"
    )];
    for seen in kept::seen(&Keys::of_process(), crate::pairs::now_ms()) {
        lines.extend(seen_lines(&seen));
    }
    lines.extend(member_lines());
    lines
}

/// A relay member of the net held, as `relay status` names it (T-617).
struct Shown {
    name: String,
    net: String,
    /// Its key's fingerprint.
    key: String,
    said: Said,
}

/// Where a relay member's list comes from: no host in the document, a host
/// that this podssh does not read, a host not asked yet, or the host and
/// its last ask, with the serial of the list taken or why none was.
enum Said {
    NoHost,
    Unread(String),
    NotAsked(String),
    Asked(String, members::Ask),
}

/// Each member of the net held with the role `relay`, and what its ask gave.
fn relay_members() -> Vec<Shown> {
    let Some(held) = net_now() else { return Vec::new() };
    let doc = &held.signed.doc;
    let each = doc.members.iter().filter(|m| m.has_role("relay")).map(|m| {
        let said = match (m.relay.as_deref(), asked_member(doc, m)) {
            (None, _) => Said::NoHost,
            (Some(text), None) => Said::Unread(text.to_string()),
            (Some(_), Some(asked)) => {
                let at = relay_name(&asked.host);
                match members::last_ask(&asked) {
                    Some(ask) => Said::Asked(at, ask),
                    None => Said::NotAsked(at),
                }
            }
        };
        Shown { name: m.name.clone(), net: doc.name.clone(), key: m.key.fingerprint(), said }
    });
    each.collect()
}

/// The lines of `relay status` for the net's relay members: each with its
/// role, its host, and whether its list was taken.
fn member_lines() -> Vec<String> {
    let line = |Shown { name, net, said, .. }: Shown| {
        let head = format!("member {name} of the net {net}: the role relay");
        match said {
            Said::NoHost => format!(
                "{head}, with no host in the net's document: its owner names one with podssh net add NAME KEY \
                 --roles relay --relay-host HOST, else podssh relay info --relay-host HOST takes its list"
            ),
            Said::Unread(text) => format!("{head}, its host {text:?} not one that this podssh reads: unused"),
            Said::NotAsked(at) => {
                format!("{head} at {at}; not asked yet: a session on the default list asks it, once a day")
            }
            Said::Asked(at, ask) => {
                let when = crate::pairs::utc(ask.asked_ms);
                match (ask.serial, ask.why) {
                    (Some(serial), _) => format!("{head} at {at}; its list taken, serial {serial}, asked {when}"),
                    (None, Some(why)) => format!("{head} at {at}; its list not taken: {why}; asked {when}"),
                    (None, None) => format!("{head} at {at}; asked {when}, and that run ended before the answer"),
                }
            }
        }
    };
    relay_members().into_iter().map(line).collect()
}

/// The net's relay members, as `relay status --json` gives them (T-617):
/// none for a list that the user named, which takes no other deployment.
pub fn members_value(relays: &RelayList) -> Value {
    if relays.explicit {
        return Value::Array(Vec::new());
    }
    let each = relay_members().into_iter().map(|Shown { name, net, key, said }| {
        let (host, ask) = match said {
            Said::NoHost => (Value::Null, None),
            Said::Unread(text) | Said::NotAsked(text) => (json!(text), None),
            Said::Asked(at, ask) => (json!(at), Some(ask)),
        };
        let asked_ms = ask.as_ref().map(|a| a.asked_ms);
        let (serial, why) = ask.map_or((None, None), |a| (a.serial, a.why));
        json!({ "name": name, "net": net, "key": key, "host": host, "asked_ms": asked_ms, "taken": serial.is_some(),
            "serial": serial, "why": why })
    });
    Value::Array(each.collect())
}

fn seen_lines(seen: &Seen) -> Vec<String> {
    match &seen.held {
        Ok(c) => {
            let each = c.doc.deployments.iter();
            each.map(|d| format!("deployment {}: {}; {}", d.name, d.shown(), signed_words(c))).collect()
        }
        Err((key, why)) => {
            let by = key.map(|k| format!(" of {k}")).unwrap_or_default();
            vec![format!("a list kept{by} is not used: {why}")]
        }
    }
}

/// `doctor`'s line `deployments`: the default alone, or with the
/// deployments of the lists that hold, each with its signer; read from the
/// cache, with no connection.
pub fn doctor_line(relays: &RelayList) -> String {
    if relays.explicit {
        return "the hosts that you named: no list of deployments joins them".into();
    }
    let lists = kept::in_force(&Keys::of_process(), crate::pairs::now_ms());
    let each = |c: &Checked| -> Vec<String> {
        c.doc.deployments.iter().map(|d| format!("{} ({}; {})", d.name, d.shown(), signed_words(c))).collect()
    };
    let others: Vec<String> = lists.iter().flat_map(each).collect();
    match others.is_empty() {
        true => "the default deployment alone: no signed list of other deployments holds here".into(),
        false => format!("the default deployment, then {}", others.join("; ")),
    }
}
