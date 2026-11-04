//! The list of deployments in the binary (T-346): the keys that it trusts
//! beside those compiled in (the settings file's `RelayKeys`,
//! `PODSSH_RELAY_KEYS`, and the members of the net that carry the role
//! `relay`), the hosts of other deployments that follow the default list,
//! and what `relay info`, `relay status`, `status` and `doctor` say of the
//! lists kept. The form, the check and the cache are
//! `podssh_relay::pool::signed` and `podssh_relay::pool::kept`.

use podssh_relay::identity::KeyName;
use podssh_relay::pool::kept::{self, Seen, Taken};
use podssh_relay::pool::signed::{self, Checked, Deployment, Keys, Signed};
use podssh_relay::relay::{self, RelayList, DEFAULT_RELAY_HOST};
use podssh_relay::token::relay_name;
use serde_json::{json, Value};

use crate::relay_settings::Refusal;
use crate::settings::Defaults;

/// Give the library the keys of the settings file and of the net, once
/// `PODSSH_RELAY_KEYS` is checked: a word of it that is no key is 78.
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
    keys.extend(net_keys());
    signed::set_by_settings(keys);
    Ok(())
}

/// The keys of the members of the net that this host holds with the role
/// `relay`, while its document holds: such a member's role signs its list
/// with the key that the net names for it. A net that cannot be read gives
/// none, and stops nothing.
fn net_keys() -> Vec<(KeyName, String)> {
    let Some(held) = crate::net::store::held_or_none() else { return Vec::new() };
    let doc = &held.signed.doc;
    if doc.expires <= crate::net::now() {
        return Vec::new();
    }
    let relays = doc.members.iter().filter(|m| m.has_role("relay"));
    relays.map(|m| (m.key.clone(), format!("the member {} of the net {}", m.name, doc.name))).collect()
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
    lines
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
