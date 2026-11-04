//! The tests of the signed list (T-346), with test keys made here: a list of
//! a trusted key names hosts outside the default's domain, and one changed
//! byte, an old `not_after`, a lower serial or a key that is not trusted
//! keeps the default's domain alone.

use std::path::PathBuf;

use super::super::kept::{self, Taken};
use super::*;
use crate::relay::{select_relays, with_others, DEFAULT_RELAY_HOST};

/// 2026-11-02, in seconds and in milliseconds.
const NOW_S: i64 = 1_793_577_600;
const NOW_MS: i64 = NOW_S * 1000;
const DAY: i64 = 86_400;

/// A test key, made here from a fixed seed: no key of anyone's.
fn key(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn trusting(identity: &Identity) -> Keys {
    Keys::from_parts(None, vec![(KeyName::Key(identity.public()), "the test".to_string())])
}

fn relay(host: &str, port: u16) -> Relay {
    Relay { host: host.into(), port }
}

/// A list of one deployment outside the default's domain.
fn doc(serial: u64, host: &str) -> Doc {
    Doc {
        serial,
        issued: NOW_S - 3600,
        not_after: NOW_S + 30 * DAY,
        deployments: vec![Deployment { name: "backup".into(), hosts: vec![relay(host, 443)] }],
    }
}

/// The cache directories of one test, removed when the test ends: the gate
/// fails a run that leaves files in the temporary directory.
struct Dirs(Vec<PathBuf>);

impl std::ops::Deref for Dirs {
    type Target = [PathBuf];
    fn deref(&self) -> &[PathBuf] {
        &self.0
    }
}

impl Drop for Dirs {
    fn drop(&mut self) {
        for dir in &self.0 {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// An empty cache directory of this test alone.
fn dirs(name: &str) -> Dirs {
    let dir = std::env::temp_dir().join(format!("podssh-signed-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Dirs(vec![dir])
}

/// The directories of a test, as the cache's functions take them.
fn at(dirs: &[PathBuf]) -> Option<&[PathBuf]> {
    Some(dirs)
}

/// The default list as a run builds it from the lists kept in `dirs`.
fn default_list(dirs: &[PathBuf], keys: &Keys) -> Vec<String> {
    let lists: Vec<Checked> = kept::seen_in(at(dirs), keys, NOW_MS).into_iter().filter_map(|s| s.held.ok()).collect();
    let list = with_others(select_relays(None, None, &[]).unwrap(), kept::others_of(&lists, false));
    list.hosts.into_iter().map(|r| relay_name(&r)).collect()
}

#[test]
fn a_signed_list_of_a_trusted_key_names_hosts_outside_the_domain() {
    let (k, dirs) = (key(0x46), dirs("trusted"));
    let signed = sign(&k, &doc(7, "relay.example.org"));
    let taken = kept::take_in(at(&dirs), &signed, &trusting(&k), NOW_MS).unwrap();
    assert!(matches!(taken, Taken::Kept(_)), "{taken:?}");
    assert_eq!(taken.checked().by, "the test");
    assert_eq!(default_list(&dirs, &trusting(&k)), vec![DEFAULT_RELAY_HOST, "relay.example.org"]);
    // The same list again changes nothing.
    assert!(matches!(kept::take_in(at(&dirs), &signed, &trusting(&k), NOW_MS), Ok(Taken::Same(_))));
    // As /relays.json carries it, beside the pool.
    let body = serde_json::to_vec(&json!({ "pool": [], "signed": signed.to_value() })).unwrap();
    assert_eq!(Signed::of_body(&body), Some(Ok(signed.clone())));
    assert_eq!(Signed::of_body(br#"{"pool":[]}"#), None, "an unsigned /relays.json has no list");
}

#[test]
fn one_changed_byte_keeps_the_parent_domain_alone() {
    let (k, dirs) = (key(0x46), dirs("changed"));
    let signed = sign(&k, &doc(7, "relay.example.org"));
    let mut text = signed.clone();
    text.text = text.text.replace("relay.example.org", "relay.example.orh");
    let mut sig = signed.clone();
    sig.sig[17] ^= 0x01;
    for bad in [text, sig] {
        assert_eq!(check(&bad, &trusting(&k), NOW_S), Err(Refused::Signature(k.public())));
        assert!(kept::take_in(at(&dirs), &bad, &trusting(&k), NOW_MS).is_err());
    }
    assert_eq!(default_list(&dirs, &trusting(&k)), vec![DEFAULT_RELAY_HOST], "nothing was kept");
    // A list kept, then changed in the cache, holds no more.
    kept::take_in(at(&dirs), &signed, &trusting(&k), NOW_MS).unwrap();
    let file = dirs[0].join(kept::FILE);
    let changed = std::fs::read_to_string(&file).unwrap().replace("relay.example.org", "relay.example.orh");
    std::fs::write(&file, changed).unwrap();
    assert_eq!(default_list(&dirs, &trusting(&k)), vec![DEFAULT_RELAY_HOST]);
}

#[test]
fn an_old_not_after_keeps_the_parent_domain_alone() {
    let (k, dirs) = (key(0x46), dirs("ended"));
    let mut ended = doc(7, "relay.example.org");
    (ended.issued, ended.not_after) = (NOW_S - 10 * DAY, NOW_S - 1);
    let signed = sign(&k, &ended);
    assert_eq!(check(&signed, &trusting(&k), NOW_S), Err(Refused::Ended { not_after: NOW_S - 1 }));
    assert!(kept::take_in(at(&dirs), &signed, &trusting(&k), NOW_MS).is_err());
    assert_eq!(default_list(&dirs, &trusting(&k)), vec![DEFAULT_RELAY_HOST]);
    // A list kept that ends later holds until then, and no more after it.
    let live = sign(&k, &doc(8, "relay.example.org"));
    kept::take_in(at(&dirs), &live, &trusting(&k), NOW_MS).unwrap();
    let later = NOW_MS + 31 * DAY * 1000;
    let seen = kept::seen_in(at(&dirs), &trusting(&k), later);
    assert!(matches!(seen[0].held, Err((Some(_), Refused::Ended { .. }))), "{seen:?}");
    // One that lives longer than a key may sign for is refused.
    let mut long = doc(9, "relay.example.org");
    long.not_after = long.issued + MAX_LIFE_S + 1;
    assert_eq!(check(&sign(&k, &long), &trusting(&k), NOW_S), Err(Refused::TooLong));
}

#[test]
fn a_lower_serial_keeps_the_list_kept() {
    let (k, dirs) = (key(0x46), dirs("serial"));
    kept::take_in(at(&dirs), &sign(&k, &doc(5, "five.example.org")), &trusting(&k), NOW_MS).unwrap();
    let lower = kept::take_in(at(&dirs), &sign(&k, &doc(4, "four.example.org")), &trusting(&k), NOW_MS);
    assert_eq!(lower.unwrap_err(), Refused::Older { serial: 4, kept: 5 });
    assert_eq!(default_list(&dirs, &trusting(&k)), vec![DEFAULT_RELAY_HOST, "five.example.org"]);
    // A higher one takes its place.
    kept::take_in(at(&dirs), &sign(&k, &doc(6, "six.example.org")), &trusting(&k), NOW_MS).unwrap();
    assert_eq!(default_list(&dirs, &trusting(&k)), vec![DEFAULT_RELAY_HOST, "six.example.org"]);
}

#[test]
fn an_unknown_key_keeps_the_parent_domain_alone() {
    let (k, other, dirs) = (key(0x46), key(0x47), dirs("unknown"));
    let signed = sign(&other, &doc(7, "relay.example.org"));
    assert_eq!(check(&signed, &trusting(&k), NOW_S), Err(Refused::Untrusted(other.public())));
    assert!(kept::take_in(at(&dirs), &signed, &trusting(&k), NOW_MS).is_err());
    assert_eq!(default_list(&dirs, &trusting(&k)), vec![DEFAULT_RELAY_HOST]);
    // A key named by its fingerprint is trusted as the key itself.
    let print = other.public().fingerprint();
    let by_print = Keys::from_parts(Some(print.as_str()), Vec::new());
    assert_eq!(check(&signed, &by_print, NOW_S).unwrap().by, KEYS_ENV);
    // A list kept, then its key no longer trusted, holds no more; `none`
    // trusts no key, the settings' too.
    kept::take_in(at(&dirs), &signed, &by_print, NOW_MS).unwrap();
    assert_eq!(default_list(&dirs, &by_print), vec![DEFAULT_RELAY_HOST, "relay.example.org"]);
    assert_eq!(default_list(&dirs, &trusting(&k)), vec![DEFAULT_RELAY_HOST]);
    let none = Keys::from_parts(Some("none"), vec![(KeyName::Key(other.public()), "RelayKeys".into())]);
    assert!(none.is_empty());
    assert_eq!(default_list(&dirs, &none), vec![DEFAULT_RELAY_HOST]);
}

#[test]
fn a_token_of_the_environment_takes_no_other_deployment() {
    let k = key(0x46);
    let lists = vec![check(&sign(&k, &doc(7, "relay.example.org")), &trusting(&k), NOW_S).unwrap()];
    assert_eq!(kept::others_of(&lists, false), vec![relay("relay.example.org", 443)]);
    assert_eq!(kept::others_of(&lists, true), Vec::<Relay>::new(), "that token is the default deployment's");
}

#[test]
fn the_hosts_of_each_deployment_take_turns_and_the_defaults_own_are_left_out() {
    let k = key(0x46);
    let mut two = doc(7, "a1.example.org");
    two.deployments[0].hosts.extend([relay("a2.example.org", 443), relay("a3.example.org", 8443)]);
    two.deployments.push(Deployment {
        name: "other".into(),
        hosts: vec![relay("tcp-x.ssh.relay.ajam.dev", 443), relay("b1.example.net", 443), relay("b2.example.net", 443)],
    });
    let lists = vec![check(&sign(&k, &two), &trusting(&k), NOW_S).unwrap()];
    let shown: Vec<String> = kept::others_of(&lists, false).iter().map(relay_name).collect();
    assert_eq!(shown, vec!["a1.example.org", "a2.example.org", "b1.example.net", "a3.example.org:8443"]);
    assert_eq!(kept::MAX_OTHERS, 4);
}

#[test]
fn the_form_is_read_strictly() {
    let good = doc(7, "relay.example.org").to_text();
    assert_eq!(Doc::parse(&good).unwrap(), doc(7, "relay.example.org"));
    let cases = [
        good.replace("\"podssh-relays\":1", "\"podssh-relays\":2"),
        good.replace("\"serial\":7", "\"serial\":0"),
        good.replace("\"backup\"", "\"bad name\""),
        good.replace("\"relay.example.org\"", "\"not a host\""),
        good.replace("\"relay.example.org\"", "\"\""),
        "not json".to_string(),
        "x".repeat(MAX_DOC + 1),
    ];
    for bad in cases {
        assert!(Doc::parse(&bad).is_err(), "{bad}");
    }
    let mut twice = doc(7, "relay.example.org");
    twice.deployments.push(twice.deployments[0].clone());
    assert!(Doc::parse(&twice.to_text()).is_err(), "two deployments of one name");
    let wire = |v: Value| Signed::of_value(&v).is_err();
    assert!(wire(json!({ "doc": good, "key": "00", "sig": "AA==" })), "a key that is no key");
    assert!(wire(json!({ "doc": good, "key": key(1).public().hex(), "sig": "AAAA" })), "a short signature");
    assert!(wire(json!({ "doc": good, "key": key(1).public().hex() })), "no signature");
}

#[test]
fn a_deployment_and_keys_are_read_as_the_flags_give_them() {
    let d = parse_deployment("backup=relay.example.org, relay2.example.org:8443,relay.example.org").unwrap();
    assert_eq!((d.name.as_str(), d.shown()), ("backup", "relay.example.org, relay2.example.org:8443".to_string()));
    for bad in ["backup", "=relay.example.org", "bad name=relay.example.org", "backup=", "backup=not a host"] {
        assert!(parse_deployment(bad).is_err(), "{bad}");
    }
    let (a, b) = (key(1).public(), key(2).public());
    let keys = parse_keys(&format!("{}, {}", a.fingerprint(), b.hex())).unwrap();
    assert!(keys[0].matches(&a) && keys[1].matches(&b));
    assert!(parse_keys("none").unwrap().is_empty());
    assert!(parse_keys("SHA256:short").is_err());
}

/// Each key compiled in is a key, and is trusted as built in.
#[test]
fn the_keys_compiled_in_are_keys() {
    let keys = Keys::from_parts(None, Vec::new());
    for word in BUILT_IN {
        let name = KeyName::parse(word).unwrap_or_else(|| panic!("{word} is not a key"));
        if let KeyName::Key(key) = name {
            assert_eq!(keys.trusts(&key), Some("built in"));
        }
    }
}

#[test]
fn the_role_signs_again_each_day_with_a_higher_serial() {
    let k = key(0x48);
    let public = k.public();
    let deployments = vec![parse_deployment("backup=relay.example.org").unwrap()];
    let signer = Signer::new(k, deployments).unwrap();
    assert_eq!(signer.key(), public);
    let first = signer.current(NOW_S);
    assert_eq!(signer.current(NOW_S + 60), first, "one signature for a day");
    let hex = public.hex();
    let keys = Keys::from_parts(Some(hex.as_str()), Vec::new());
    let read = |v: &Value| check(&Signed::of_value(v).unwrap(), &keys, NOW_S + 2 * DAY).unwrap().doc;
    let next = signer.current(NOW_S + DAY);
    assert!(read(&next).serial > read(&first).serial);
    assert_eq!(read(&next).not_after, NOW_S + DAY + ROLE_LIFE_S);
    // A clock that went back still signs a higher serial.
    let back = signer.current(NOW_S - DAY);
    assert!(Doc::parse(&Signed::of_value(&back).unwrap().text).unwrap().serial > read(&next).serial);
    assert!(Signer::new(key(0x48), Vec::new()).is_err(), "a list of no deployment");
}
