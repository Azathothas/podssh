//! The tests of the net's relay members (T-617), with test keys made here and
//! a request that a test answers: a list at the member's host is taken by
//! the member's key alone, and each member is asked once a day, whatever it
//! answered.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use super::super::signed::{sign, Deployment, Doc};
use super::*;
use crate::identity::Identity;

/// 2026-11-02, in seconds and in milliseconds.
const NOW_S: i64 = 1_793_577_600;
const NOW_MS: i64 = NOW_S * 1000;
const HOUR_MS: i64 = 3600 * 1000;

/// A test key, made here from a fixed seed: no key of anyone's.
fn key(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn trusting(keys: &[&Identity]) -> Keys {
    let named = keys.iter().map(|k| (KeyName::Key(k.public()), "the test".to_string())).collect();
    Keys::from_parts(None, named)
}

/// The member `lab` of the net `home`, whose role is at `relay-a.example.org`
/// and whose key is `identity`'s.
fn lab(identity: &Identity) -> Member {
    Member {
        name: "lab".into(),
        net: "home".into(),
        key: KeyName::Key(identity.public()),
        host: Relay { host: "relay-a.example.org".into(), port: 8443 },
    }
}

/// A `/relays.json` body with a list of one deployment, signed by `by`.
fn body(by: &Identity, serial: u64) -> Vec<u8> {
    let hosts = vec![Relay { host: "relay-b.example.org".into(), port: 443 }];
    let doc = Doc {
        serial,
        issued: NOW_S - 3600,
        not_after: NOW_S + 30 * 86_400,
        deployments: vec![Deployment { name: "backup".into(), hosts }],
    };
    serde_json::to_vec(&json!({ "pool": [], "signed": sign(by, &doc).to_value() })).unwrap()
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
    let dir = std::env::temp_dir().join(format!("podssh-members-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Dirs(vec![dir])
}

fn at(dirs: &[PathBuf]) -> Option<&[PathBuf]> {
    Some(dirs)
}

#[test]
fn a_list_at_the_member_s_host_is_taken_by_the_member_s_key() {
    let (k, dirs) = (key(0x51), dirs("taken"));
    let taken = take_from(at(&dirs), &lab(&k), &body(&k, 7), &trusting(&[&k]), NOW_MS).unwrap();
    assert!(matches!(taken, Taken::Kept(_)), "{taken:?}");
    assert_eq!(taken.checked().doc.deployments[0].name, "backup");
    // Kept as each list is, so that the default list takes its hosts.
    let held = kept::seen_in(at(&dirs), &trusting(&[&k]), NOW_MS);
    assert!(held.len() == 1 && held[0].held.is_ok(), "{held:?}");
    let again = take_from(at(&dirs), &lab(&k), &body(&k, 7), &trusting(&[&k]), NOW_MS);
    assert!(matches!(again, Ok(Taken::Same(_))), "{again:?}");
    // A member named by its key's fingerprint, as `net add` takes one.
    let by_print = Member { key: KeyName::parse(&k.public().fingerprint()).unwrap(), ..lab(&k) };
    assert!(take_from(at(&dirs), &by_print, &body(&k, 8), &trusting(&[&k]), NOW_MS).is_ok());
}

#[test]
fn a_list_of_another_key_is_not_the_member_s_even_when_trusted() {
    let (k, other, dirs) = (key(0x51), key(0x52), dirs("another"));
    let why = take_from(at(&dirs), &lab(&k), &body(&other, 7), &trusting(&[&k, &other]), NOW_MS).unwrap_err();
    let said = format!(
        "its list is signed by {}, not by the member's key {}",
        other.public().fingerprint(),
        k.public().fingerprint()
    );
    assert_eq!(why, said);
    assert!(kept::seen_in(at(&dirs), &trusting(&[&k, &other]), NOW_MS).is_empty(), "nothing was kept");
}

#[test]
fn no_list_a_changed_byte_and_no_trust_take_nothing() {
    let (k, dirs) = (key(0x51), dirs("refused"));
    let none = take_from(at(&dirs), &lab(&k), br#"{"pool":[]}"#, &trusting(&[&k]), NOW_MS).unwrap_err();
    assert!(none.contains("carries no signed list"), "{none}");
    let changed = String::from_utf8(body(&k, 7)).unwrap().replace("relay-b.example.org", "relay-b.example.orh");
    let why = take_from(at(&dirs), &lab(&k), changed.as_bytes(), &trusting(&[&k]), NOW_MS).unwrap_err();
    assert!(why.contains("does not verify"), "{why}");
    // `PODSSH_RELAY_KEYS=none` trusts no key, the net's too.
    let off = Keys::from_parts(Some("none"), vec![(KeyName::Key(k.public()), "the test".into())]);
    let why = take_from(at(&dirs), &lab(&k), &body(&k, 7), &off, NOW_MS).unwrap_err();
    assert!(why.contains("does not trust"), "{why}");
    assert!(kept::seen_in(at(&dirs), &trusting(&[&k]), NOW_MS).is_empty(), "nothing was kept");
}

#[test]
fn a_member_is_due_once_a_day() {
    let ask = |asked_ms: i64| Ask { host: "h".into(), key: "k".into(), asked_ms, serial: None, why: None };
    assert!(due(None, NOW_MS), "never asked");
    assert!(!due(Some(&ask(NOW_MS)), NOW_MS));
    assert!(!due(Some(&ask(NOW_MS - 23 * HOUR_MS)), NOW_MS));
    assert!(due(Some(&ask(NOW_MS - 24 * HOUR_MS)), NOW_MS), "a day after");
    assert!(due(Some(&ask(NOW_MS + HOUR_MS)), NOW_MS), "an ask from ahead of a clock that went back");
}

#[tokio::test]
async fn each_member_is_asked_once_a_day_whatever_it_answered() {
    let (k, down, dirs) = (key(0x51), key(0x53), dirs("daily"));
    let mut dead = lab(&down);
    dead.host = Relay { host: "relay-c.example.org".into(), port: 443 };
    let members = [lab(&k), dead];
    let keys = trusting(&[&k, &down]);
    let calls = AtomicUsize::new(0);
    let answer = |host: Relay, _: Duration| {
        calls.fetch_add(1, Ordering::SeqCst);
        let up = host.host == "relay-a.example.org";
        let k = key(0x51);
        async move {
            if up {
                Ok(body(&k, 7))
            } else {
                Err("connection refused".to_string())
            }
        }
    };
    assert_eq!(ask_due_with(at(&dirs), &members, &keys, NOW_MS, answer).await, 1, "one list newly kept");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "each member asked");
    let asks = load(at(&dirs));
    let of = |m: &Member| asks.of(m).cloned().unwrap();
    assert_eq!((of(&members[0]).serial, of(&members[0]).why), (Some(7), None));
    assert_eq!((of(&members[1]).serial, of(&members[1]).why.as_deref()), (None, Some("connection refused")));
    // Within the day: neither is asked again, the one that failed neither.
    let later = NOW_MS + 23 * HOUR_MS;
    assert_eq!(ask_due_with(at(&dirs), &members, &keys, later, answer).await, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "no member asked twice in a day");
    // A day after, each is asked again; the same list is kept already.
    let next = NOW_MS + 25 * HOUR_MS;
    assert_eq!(ask_due_with(at(&dirs), &members, &keys, next, answer).await, 0, "the list kept already");
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(load(at(&dirs)).of(&members[0]).map(|a| a.asked_ms), Some(next));
}

#[tokio::test]
async fn an_ask_is_kept_before_it_is_made() {
    let (k, dirs) = (key(0x51), dirs("first"));
    let members = [lab(&k)];
    let seen = std::sync::Mutex::new(None);
    let answer = |_: Relay, _: Duration| {
        // What the file holds while the ask runs: the ask, with no answer.
        *seen.lock().unwrap() = load(at(&dirs)).of(&members[0]).cloned();
        async { Err("cut".to_string()) }
    };
    ask_due_with(at(&dirs), &members, &trusting(&[&k]), NOW_MS, answer).await;
    let during = seen.lock().unwrap().clone().expect("the ask was kept first");
    assert_eq!((during.asked_ms, during.serial, during.why), (NOW_MS, None, None));
}

#[test]
fn the_file_keeps_its_newest_asks_alone() {
    let mut asks = Asks::default();
    for i in 0..(MAX_ASKS as i64 + 4) {
        asks.put(Ask { host: format!("h{i}"), key: "k".into(), asked_ms: i, serial: None, why: None });
    }
    assert_eq!(asks.asks.len(), MAX_ASKS);
    assert!(asks.asks.iter().all(|a| a.asked_ms >= 4), "the oldest went first");
    // One ask for each host and key: a new one takes the old one's place.
    asks.put(Ask { host: "h5".into(), key: "k".into(), asked_ms: 99, serial: Some(1), why: None });
    assert_eq!(asks.asks.iter().filter(|a| a.host == "h5").count(), 1);
}
