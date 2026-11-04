//! Pairing by a short code (T-086), offline, at each mailbox that this host
//! runs on the loopback (`mailbox_harness`): podssh's relay role (with the
//! feature `serve`), and magic-wormhole's own mailbox server. Two podssh
//! ends of one code agree and move each part; a wrong code fails both ends
//! and spends the code; a second use, and a code past its life, find
//! nobody; a third end is refused while two hold the code; no line and no
//! `Debug` holds the code. A peer of magic-wormhole's own Python library and
//! podssh's finish the `pake` and `version` phases and a message each way,
//! either one giving the code, and a wrong code fails both. A code of the
//! net's invitation (T-616) taken by the pairing's command is told apart at
//! the version phase, with the command that takes it. Planted
//! (`scripts/plants/t086-*.patch`): a third side let in, the code said in a
//! line, a version that does not open taken; (`t616-kind-unchecked`) a
//! version of another kind taken.
#![cfg(all(feature = "pair", feature = "code"))]

mod cleanup;
mod mailbox_harness;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mailbox_harness::{mailboxes, nobody_there, Peer, LIMIT};
use podssh_relay::code::exchange::{self, Done, Offer};
use podssh_relay::code::mailbox::Mood;
use podssh_relay::code::run::{self, Ends, Given, Taken, Waits};
use podssh_relay::code::{self, words, Code, Failed};
use podssh_relay::identity::PublicKey;
use podssh_relay::pair::OperatorPart;
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use serde_json::{json, Value};
use zeroize::Zeroizing;

const NAME: &str = "0123456789abcdef0123456789abcdef";
// The repository's fixture form: a token with no digit but zeros.
const TOKEN: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";
const NODE: PublicKey = PublicKey([0x22; 32]);
const OPERATOR: PublicKey = PublicKey([0x11; 32]);

/// Each line that a run said.
type Said = Arc<Mutex<Vec<String>>>;

fn waits() -> Waits {
    // A taker at a mailbox that lists no nameplate waits `giver` for nobody.
    Waits { life: Duration::from_secs(60), giver: Duration::from_secs(5), step: Duration::from_secs(20) }
}

fn ends(mailboxes: Vec<WsUrl>, said: &Said) -> Ends {
    let said = said.clone();
    let say: code::Say = Arc::new(move |line: String| said.lock().unwrap().push(line));
    Ends { mailboxes, trust: Trust::Default, proxy: ProxyChoice::Direct, say }
}

fn offer() -> Offer {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let token = Zeroizing::new(TOKEN.to_string());
    let part = OperatorPart::checked("relay.example.org", NAME.into(), token, now + 3_600_000, now).unwrap();
    Offer { label: "lab".into(), node: NODE, part: Some(part) }
}

/// What a pairing of two podssh ends gave, and the code that the giver
/// showed.
struct Pairing {
    given: Result<Given, Failed>,
    taken: Result<Taken, Failed>,
    code: String,
}

/// A pairing at `mailboxes`, the taker typing `typed` of the code that the
/// giver showed.
async fn pairing(mailboxes: Vec<WsUrl>, said: &Said, typed: fn(&str) -> String) -> Pairing {
    let ends = ends(mailboxes, said);
    let offer = offer();
    let (shown_tx, shown_rx) = tokio::sync::oneshot::channel::<String>();
    let mut shown_tx = Some(shown_tx);
    let mut show = move |made: &Code, _: &str| {
        if let Some(tx) = shown_tx.take() {
            let _ = tx.send(made.for_terminal().to_string());
        }
    };
    let mut admit = |key: &PublicKey| Done { admitted: *key == OPERATOR, said: "in the test's allowlist".into() };
    let waits = waits();
    let giving = run::give(&ends, &waits, &offer, &mut show, &mut admit);
    let taking = async {
        let shown = shown_rx.await.expect("the giver showed a code");
        let code = Code::parse(&typed(&shown)).expect("a code");
        let mut check = |offer: &Offer| if offer.node == NODE { Ok(()) } else { Err("another node".to_string()) };
        (run::take(&ends, &waits, &code, &OPERATOR, &mut check).await, shown)
    };
    let (given, (taken, code)) = tokio::join!(giving, taking);
    Pairing { given, taken, code }
}

/// A taker alone of `shown` at `url`.
async fn take_only(url: &WsUrl, said: &Said, shown: &str) -> Result<Taken, Failed> {
    let code = Code::parse(shown).expect("a code");
    let mut check = |_: &Offer| Ok(());
    run::take(&ends(vec![url.clone()], said), &waits(), &code, &OPERATOR, &mut check).await
}

/// The code with its last word another of its list.
fn wrong(shown: &str) -> String {
    let (head, last) = shown.rsplit_once('-').expect("a word");
    let other = if last == words::ODD[0] { words::ODD[1] } else { words::ODD[0] };
    format!("{head}-{other}")
}

fn same(shown: &str) -> String {
    shown.to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn two_podssh_ends_of_one_code_agree_and_move_each_part() {
    for (name, url, _server) in mailboxes("agree").await {
        let said = Said::default();
        let p = pairing(vec![url.clone()], &said, same).await;
        let given = p.given.unwrap_or_else(|e| panic!("{name}: the giver: {e}"));
        let taken = p.taken.unwrap_or_else(|e| panic!("{name}: the taker: {e}"));
        assert_eq!(given.operator, OPERATOR, "{name}");
        assert!(given.done.admitted, "{name}");
        assert_eq!(given.mailbox, url.shown(), "{name}");
        assert_eq!((taken.offer.label.as_str(), taken.offer.node), ("lab", NODE), "{name}");
        let part = taken.offer.part.as_ref().expect("the operator's part");
        assert_eq!((part.name.as_str(), part.connect_token()), (NAME, TOKEN), "{name}");
        assert_eq!(part.relay.host, "relay.example.org", "{name}");
        assert_eq!(taken.done, Done { admitted: true, said: "in the test's allowlist".into() }, "{name}");
    }
}

#[tokio::test]
async fn a_wrong_code_fails_both_ends_and_spends_the_code() {
    for (name, url, _server) in mailboxes("wrong").await {
        let said = Said::default();
        let p = pairing(vec![url.clone()], &said, wrong).await;
        assert_eq!(p.given.err(), Some(Failed::WrongCode), "{name}: the giver");
        assert_eq!(p.taken.err(), Some(Failed::WrongCode), "{name}: the taker");
        // The right code, after the one failed exchange: nobody holds it.
        let again = take_only(&url, &said, &p.code).await;
        assert_eq!(again.err(), Some(Failed::Nobody), "{name}: the right code after a wrong one");
    }
}

#[tokio::test]
async fn a_second_use_of_a_code_finds_nobody() {
    for (name, url, _server) in mailboxes("second").await {
        let said = Said::default();
        let p = pairing(vec![url.clone()], &said, same).await;
        assert!(p.given.is_ok() && p.taken.is_ok(), "{name}: the first use");
        let again = take_only(&url, &said, &p.code).await;
        assert_eq!(again.err(), Some(Failed::Nobody), "{name}: the second use");
    }
}

#[tokio::test]
async fn a_code_past_its_life_finds_nobody() {
    for (name, url, _server) in mailboxes("life").await {
        let said = Said::default();
        let ends = ends(vec![url.clone()], &said);
        let short = Waits { life: Duration::from_secs(2), ..waits() };
        let mut shown = None;
        let mut show = |made: &Code, _: &str| shown = Some(made.for_terminal().to_string());
        let mut admit = |_: &PublicKey| Done { admitted: false, said: String::new() };
        let given = run::give(&ends, &short, &offer(), &mut show, &mut admit).await;
        assert_eq!(given.err(), Some(Failed::Expired(Duration::from_secs(2))), "{name}");
        let shown = shown.expect("the giver showed its code");
        assert_eq!(take_only(&url, &said, &shown).await.err(), Some(Failed::Nobody), "{name}: a code past its life");
    }
}

#[tokio::test]
async fn a_third_end_is_refused_while_two_hold_the_code() {
    for (name, url, _server) in mailboxes("third").await {
        let said = Said::default();
        let ends = ends(vec![url.clone()], &said);
        let versions = json!({ "podssh-test": 1 });
        let (mut giver, code) = run::opened(&ends, versions.clone()).await.expect("a code");
        let first = run::joined(&ends, &code, versions.clone(), &waits()).await;
        let mut first = first.unwrap_or_else(|e| panic!("{name}: the first taker: {e}"));
        match run::joined(&ends, &code, versions.clone(), &waits()).await {
            Err(Failed::Refused(why)) => assert!(why.contains("two ends hold this code"), "{name}: {why}"),
            other => panic!("{name}: a third end of the code was not refused: {:?}", other.err()),
        }
        // The two that hold it go on.
        assert!(giver.agree(LIMIT).await.unwrap(), "{name}: the giver hears the first taker");
        assert_eq!(giver.confirm(LIMIT).await.unwrap(), versions, "{name}");
        assert_eq!(first.confirm(LIMIT).await.unwrap(), versions, "{name}");
        giver.close(Mood::Happy).await;
        first.close(Mood::Happy).await;
    }
}

#[tokio::test]
async fn a_code_given_to_the_other_kind_s_command_is_told_apart_before_a_word() {
    for (name, url, _server) in mailboxes("kind").await {
        let said = Said::default();
        let ends = ends(vec![url.clone()], &said);
        let (shown_tx, shown_rx) = tokio::sync::oneshot::channel::<String>();
        let mut shown_tx = Some(shown_tx);
        let mut show = move |made: &Code, _: &str| {
            if let Some(tx) = shown_tx.take() {
                let _ = tx.send(made.for_terminal().to_string());
            }
        };
        let mut answer = |_: &[u8]| -> Result<Vec<Vec<u8>>, Failed> { Ok(Vec::new()) };
        let (invited, waits) = (br#"{"net": "home"}"#, waits());
        let giving = run::give_with(&ends, &waits, exchange::NET_INVITE, invited, &mut show, &mut answer);
        let taking = async {
            let code = Code::parse(&shown_rx.await.expect("the giver showed a code")).expect("a code");
            let mut check = |_: &Offer| Ok(());
            run::take(&ends, &waits, &code, &OPERATOR, &mut check).await
        };
        let (given, taken) = tokio::join!(giving, taking);
        let Err(Failed::Peer(why)) = taken else { panic!("{name}: the pairing's taker went on") };
        assert!(why.contains("one of podssh net invite NAME by podssh net join"), "{name}: {why}");
        match given {
            Err(Failed::Peer(why)) => {
                assert!(why.contains("runs podssh's pairing, not its invitation"), "{name}: {why}")
            }
            other => panic!("{name}: the invitation's giver went on: {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_code_is_in_no_line_and_no_debug() {
    for (name, url, _server) in mailboxes("quiet").await {
        let said = Said::default();
        // A mailbox where nothing listens first, so that each end has lines.
        let p = pairing(vec![nobody_there(), url.clone()], &said, same).await;
        let (given, taken) = (p.given.expect("the giver"), p.taken.expect("the taker"));
        let lines = said.lock().unwrap().clone();
        assert!(lines.len() >= 2, "{name}: each end said the mailbox that failed: {lines:?}");
        let secret: Vec<&str> = p.code.split('-').skip(1).collect();
        assert_eq!(secret.len(), code::WORDS);
        let debug = format!("{given:?} {:?} {:?}", Code::parse(&p.code).unwrap(), taken.done);
        for word in secret {
            for line in lines.iter().chain([&debug]) {
                assert!(!line.contains(word), "{name}: a word of the code in {line:?}");
            }
        }
    }
}

#[tokio::test]
async fn a_peer_of_magic_wormholes_python_library_takes_podssh_s_code() {
    for (name, url, _server) in mailboxes("py-take").await {
        let said = Said::default();
        let ends = ends(vec![url.clone()], &said);
        let (mut hole, code) = run::opened(&ends, json!({ "podssh-test": 1 })).await.expect("a code");
        let Some(mut peer) = Peer::start(&url, code::APPID, "take") else { return };
        peer.type_code(code.for_terminal());
        assert!(hole.agree(LIMIT).await.unwrap(), "{name}: the peer's pake: {}", peer.said());
        let theirs = hole.confirm(LIMIT).await.unwrap_or_else(|e| panic!("{name}: {e}: {}", peer.said()));
        assert_eq!(theirs, json!({ "podssh-test": 1 }), "{name}");
        hole.send(b"from podssh").await.unwrap();
        assert_eq!(hole.receive(LIMIT).await.unwrap(), b"from python", "{name}");
        hole.close(Mood::Happy).await;
        assert_eq!(peer.after("versions").as_deref(), Some(r#"{"podssh-test": 1}"#), "{name}: {}", peer.said());
        assert_eq!(peer.after("got"), Some(hex(b"from podssh")), "{name}: {}", peer.said());
    }
}

// The test waits on the peer's line with no await; the role, in this
// process, needs a worker of its own meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn podssh_takes_a_code_that_magic_wormholes_python_library_gives() {
    for (name, url, _server) in mailboxes("py-give").await {
        let said = Said::default();
        let ends = ends(vec![url.clone()], &said);
        let Some(mut peer) = Peer::start(&url, code::APPID, "give") else { return };
        let typed = peer.after("code").unwrap_or_else(|| panic!("{name}: no code: {}", peer.said()));
        let code = Code::parse(&typed).expect("magic-wormhole's code is podssh's form");
        assert_eq!(code.words(), 3, "{name}");
        let joined = run::joined(&ends, &code, json!({ "podssh-test": 1 }), &waits()).await;
        let mut hole = joined.unwrap_or_else(|e| panic!("{name}: {e}: {}", peer.said()));
        let theirs: Value = hole.confirm(LIMIT).await.unwrap();
        assert_eq!(theirs, json!({ "podssh-test": 1 }), "{name}");
        hole.send(b"from podssh").await.unwrap();
        assert_eq!(hole.receive(LIMIT).await.unwrap(), b"from python", "{name}");
        hole.close(Mood::Happy).await;
        assert_eq!(peer.after("got"), Some(hex(b"from podssh")), "{name}: {}", peer.said());
    }
}

#[tokio::test]
async fn a_peer_of_magic_wormholes_python_library_with_a_wrong_code_fails_both_ends() {
    for (name, url, _server) in mailboxes("py-wrong").await {
        let said = Said::default();
        let ends = ends(vec![url.clone()], &said);
        let (mut hole, code) = run::opened(&ends, json!({ "podssh-test": 1 })).await.expect("a code");
        let Some(mut peer) = Peer::start(&url, code::APPID, "take") else { return };
        peer.type_code(&wrong(code.for_terminal()));
        assert!(hole.agree(LIMIT).await.unwrap(), "{name}: the peer's pake: {}", peer.said());
        assert_eq!(hole.confirm(LIMIT).await.err(), Some(Failed::WrongCode), "{name}");
        assert_eq!(peer.after("wrong").as_deref(), Some(""), "{name}: {}", peer.said());
    }
}
