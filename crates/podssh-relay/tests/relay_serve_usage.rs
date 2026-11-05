//! The relay role's counts of each key (T-636), through the role as a
//! client that podssh did not shape reaches it: a key mints by its
//! signature of the role's challenge (T-448), and each session of
//! `/connect/` to a stand-in target on the loopback is charged to that key
//! at its end, each way apart. A key past its budget for today is refused
//! before the dial, on each road of the forward path, and the target sees
//! no connection; another key's budget is its own; and the role's
//! keepalives, and a client's empty frames, charge nothing.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::identity::Identity;
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::usage::{Totals, Usage};
use podssh_relay::serve::{Limits, Mint};
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::ConnectError;
use role_harness::{closed, next, Role, LIMIT};

/// A list of the keys of `seeds`, in a private scratch file, removed when
/// the test ends, pass or fail: the gate counts what tests leave.
struct Keys {
    dir: PathBuf,
    path: PathBuf,
}

impl Keys {
    fn of(tag: &str, seeds: &[u8]) -> Keys {
        let dir = std::env::temp_dir().join(format!("podssh-usage-{}-{tag}", std::process::id()));
        podssh_relay::cache::private_dir(&dir).unwrap();
        let path = dir.join("allow");
        let lines: String = seeds.iter().map(|&seed| format!("{} the key of seed {seed}\n", print(seed))).collect();
        std::fs::write(&path, lines).unwrap();
        Keys { dir, path }
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn print(seed: u8) -> String {
    Identity::from_seed(&[seed; 32]).public().fingerprint()
}

/// The role that mints for the keys of `keys`, dials the loopback, and
/// counts by `usage`.
async fn role(keys: &Keys, limits: Limits, usage: Usage) -> Role {
    let policy = Policy { private: true, ..Policy::default() };
    Role::metered(Mint::Keys(keys.path.clone()), policy, limits, usage).await
}

/// A token of the role's for the key of `seed`, as podssh's client mints
/// one with a key: the contract's `{}`, then the key's proof of the role's
/// challenge, signed for the `Host` that it sends.
async fn mint_by_key(role: &Role, seed: u8) -> String {
    let (status, body) = role.http_body("POST", "/v1/mint", None, "{}").await;
    assert_eq!(status, 401, "a challenge: {body}");
    let asked: serde_json::Value = serde_json::from_str(&body).expect("the challenge's JSON");
    let challenge = asked["challenge"].as_str().expect("a challenge");
    let proof = podssh_relay::keyed::proof(&Identity::from_seed(&[seed; 32]), "127.0.0.1", "/v1/mint", challenge);
    let (status, body) = role.http_body("POST", "/v1/mint", None, std::str::from_utf8(&proof).unwrap()).await;
    assert_eq!(status, 200, "a token: {body}");
    let minted: serde_json::Value = serde_json::from_str(&body).expect("the token's JSON");
    minted["token"].as_str().expect("a token").to_string()
}

/// A target on the loopback that sends back what it gets, then closes at
/// its client's end; its connections counted.
async fn echo() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = accepted.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut from, mut to) = tcp.split();
                let _ = tokio::io::copy(&mut from, &mut to).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut to).await;
            });
        }
    });
    (port, accepted)
}

/// One session of `/connect/` to `port` with `token`: `sent` up, each byte
/// of it back, then the client's Close; the role's Close.
async fn session(role: &Role, port: u16, token: &str, sent: &[u8]) -> (Option<u16>, String) {
    let socket = role.socket(&format!("/connect/127.0.0.1/{port}"), token).await.expect("a session");
    socket.send_binary(sent).await.unwrap();
    let mut back = Vec::new();
    while back.len() < sent.len() {
        match next(&socket).await {
            Some((OPCODE_BINARY, bytes)) => back.extend_from_slice(&bytes),
            other => panic!("before the echo came: {other:?}"),
        }
    }
    assert_eq!(back, sent);
    socket.send_close(1000, "").await.unwrap();
    closed(&socket).await
}

/// The totals of the key of `seed`, once they hold `sessions` sessions,
/// `LIMIT` at most: a session is charged at its end, after its Close.
async fn charged(role: &Role, seed: u8, sessions: u64) -> Totals {
    let deadline = Instant::now() + LIMIT;
    loop {
        let totals = role.cfg.usage.totals(&print(seed));
        if let Some(totals) = totals.filter(|t| t.today.sessions >= sessions) {
            return totals;
        }
        assert!(Instant::now() < deadline, "the key of seed {seed} was not charged {sessions}: {totals:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The status and body of a refused upgrade.
fn refused<T>(upgrade: Result<T, ConnectError>) -> (u16, String) {
    match upgrade {
        Err(ConnectError::Refused { status, body }) => (status, body),
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the upgrade was taken"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_past_its_budget_is_refused_before_the_dial_and_another_key_counts_apart() {
    let keys = Keys::of("budget", &[1, 2]);
    let usage = Usage::open(Some(64), None).unwrap();
    let said = Arc::new(Mutex::new(Vec::<String>::new()));
    let lines = said.clone();
    usage.say_to(Arc::new(move |line: &str| lines.lock().unwrap().push(line.to_string())));
    let role = role(&keys, Limits::default(), usage).await;
    let (port, accepted) = echo().await;
    let one = mint_by_key(&role, 1).await;
    assert_eq!(session(&role, port, &one, &[7u8; 40]).await, (Some(1000), "target closed".to_string()));
    let today = charged(&role, 1, 1).await.today;
    assert_eq!((today.up, today.down, today.sessions), (40, 40, 1), "each way apart, once");
    let spent = format!("usage: the key {} spent its quota of 64 bytes for today", print(1));
    assert!(said.lock().unwrap().iter().any(|l| l.starts_with(&spent)), "{:?}", said.lock().unwrap());

    // 80 of 64 bytes: each road of the forward path refuses the key before
    // the dial, with a new token of it too.
    let (status, body) = refused(role.socket(&format!("/connect/127.0.0.1/{port}"), &one).await);
    assert_eq!((status, body.trim_end()), (403, "forward: this key's quota of 64 bytes for today is spent"));
    let again = mint_by_key(&role, 1).await;
    let (status, body) = refused(role.socket(&format!("/v1/layer/127.0.0.1/{port}"), &again).await);
    assert_eq!((status, body.trim_end()), (403, "layer: this key's quota of 64 bytes for today is spent"));
    let (status, body) = role.http("POST", &format!("/v1/http/open/127.0.0.1/{port}"), Some(again.as_str())).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("http: this key's quota of 64 bytes for today is spent"), "{body}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "the target saw no connection of a refused key");

    // Another key's budget is its own, and the refusals charged nothing.
    let two = mint_by_key(&role, 2).await;
    session(&role, port, &two, b"twelve bytes").await;
    let today = charged(&role, 2, 1).await.today;
    assert_eq!((today.up, today.down, today.sessions), (12, 12, 1));
    assert_eq!(role.cfg.usage.totals(&print(1)).unwrap().today.sessions, 1, "no refusal is a session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keepalives_and_empty_frames_charge_nothing() {
    let keys = Keys::of("keepalive", &[3]);
    let limits = Limits { keepalive: Duration::from_millis(100), ..Limits::default() };
    let role = role(&keys, limits, Usage::default()).await;
    let (port, _) = echo().await;
    let token = mint_by_key(&role, 3).await;
    let socket = role.socket(&format!("/connect/127.0.0.1/{port}"), &token).await.expect("a session");
    for _ in 0..3 {
        socket.send_binary(&[]).await.unwrap();
    }
    // The role's keepalives wait for the client meanwhile, an empty frame
    // at each look at the limits.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    socket.send_binary(b"hello").await.unwrap();
    let (mut back, mut kept) = (Vec::new(), 0);
    while back.len() < 5 {
        match next(&socket).await {
            Some((OPCODE_BINARY, bytes)) if bytes.is_empty() => kept += 1,
            Some((OPCODE_BINARY, bytes)) => back.extend_from_slice(&bytes),
            other => panic!("before the echo came: {other:?}"),
        }
    }
    assert!(kept >= 1, "a keepalive came before the echo");
    assert_eq!(back, b"hello");
    socket.send_close(1000, "").await.unwrap();
    let _ = closed(&socket).await;
    let today = charged(&role, 3, 1).await.today;
    assert_eq!((today.up, today.down, today.sessions), (5, 5, 1), "keepalives and empty frames are no byte");
}
