//! The private ranges of podssh's relay role (T-635, `--routes`), beside
//! `relay_serve_contract`: raw clients of the contract, as a client that
//! podssh did not shape opens one. A private target that a range holds is
//! dialed; one outside each gets the refusal of a role with no range, word
//! for word, so that a client reads nothing new, while the role's line keeps
//! the cause; a name whose each address a range holds is dialed; port 25
//! stays refused inside a range; `/trace` reads a target of a range.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::ranges::Range;
use podssh_relay::serve::{tokens, Mint};
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::session::RelaySession;
use podssh_ws::ConnectError;
use role_harness::{next, proxy, Role};

const LINE: &str = "SSH-2.0-inside-a-range\r\n";

/// The role with the ranges of `words`, and a token of its own.
async fn role_with(words: &[&str]) -> (Role, String) {
    let ranges = words.iter().map(|w| Range::strict(w).expect("a range")).collect();
    let role = Role::configured(Mint::Anyone, Policy { ranges, ..Policy::default() }, Default::default()).await;
    let (token, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    (role, token)
}

/// The answer of a refused upgrade: its status and body.
fn refusal(r: Result<RelaySession<tokio::net::TcpStream>, ConnectError>) -> (u16, String) {
    match r {
        Err(ConnectError::Refused { status, body }) => (status, body),
        Err(other) => panic!("{other}"),
        Ok(_) => panic!("the upgrade was taken"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_private_target_in_a_range_is_dialed_and_one_outside_gets_the_words_of_before() {
    let target = proxy::greeting(LINE).await;
    let (role, token) = role_with(&["127.0.0.1"]).await;
    let inside = role.socket(&format!("/connect/127.0.0.1/{target}"), &token).await;
    let inside = inside.expect("a target that a range holds");
    assert_eq!(next(&inside).await, Some((OPCODE_BINARY, LINE.as_bytes().to_vec())));
    // Outside each range: another loopback address and a private one, each
    // refused before any dial, as by a role with no range.
    let (plain, plain_token) = role_with(&[]).await;
    for host in ["127.0.0.2", "10.255.255.1"] {
        let path = format!("/connect/{host}/{target}");
        let (status, body) = refusal(role.socket(&path, &token).await);
        let before = refusal(plain.socket(&path, &plain_token).await);
        assert_eq!((status, &body), (before.0, &before.1), "{host}: the refusal of a role with no range");
        assert!(body.contains("not in the ALLOW list: this relay dials no address of it"), "{host}: {body}");
    }
    let events = role.events.lock().unwrap().clone();
    assert!(role.said("which is not a public address, nor in a range of --routes"), "{events:?}");
    // Port 25 is refused first, also inside a range.
    let (status, body) = refusal(role.socket("/connect/127.0.0.1/25", &token).await);
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("port 25 is refused"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_whose_each_address_a_range_holds_is_dialed() {
    let target = proxy::greeting(LINE).await;
    // Each address that `localhost` may give, on any host.
    let (role, token) = role_with(&["127.0.0.0/8", "::1"]).await;
    let named = role.socket(&format!("/connect/localhost/{target}"), &token).await;
    let named = named.expect("a name whose each address a range holds");
    assert_eq!(next(&named).await, Some((OPCODE_BINARY, LINE.as_bytes().to_vec())));
    // `/trace` reads it the same.
    let (status, body) = role.http("GET", &format!("/trace?target=localhost:{target}"), Some(token.as_str())).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("SSH-2.0-inside-a-range"), "{body}");
    // A role with no range refuses the same name.
    let (plain, plain_token) = role_with(&[]).await;
    let (status, body) = refusal(plain.socket(&format!("/connect/localhost/{target}"), &plain_token).await);
    assert_eq!(status, 403, "{body}");
}
