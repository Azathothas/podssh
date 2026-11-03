//! A pair of podssh's relay role whose connect token takes one upgrade
//! alone (T-226): `POST /v1/pair?once=1` says so, and its connect token is
//! refused at its second upgrade and at the status, while the node's token
//! stays; a pair of before takes each upgrade; `/relays.json` offers it.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod role_harness;

use role_harness::Role;
use serde_json::Value;

/// A new pair of the role's, as its answer gives it.
async fn pair(role: &Role, path: &str) -> Value {
    let (status, body) = role.http("POST", path, None).await;
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).expect("JSON")
}

fn field<'a>(pair: &'a Value, name: &str) -> &'a str {
    pair[name].as_str().expect("a field of the pair")
}

#[tokio::test]
async fn a_connect_token_of_one_use_is_refused_at_its_second_upgrade() {
    let role = Role::start().await;
    let made = pair(&role, "/v1/pair?once=1").await;
    assert_eq!(made["once"], true, "the answer says that its token takes one upgrade");
    let (name, connect) = (field(&made, "name"), field(&made, "connect_token"));
    let (status, _) = role.http("GET", &format!("/v1/status/{name}"), Some(connect)).await;
    assert_eq!(status, 200, "the status before the upgrade spends nothing");
    let path = format!("/v1/connect/{name}");
    if let Err(e) = role.socket(&path, connect).await {
        panic!("the first upgrade: {e}");
    }
    assert!(role.socket(&path, connect).await.is_err(), "the second upgrade of a token of one use");
    let (status, body) = role.http("GET", &format!("/v1/status/{name}"), Some(connect)).await;
    assert_eq!((status, body.contains("reverse: forbidden")), (403, true), "the status after its use: {body}");
    assert!(role.socket(&format!("/v1/node/{name}"), field(&made, "node_token")).await.is_ok(), "the node's token");
}

#[tokio::test]
async fn a_pair_of_before_takes_each_upgrade_and_the_role_offers_one_of_once() {
    let role = Role::start().await;
    let made = pair(&role, "/v1/pair").await;
    assert!(made.get("once").is_none(), "the contract's answer, with no word of once");
    let path = format!("/v1/connect/{}", field(&made, "name"));
    for n in 0..2 {
        assert!(role.socket(&path, field(&made, "connect_token")).await.is_ok(), "upgrade {n}");
    }
    let (status, body) = role.http("GET", "/relays.json", None).await;
    let doc: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!((status, &doc["reverse"]["pair_once"]), (200, &Value::Bool(true)), "{body}");
}
