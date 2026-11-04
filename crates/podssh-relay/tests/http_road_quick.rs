//! The HTTP road (T-319) to the relay role behind a quick tunnel's node,
//! through the stand-in edge of T-300 and its front (`quick_relay_harness`),
//! as a client reaches `https://NAME.trycloudflare.com`: the node takes each
//! request's body whole, 32 KiB at most, and passes an answer to the end of
//! the role's connection, so the role names the node's bound on a batch and
//! closes each connection after its answer. A session carries 20 MiB each way
//! with equal digests in the split form and in the serial form, after the
//! target's version line.
//!
//!     cargo test -p podssh-relay --features quick,serve,plain-ws --test http_road_quick
#![cfg(all(feature = "quick", feature = "serve", feature = "plain-ws"))]

mod http_road_harness;
mod quick_harness;
mod quick_relay_harness;

use http_road_harness::{each_way, open, raw, road, MIB};
use podssh_relay::http_road::client::End;
use podssh_relay::http_road::Form;
use podssh_relay::serve::{tokens, Mint};
use quick_relay_harness::{banner_target, Tunnel, BANNER, NAME};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_forms_carry_20_mib_each_way_through_a_quick_tunnel_s_node() {
    let tunnel = Tunnel::start(Mint::Anyone, false).await;
    let (token, _) = tunnel.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let target = banner_target().await;
    for (form, seed) in [(Form::Split, 11), (Form::Serial, 12)] {
        let opened = open(&road(tunnel.port, NAME), target, &token, Some(form)).await;
        assert_eq!(opened.form, form);
        let end = each_way(opened, BANNER, 20 * MIB, seed).await;
        assert_eq!(end, Some(End::Closed { code: 1000, reason: "target closed".into() }), "{form:?}");
    }
    assert!(tunnel.said("http open") && tunnel.said("http close 1000"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn behind_the_node_the_open_names_the_node_s_bound_on_a_batch() {
    let tunnel = Tunnel::start(Mint::Anyone, false).await;
    let (token, _) = tunnel.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let target = banner_target().await;
    let request = format!(
        "POST /v1/http/open/127.0.0.1/{target} HTTP/1.1\r\nHost: {NAME}\r\nX-Relay-Token: {token}\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let (status, text) = raw(tunnel.port, &request).await;
    assert_eq!(status, 200, "{text}");
    let doc: serde_json::Value = serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(doc["batch_max"], 32 * 1024, "{doc}");
    let id = doc["session"].as_str().unwrap();
    let key = doc["key"].as_str().unwrap();
    let close = format!(
        "POST /v1/http/s/{id}/close HTTP/1.1\r\nHost: {NAME}\r\nX-Session-Key: {key}\r\nContent-Length: 0\r\n\r\n"
    );
    assert_eq!(raw(tunnel.port, &close).await.0, 204);
}
