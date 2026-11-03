//! The probes of T-325 behind a quick tunnel's node, through the stand-in
//! edge of T-300 and its front (`quick_relay_harness`), as `podssh doctor
//! --stream https://NAME.trycloudflare.com` asks them: a drip's bytes pass
//! the node at their moments; a body comes to the role whole, as the node
//! takes one before it passes it, and one past the node's 32 KiB gets the
//! node's 413; and the role's `/relays.json` there names the node's own
//! limits, so that a client says them as the node's, not the path's.
#![cfg(all(feature = "quick", feature = "serve", feature = "plain-ws"))]

mod quick_harness;
mod quick_relay_harness;

use std::time::Duration;

use podssh_relay::serve::Mint;
use quick_relay_harness::{http, Tunnel, LIMIT, NAME};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// A request through the front, and the time of each read of its answer
/// with the body's bytes by then.
async fn timed(port: u16, head: &str) -> (String, Vec<(Duration, usize)>) {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(head.as_bytes()).await.unwrap();
    let started = Instant::now();
    let (mut got, mut reads, mut buf) = (Vec::new(), Vec::new(), [0u8; 4096]);
    loop {
        let n = tokio::time::timeout(LIMIT, tcp.read(&mut buf)).await.expect("an answer in time").unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
        let body = got.windows(4).position(|w| w == b"\r\n\r\n").map_or(0, |end| got.len() - end - 4);
        reads.push((started.elapsed(), body));
    }
    (String::from_utf8_lossy(&got).into_owned(), reads)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_drip_passes_the_node_at_its_moments() {
    let tunnel = Tunnel::start(Mint::Anyone, false).await;
    let head = format!("GET /v1/probe/drip?duration=2&numbytes=5&delay=0 HTTP/1.1\r\nHost: {NAME}\r\n\r\n");
    let (text, reads) = timed(tunnel.port, &head).await;
    assert!(text.starts_with("HTTP/1.1 200 ") && text.ends_with("\r\n\r\n*****"), "{text}");
    let first = reads.iter().find(|(_, body)| *body >= 1).unwrap().0;
    let last = reads.iter().find(|(_, body)| *body >= 5).unwrap().0;
    // Each byte went at its moment, so the five came over the 2 s.
    assert!(last.saturating_sub(first) >= Duration::from_millis(1500), "{reads:?}");
}

/// The node takes a body whole: the role says one part; past the node's
/// cap, the node's own 413 before the role sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_comes_whole_and_past_the_node_s_cap_gets_its_413() {
    let tunnel = Tunnel::start(Mint::Anyone, false).await;
    let (status, body) = http(tunnel.port, "POST", "/v1/probe/anything", NAME, &[b'p'; 4096]).await;
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("the parts' JSON");
    assert_eq!(doc["bytes"], 4096);
    assert_eq!(doc["parts"].as_array().map(Vec::len), Some(1), "{doc}");
    // Under the stand-in edge's window, so that the whole body goes.
    let (status, _) = http(tunnel.port, "POST", "/v1/probe/anything", NAME, &[b'p'; 40 * 1024]).await;
    assert_eq!(status, 413, "the node's BODY_MAX");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_role_s_relays_json_names_the_node_s_limits_behind_it() {
    let tunnel = Tunnel::start(Mint::Anyone, false).await;
    let (status, body) = http(tunnel.port, "GET", "/relays.json", NAME, b"").await;
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("the document's JSON");
    let probe = &doc["limits"]["probe"];
    assert_eq!(probe["behind"], "the node of a quick tunnel", "{doc}");
    assert_eq!((&probe["body"], &probe["body_max_bytes"]), (&serde_json::json!("whole"), &serde_json::json!(32768)));
    assert_eq!(probe["quiet_max_ms"], 60_000);
}
