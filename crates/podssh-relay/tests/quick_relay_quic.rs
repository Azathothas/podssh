//! The relay role behind a quick tunnel over QUIC (T-428): the edge's
//! `ConnectRequest` as the reference encoder's fixtures name its metadata
//! (`HttpMethod`, `HttpHost`, `HttpHeader:NAME`), and the bytes after it, on
//! one end of a pipe, as a QUIC stream of the edge carries them; the node's
//! `ConnectResponse` and what follows it on the other, read back with the
//! node's own reader of the metadata. A request of the role's, a WebSocket
//! to a target through the role, a body with its length, and a request
//! that would break its head, refused by the node itself.
#![cfg(all(feature = "quick", feature = "serve"))]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::quick::capnp;
use podssh_relay::quick::connect::{self, ConnectRequest, Kind};
use podssh_relay::quick::origin::Origin;
use podssh_relay::quick::origin_quic;
use podssh_relay::serve::behind::Behind;
use podssh_relay::serve::{self as role, Config, Mint};
use podssh_ws::frame::{self, Frame, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

const LIMIT: Duration = Duration::from_secs(20);
const NAME: &str = "podssh-test.trycloudflare.com";
const BANNER: &[u8] = b"SSH-2.0-babeld-5c1f8e2a\r\n";

fn cfg(mint: Mint) -> Arc<Config> {
    Arc::new(Config {
        version: "podssh test".into(),
        mint,
        tokens: role::tokens::Tokens::new([8; 32]),
        policy: role::policy::Policy { private: true, ..Default::default() },
        limits: Default::default(),
        pairs: Default::default(),
        answered: Default::default(),
        events: None,
        brake: Default::default(),
    })
}

/// A request of the edge for `path`, of `kind`, with the headers `fields`.
fn request(path: &str, kind: Kind, method: &str, fields: &[(&str, &str)]) -> ConnectRequest {
    let mut metadata = vec![("HttpMethod".to_string(), method.to_string()), ("HttpHost".to_string(), NAME.to_string())];
    metadata.extend(fields.iter().map(|(n, v)| (format!("{}{n}", connect::HEADER), v.to_string())));
    ConnectRequest { dest: format!("https://{NAME}{path}"), kind, metadata }
}

/// `request`, and `sent` after it, through the node's origin; the edge's
/// end of the stream, the answer's error and metadata, and the bytes read
/// past the answer.
async fn exchange(cfg: Arc<Config>, request: ConnectRequest, sent: &[u8]) -> (DuplexStream, ConnectRequest, Vec<u8>) {
    let origin: Arc<dyn Origin> = Arc::new(Behind::new(cfg, NAME, false));
    let (mut edge, node) = tokio::io::duplex(1 << 20);
    let (from_edge, to_edge) = tokio::io::split(node);
    tokio::spawn(async move { origin_quic::serve(origin, &request, from_edge, to_edge).await });
    edge.write_all(sent).await.unwrap();
    let mut got = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let len = loop {
        if got.len() > connect::PREAMBLE {
            if let Some(len) = capnp::frame_len(&got[connect::PREAMBLE..]).unwrap() {
                if got.len() >= connect::PREAMBLE + len {
                    break len;
                }
            }
        }
        let n = tokio::time::timeout(LIMIT, edge.read(&mut chunk)).await.expect("the answer in time").unwrap();
        assert!(n > 0, "the stream ended before the answer: {got:?}");
        got.extend_from_slice(&chunk[..n]);
    };
    assert_eq!(&got[..connect::PREAMBLE], &connect::preamble(), "a data stream's preamble");
    // A response read as a request: its error where `dest` is, and its
    // metadata where a request's is (`connect_tests.rs`).
    let end = connect::PREAMBLE + len;
    let answer = connect::read_request(&got[connect::PREAMBLE..end]).expect("the node's ConnectResponse");
    (edge, answer, got[end..].to_vec())
}

fn meta<'a>(answer: &'a ConnectRequest, key: &str) -> Option<&'a str> {
    answer.metadata.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
}

/// The rest of the stream, until the node ends it.
async fn rest(mut edge: DuplexStream, mut got: Vec<u8>) -> Vec<u8> {
    let read = tokio::time::timeout(LIMIT, edge.read_to_end(&mut got)).await.expect("the end in time");
    read.unwrap();
    got
}

#[tokio::test]
async fn a_request_of_the_role_s_gets_its_answer_in_the_metadata_and_its_body_after() {
    let (edge, answer, after) = exchange(cfg(Mint::Anyone), request("/health", Kind::Http, "GET", &[]), b"").await;
    assert!(answer.dest.is_empty(), "no error: {}", answer.dest);
    assert_eq!(meta(&answer, "HttpStatus"), Some("200"));
    assert_eq!(meta(&answer, "HttpHeader:content-type"), Some("application/json"));
    assert!(meta(&answer, "HttpHeader:connection").is_none(), "no header of one hop");
    let body = rest(edge, after).await;
    let length: usize = meta(&answer, "HttpHeader:content-length").unwrap().parse().unwrap();
    assert_eq!(body.len(), length);
    let health: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(health["contract"], "2026-10-03-r2");
}

#[tokio::test]
async fn a_body_with_its_length_reaches_the_role() {
    let request = request("/v1/mint", Kind::Http, "POST", &[("Content-Length", "2")]);
    let (edge, answer, after) = exchange(cfg(Mint::Anyone), request, b"{}").await;
    assert_eq!(meta(&answer, "HttpStatus"), Some("200"), "{answer:?}");
    let minted: serde_json::Value = serde_json::from_slice(&rest(edge, after).await).unwrap();
    assert_eq!(minted["scope"], "forward");
    assert!(minted["token"].as_str().is_some_and(|t| !t.is_empty()));
}

#[tokio::test]
async fn a_request_that_would_break_its_head_is_refused_by_the_node() {
    let request = request("/health", Kind::Http, "GET", &[("X-Relay-Token", "a\r\nX-Other: forged")]);
    let (edge, answer, after) = exchange(cfg(Mint::Anyone), request, b"").await;
    assert_eq!(meta(&answer, "HttpStatus"), Some("400"));
    assert!(!answer.dest.is_empty(), "the node says why");
    assert!(rest(edge, after).await.is_empty());
}

#[tokio::test]
async fn a_websocket_through_the_role_reads_the_target_s_first_line_and_carries_bytes_up() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        tcp.write_all(BANNER).await.unwrap();
        let (mut r, mut w) = tcp.split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });
    let cfg = cfg(Mint::Nobody);
    let (token, _) = cfg.tokens.mint(role::tokens::now_ms(), role::tokens::LIFETIME_MS);
    // RFC 6455's example key, whose accept is s3pPLMBiTxaQ9kYGzzhZRbK+xOo=.
    let fields = [
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("Sec-Websocket-Version", "13"),
        ("X-Relay-Token", token.as_str()),
    ];
    let request = request(&format!("/connect/127.0.0.1/{port}"), Kind::WebSocket, "GET", &fields);
    let (mut edge, answer, mut after) = exchange(cfg, request, b"").await;
    assert_eq!(meta(&answer, "HttpStatus"), Some("101"), "{answer:?}");
    assert_eq!(meta(&answer, "HttpHeader:sec-websocket-accept"), Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    // The role's frames, unmasked as a server writes them, as they are.
    let mut got = Vec::new();
    let mut chunk = vec![0u8; 4096];
    while got.len() < BANNER.len() {
        match frame::decode(&after, Role::Server).unwrap() {
            Some((frame, used)) => {
                after.drain(..used);
                got.extend_from_slice(&frame.payload);
            }
            None => {
                let n = tokio::time::timeout(LIMIT, edge.read(&mut chunk)).await.expect("a frame in time").unwrap();
                assert!(n > 0, "the stream ended");
                after.extend_from_slice(&chunk[..n]);
            }
        }
    }
    assert_eq!(got, BANNER);
    // The visitor's frame, masked, reaches the target, which echoes it.
    let up = Frame { fin: true, opcode: 0x2, payload: b"SSH-2.0-podssh_t428\r\n".to_vec() };
    edge.write_all(&frame::encode(&up, Role::Client, [3, 1, 4, 1])).await.unwrap();
    let mut echoed = Vec::new();
    while echoed.len() < up.payload.len() {
        match frame::decode(&after, Role::Server).unwrap() {
            Some((frame, used)) => {
                after.drain(..used);
                echoed.extend_from_slice(&frame.payload);
            }
            None => {
                let n = tokio::time::timeout(LIMIT, edge.read(&mut chunk)).await.expect("a frame in time").unwrap();
                assert!(n > 0, "the stream ended");
                after.extend_from_slice(&chunk[..n]);
            }
        }
    }
    assert_eq!(echoed, up.payload);
}
