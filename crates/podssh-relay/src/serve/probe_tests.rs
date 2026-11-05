//! The probes of T-325 on a pipe, on a clock that tokio holds: a drip's
//! bytes at their moments, a body's parts with their times, the refusals,
//! the query of go-httpbin, and the limits that `/relays.json` names, the
//! node's own behind a quick tunnel.

use std::sync::Arc;

use podssh_ws::http::request::parse_request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::tokens::Tokens;
use super::super::{serve_connection, Config, Mint};
use super::*;

fn head(text: &str) -> Request {
    parse_request(text.as_bytes()).unwrap()
}

/// What came on `client` until its end, and the time of each read, from
/// `started`, with the bytes of the body that had come by then.
async fn read_timed(client: &mut tokio::io::DuplexStream, started: Instant) -> (String, Vec<(Duration, usize)>) {
    let (mut got, mut reads, mut buf) = (Vec::new(), Vec::new(), [0u8; 4096]);
    loop {
        let n = client.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
        let body = got.windows(4).position(|w| w == b"\r\n\r\n").map_or(0, |end| got.len() - end - 4);
        reads.push((started.elapsed(), body));
    }
    (String::from_utf8(got).unwrap(), reads)
}

/// When the body's byte `k` came: the first read after which it was there.
fn moment(reads: &[(Duration, usize)], k: usize) -> Duration {
    reads.iter().find(|(_, body)| *body > k).map(|(at, _)| *at).unwrap()
}

fn near(at: Duration, ms: u64) -> bool {
    at.as_millis().abs_diff(u128::from(ms)) <= 10
}

#[test]
fn a_drip_takes_go_httpbin_s_query_and_its_defaults() {
    let d = drip_of("/v1/probe/drip").unwrap();
    assert_eq!(d, Drip { duration: Duration::from_secs(2), delay: Duration::from_secs(2), bytes: 10, code: 200 });
    let d = drip_of("/v1/probe/drip?duration=1.5&numbytes=4&delay=500ms&code=504").unwrap();
    assert_eq!((d.duration, d.delay), (Duration::from_millis(1500), Duration::from_millis(500)));
    assert_eq!((d.bytes, d.code), (4, 504));
    for bad in ["numbytes=0", "numbytes=65537", "duration=-1", "duration=x", "code=99", "duration=590&delay=11"] {
        assert!(drip_of(&format!("/v1/probe/drip?{bad}")).is_err(), "{bad}");
    }
    assert_eq!(parse_duration("1m30s"), Some(Duration::from_secs(90)));
    assert_eq!(parse_duration("250ms"), Some(Duration::from_millis(250)));
    assert_eq!(parse_duration("2"), Some(Duration::from_secs(2)));
    for bad in ["", "s", "2x", "NaN", "inf", "1e300", "-2s"] {
        assert_eq!(parse_duration(bad), None, "{bad}");
    }
    // go-httpbin's pause: the duration over the gaps, rounded up.
    assert_eq!(pause_of(Duration::from_secs(2), 5), Duration::from_millis(500));
    assert_eq!(pause_of(Duration::from_secs(1), 4), Duration::from_nanos(333_333_334));
    assert_eq!(pause_of(Duration::from_secs(3), 1), Duration::from_secs(3));
}

/// The head and the first byte at once, each later byte at its own moment,
/// the last at the drip's duration.
#[tokio::test(start_paused = true)]
async fn a_drip_sends_each_byte_at_its_moment() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let asked = head("GET /v1/probe/drip?duration=2&numbytes=5&delay=0 HTTP/1.1\r\nHost: r\r\n\r\n");
    let started = Instant::now();
    tokio::spawn(request(server, asked, Vec::new()));
    let (text, reads) = read_timed(&mut client, started).await;
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n") && text.contains("Content-Length: 5\r\n"), "{text}");
    assert!(text.ends_with("\r\n\r\n*****"), "{text}");
    for (k, ms) in [0, 500, 1000, 1500, 2000].into_iter().enumerate() {
        assert!(near(moment(&reads, k), ms), "byte {k}: {reads:?}");
    }
}

/// A delay holds the head, as go-httpbin's does.
#[tokio::test(start_paused = true)]
async fn a_delay_holds_the_head() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let asked = head("GET /v1/probe/drip?duration=0&numbytes=1&delay=3 HTTP/1.1\r\nHost: r\r\n\r\n");
    let started = Instant::now();
    tokio::spawn(request(server, asked, Vec::new()));
    let (text, reads) = read_timed(&mut client, started).await;
    assert!(text.ends_with("\r\n\r\n*"), "{text}");
    assert!(near(reads[0].0, 3000), "{reads:?}");
}

/// A body sent in four parts half a second apart is answered with the four,
/// each with its time from the head.
#[tokio::test(start_paused = true)]
async fn a_body_is_answered_with_when_each_part_came() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let asked = head("POST /v1/probe/anything HTTP/1.1\r\nHost: r\r\nContent-Length: 4096\r\n\r\n");
    tokio::spawn(request(server, asked, Vec::new()));
    for _ in 0..4 {
        client.write_all(&[b'p'; 1024]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (text, _) = read_timed(&mut client, Instant::now()).await;
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    let doc: Value = serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(doc["bytes"], 4096);
    let parts = doc["parts"].as_array().unwrap();
    assert_eq!(parts.len(), 4, "{doc}");
    for (part, ms) in parts.iter().zip([0u64, 500, 1000, 1500]) {
        let from = part["from_ms"].as_u64().unwrap();
        assert!(from.abs_diff(ms) <= 10 && part["bytes"] == 1024, "{doc}");
    }
}

/// Reads that come together are one part; past the parts shown, each later
/// read joins the last.
#[test]
fn reads_close_together_are_one_part() {
    let mut parts = Parts::default();
    parts.add(Duration::ZERO, 10);
    parts.add(Duration::from_millis(30), 10);
    parts.add(Duration::from_millis(70), 10);
    parts.add(Duration::from_millis(500), 5);
    let want = [
        Part { from: Duration::ZERO, to: Duration::from_millis(70), bytes: 30 },
        Part { from: Duration::from_millis(500), to: Duration::from_millis(500), bytes: 5 },
    ];
    assert_eq!(parts.parts(), want);
    let mut many = Parts::default();
    for n in 0..100u64 {
        many.add(Duration::from_secs(n), 1);
    }
    assert_eq!(many.parts().len(), PARTS_SHOWN);
    assert_eq!(many.parts().last().unwrap().bytes, 100 - PARTS_SHOWN as u64 + 1);
}

/// A body past the role's own cap gets 413 before any byte of it is sent,
/// one with no length 411, and another method 405 with what to use.
#[tokio::test(start_paused = true)]
async fn a_body_past_the_cap_or_with_no_length_is_refused_at_once() {
    let cases = [
        (format!("POST /v1/probe/anything HTTP/1.1\r\nHost: r\r\nContent-Length: {}\r\n\r\n", BODY_MAX + 1), "413"),
        ("POST /v1/probe/anything HTTP/1.1\r\nHost: r\r\nTransfer-Encoding: chunked\r\n\r\n".into(), "411"),
        ("GET /v1/probe/anything HTTP/1.1\r\nHost: r\r\n\r\n".into(), "405"),
        ("POST /v1/probe/drip HTTP/1.1\r\nHost: r\r\nContent-Length: 0\r\n\r\n".into(), "405"),
    ];
    for (text, status) in cases {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(request(server, head(&text), Vec::new()));
        let (answer, _) = read_timed(&mut client, Instant::now()).await;
        assert!(answer.starts_with(&format!("HTTP/1.1 {status} ")), "{text}: {answer}");
    }
}

/// At most so many probes at once, each turn given back when it ends.
#[test]
fn a_turn_is_given_back_when_its_probe_ends() {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let held: Vec<Turn> = (0..3).map_while(|_| Turn::take(&COUNT, 3)).collect();
    assert_eq!(held.len(), 3);
    assert!(Turn::take(&COUNT, 3).is_none(), "a fourth");
    drop(held);
    assert!(Turn::take(&COUNT, 3).is_some(), "each turn came back");
}

#[test]
fn the_limits_name_what_the_role_does_itself() {
    let own = limits();
    assert_eq!((&own["body"], &own["body_max_bytes"]), (&json!("streamed"), &json!(BODY_MAX)));
    assert_eq!(own["quiet_max_ms"], 600_000);
    assert!(own.get("behind").is_none(), "{own}");
}

/// Behind a quick tunnel's node, the node's own limits on what it passes.
#[cfg(feature = "quick")]
#[tokio::test]
async fn behind_a_node_the_limits_are_the_node_s() {
    let behind = behind_node(async { limits() }).await;
    assert_eq!(behind["behind"], "the node of a quick tunnel");
    assert_eq!((&behind["body"], &behind["body_max_bytes"]), (&json!("whole"), &json!(32 * 1024)));
    assert_eq!(behind["quiet_max_ms"], 60_000);
    assert_eq!(limits()["body"], "streamed", "outside the node's request");
}

fn cfg() -> Arc<Config> {
    Arc::new(Config {
        version: "test".into(),
        mint: Mint::Anyone,
        tokens: Tokens::new([5; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Default::default(),
        pairs: Default::default(),
        resumes: Default::default(),
        answered: Default::default(),
        brake: Default::default(),
        usage: Default::default(),
        events: None,
    })
}

/// The role routes the probes, needing no token, and names their limits in
/// `/relays.json`.
#[tokio::test(start_paused = true)]
async fn the_role_serves_the_probes_and_names_their_limits() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(serve_connection(server, cfg()));
    client.write_all(b"GET /v1/probe/drip?duration=1&numbytes=3 HTTP/1.1\r\nHost: r\r\n\r\n").await.unwrap();
    let (text, _) = read_timed(&mut client, Instant::now()).await;
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n") && text.ends_with("\r\n\r\n***"), "{text}");
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(serve_connection(server, cfg()));
    client.write_all(b"GET /relays.json HTTP/1.1\r\nHost: r\r\n\r\n").await.unwrap();
    let (text, _) = read_timed(&mut client, Instant::now()).await;
    let doc: Value = serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(doc["limits"]["probe"]["body_max_bytes"], BODY_MAX, "{doc}");
    assert!(super::super::serves("/v1/probe/drip"), "a quick tunnel's node gives the path to the role");
}
