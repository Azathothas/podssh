//! The minimal HTTP/1.1 client used for minting tokens and for reading why an
//! upgrade was refused.

use podssh_ws::http::{decode_chunked, exchange, read_response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn chunked_bodies_decode_and_incomplete_ones_ask_for_more() {
    let full = b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n";
    assert_eq!(decode_chunked(full, 1024).unwrap().unwrap(), b"Wikipedia");
    assert_eq!(decode_chunked(&full[..10], 1024).unwrap(), None);
    assert_eq!(decode_chunked(b"4\r\nWiki\r\n0\r\n", 1024).unwrap(), None);
    assert!(decode_chunked(b"zz\r\n", 1024).is_err(), "a bad size is an error");
    assert!(decode_chunked(b"4\r\nWikiXX", 1024).is_err(), "a chunk must end in CRLF");
    assert!(decode_chunked(full, 4).is_err(), "the size cap applies");
}

/// The relay chooses each chunk's size: one near the largest number, after a
/// chunk or alone, under each cap, is refused and wraps nothing. The sums
/// that it passed overflowed: a panic in a build with overflow checks, and
/// in the release build a slice that ends before it starts, which aborts
/// (found by the fuzz target `http_chunked`, T-198).
#[test]
fn a_chunk_size_near_the_largest_number_is_refused() {
    let huge = format!("{:x}", usize::MAX);
    let less = format!("{:x}", usize::MAX - 1);
    for size in [&huge, &less] {
        for raw in [format!("1\r\na\r\n{size}\r\nxx\r\n0\r\n\r\n"), format!("{size}\r\nxx\r\n0\r\n\r\n")] {
            for max in [1024, usize::MAX] {
                assert!(decode_chunked(raw.as_bytes(), max).is_err(), "{raw:?} under {max}");
            }
        }
    }
}

#[tokio::test]
async fn a_content_length_body_is_read_exactly() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: b\r\n\r\nhello trailing";
    let r = read_response(&mut &raw[..], Vec::new(), 1024).await.unwrap();
    assert_eq!((r.status, r.reason.as_str(), r.body.as_slice()), (200, "OK", &b"hello"[..]));
    assert_eq!(r.header("x-a"), Some("b"));
    assert_eq!(r.header("X-A"), Some("b"), "header lookup ignores case");
}

#[tokio::test]
async fn a_chunked_body_is_decoded() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n2\r\n\":\r\n2\r\n1}\r\n0\r\n\r\n";
    let r = read_response(&mut &raw[..], Vec::new(), 1024).await.unwrap();
    assert_eq!(r.body, br#"{"a":1}"#);
}

#[tokio::test]
async fn a_body_without_framing_runs_to_the_end_of_the_stream() {
    let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nmissing or wrong token";
    let r = read_response(&mut &raw[..], Vec::new(), 1024).await.unwrap();
    assert_eq!(r.status, 403);
    assert_eq!(r.body_text(200), "missing or wrong token");
    assert_eq!(r.body_text(7), "missing…", "body_text cuts long bodies");
}

#[tokio::test]
async fn bytes_already_read_are_used_first() {
    let buffered = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 4\r\n\r\nde".to_vec();
    let r = read_response(&mut &b"ad"[..], buffered, 1024).await.unwrap();
    assert_eq!((r.status, r.body.as_slice()), (502, &b"dead"[..]));
}

#[tokio::test]
async fn no_content_statuses_have_no_body() {
    let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
    assert!(read_response(&mut &raw[..], Vec::new(), 1024).await.unwrap().body.is_empty());
}

#[tokio::test]
async fn oversized_and_truncated_bodies_are_errors() {
    let big = b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n";
    assert!(read_response(&mut &big[..], Vec::new(), 1024).await.is_err());
    let cut = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort";
    assert!(read_response(&mut &cut[..], Vec::new(), 1024).await.is_err());
    assert!(read_response(&mut &b"garbage\r\n\r\n"[..], Vec::new(), 1024).await.is_err());
}

#[tokio::test]
async fn exchange_writes_a_well_formed_request_and_reads_the_reply() {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut chunk = [0u8; 1024];
        while !seen.windows(2).any(|w| w == b"{}") {
            let n = server.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            seen.extend_from_slice(&chunk[..n]);
        }
        server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"token\":\"t\"}").await.unwrap();
        String::from_utf8(seen).unwrap()
    });
    let r = exchange(
        &mut client,
        "POST",
        "relay.example",
        "/v1/mint",
        &[("Content-Type", "application/json")],
        b"{}",
        1024,
    )
    .await
    .unwrap();
    assert_eq!(r.body, br#"{"token":"t"}"#);

    let request = peer.await.unwrap();
    assert!(request.starts_with("POST /v1/mint HTTP/1.1\r\n"), "{request}");
    for line in ["Host: relay.example", "Connection: close", "Content-Length: 2", "Content-Type: application/json"] {
        assert!(request.contains(&format!("\r\n{line}\r\n")), "missing {line:?} in {request}");
    }
    assert!(request.ends_with("\r\n\r\n{}"), "{request}");
}

#[tokio::test]
async fn a_header_with_a_line_break_is_refused_before_anything_is_sent() {
    let (mut client, _server) = tokio::io::duplex(1024);
    let err = exchange(&mut client, "POST", "h", "/", &[("X", "a\r\nInjected: 1")], b"", 1024).await.unwrap_err();
    assert!(err.to_string().contains("CR or LF"), "{err}");
}

/// A relay or proxy error body reaches the user's terminal through
/// `body_text`; escape sequences, BEL and a bare CR must not survive it.
#[test]
fn an_error_body_cannot_carry_terminal_controls() {
    let r = podssh_ws::http::Response {
        status: 403,
        reason: "Forbidden".into(),
        headers: Vec::new(),
        body: b"denied\x1b[2J\x07\r\nFAKE PROMPT$ ".to_vec(),
    };
    assert_eq!(r.body_text(200), "denied[2J FAKE PROMPT$");
}

/// A header shown in a line (a relay's Retry-After of 429, T-407) is made
/// safe as the body is, and cut.
#[test]
fn a_header_shown_in_a_line_cannot_carry_terminal_controls() {
    let r = podssh_ws::http::Response {
        status: 429,
        reason: "Too Many Requests".into(),
        headers: vec![("retry-after".into(), "30\x1b]0;owned\x07 then\x1b[2J more".into())],
        body: Vec::new(),
    };
    assert_eq!(r.header_text("Retry-After", 200).as_deref(), Some("30]0;owned then[2J more"));
    assert_eq!(r.header_text("retry-after", 4).as_deref(), Some("30]0…"));
    assert_eq!(r.header_text("date", 10), None);
}
