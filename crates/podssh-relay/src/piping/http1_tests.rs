//! The HTTP/1.1 of the road against the bytes of answers as Node's and
//! hyper's servers frame them: a length, chunks with an extension and
//! trailers, a body to the close, and a body that is cut short.

use super::http1::{chunk, read_head, request, Answer, Framing, Length, Reader, LAST_CHUNK};

/// The whole body of `raw`, an answer's head and body, read in pieces.
async fn body_of(raw: &[u8]) -> (Answer, Result<Vec<u8>, String>, bool) {
    let mut io = raw;
    let mut buf = Vec::new();
    let answer = read_head(&mut io, &mut buf).await.expect("a head");
    let mut reader = Reader::new(io, buf, answer.framing);
    let body = reader.all(1 << 20).await;
    let finished = reader.finished();
    (answer, body, finished)
}

#[test]
fn a_request_names_its_body_s_length_or_its_chunks_and_a_get_names_none() {
    let get = String::from_utf8(request("GET", "ppng.io", "/abc", Length::None)).unwrap();
    assert!(get.starts_with("GET /abc HTTP/1.1\r\nHost: ppng.io\r\nUser-Agent: podssh/"), "{get}");
    assert!(get.ends_with("\r\n\r\n") && !get.contains("Content-") && !get.contains("Transfer-"), "{get}");
    let post = String::from_utf8(request("POST", "h:8080", "/p/abc", Length::Chunked)).unwrap();
    assert!(post.contains("\r\nTransfer-Encoding: chunked\r\n") && !post.contains("Content-Length"), "{post}");
    let whole = String::from_utf8(request("POST", "h", "/abc-3", Length::Fixed(5))).unwrap();
    assert!(whole.contains("\r\nContent-Length: 5\r\n") && !whole.contains("chunked"), "{whole}");
    assert_eq!(chunk(b"hello"), b"5\r\nhello\r\n");
    assert_eq!(chunk(&[0u8; 26])[..4], *b"1a\r\n");
    assert_eq!(LAST_CHUNK, b"0\r\n\r\n");
}

#[tokio::test]
async fn a_body_of_a_length_ends_at_its_length_and_keeps_its_connection() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";
    let (answer, body, finished) = body_of(raw).await;
    assert_eq!(answer, Answer { status: 200, framing: Framing::Length(5), keep: true });
    assert_eq!(body.unwrap(), b"hello");
    assert!(finished);
}

#[tokio::test]
async fn chunks_with_an_extension_and_trailers_come_whole_after_a_100_continue() {
    let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
        4;name=value\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nExpires: never\r\n\r\n";
    let (answer, body, finished) = body_of(raw).await;
    assert_eq!(answer.framing, Framing::Chunked);
    assert_eq!(body.unwrap(), b"Wikipedia in\r\n\r\nchunks.");
    assert!(finished);
}

#[tokio::test]
async fn a_body_to_the_close_ends_with_the_stream_and_keeps_no_connection() {
    let raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n[INFO] Waiting for 1 receiver(s)...\n";
    let (answer, body, _) = body_of(raw).await;
    assert_eq!((answer.framing, answer.keep), (Framing::UntilClose, false));
    assert_eq!(body.unwrap(), b"[INFO] Waiting for 1 receiver(s)...\n");
}

#[tokio::test]
async fn a_body_cut_short_or_with_a_bad_chunk_is_an_error() {
    for raw in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhello"[..],
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
    ] {
        let (_, body, finished) = body_of(raw).await;
        assert!(body.is_err() && !finished, "{:?}", String::from_utf8_lossy(raw));
    }
}

#[tokio::test]
async fn a_body_comes_piece_by_piece_as_its_chunks_come() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
    let mut io = &raw[..];
    let mut buf = Vec::new();
    let answer = read_head(&mut io, &mut buf).await.unwrap();
    let mut reader = Reader::new(io, buf, answer.framing);
    assert_eq!(reader.next().await.unwrap(), Some(b"abc".to_vec()));
    assert_eq!(reader.next().await.unwrap(), Some(b"de".to_vec()));
    assert_eq!(reader.next().await.unwrap(), None);
    assert_eq!(reader.next().await.unwrap(), None, "the end stays the end");
}

#[tokio::test]
async fn a_head_with_no_end_or_a_closed_connection_is_an_error() {
    let mut buf = Vec::new();
    assert!(read_head(&mut &b"HTTP/1.1 200 OK\r\n"[..], &mut buf).await.is_err());
    let long = format!("HTTP/1.1 200 OK\r\nX: {}\r\n", "a".repeat(20_000));
    let mut buf = Vec::new();
    assert!(read_head(&mut long.as_bytes(), &mut buf).await.unwrap_err().contains("16 KiB"));
    let mut buf = Vec::new();
    let answer = read_head(&mut &b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"[..], &mut buf).await.unwrap();
    assert!(!answer.keep, "HTTP/1.0 keeps no connection");
}
