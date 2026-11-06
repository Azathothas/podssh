use super::*;

#[test]
fn a_server_is_https_or_wss_and_http_only_to_this_host() {
    let s = Server::parse("https://chisel.example.org").unwrap();
    assert!(s.tls());
    assert_eq!((s.host(), s.port(), s.target()), ("chisel.example.org", 443, "/"));
    assert_eq!(s.shown(), "https://chisel.example.org");
    let s = Server::parse("wss://chisel.example.org:8443/tunnel").unwrap();
    assert_eq!((s.port(), s.target()), (8443, "/tunnel"));
    assert_eq!(s.shown(), "https://chisel.example.org:8443/tunnel");
    let local = Server::parse("http://127.0.0.1:8080").unwrap();
    assert!(!local.tls() && local.is_loopback());
    let why = Server::parse("http://chisel.example.org").unwrap_err();
    assert!(why.contains("in the clear"), "{why}");
    let why = Server::parse("ftp://chisel.example.org").unwrap_err();
    assert!(why.contains("https://"), "{why}");
}

#[test]
fn the_request_names_the_subprotocol_and_its_target() {
    let r = upgrade::request("chisel.example.org", "/tunnel", "dGhlIHNhbXBsZSBub25jZQ==");
    assert!(r.starts_with("GET /tunnel HTTP/1.1\r\n"), "{r}");
    assert!(r.contains("\r\nSec-WebSocket-Protocol: chisel-v3\r\n"), "{r}");
    assert!(r.contains("\r\nHost: chisel.example.org\r\n"), "{r}");
    assert!(r.ends_with("\r\n\r\n"));
}

#[test]
fn a_404_not_found_is_read_as_chisel_s_words() {
    let words = upgrade::words(404, "Not Found", "Not found");
    assert!(words.starts_with("Not found; "), "{words}");
    assert!(words.contains("chisel-v3"), "{words}");
    let other = upgrade::words(403, "Forbidden", "");
    assert!(other.contains("a server in front of it"), "{other}");
}

#[tokio::test]
async fn a_101_with_no_subprotocol_is_taken_as_chisel_s() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let accept = crate::handshake::accept_key(key);
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \
         {accept}\r\n\r\nafter"
    );
    let (ours, mut theirs) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut got = vec![0u8; 1024];
        let _ = theirs.read(&mut got).await.unwrap();
        theirs.write_all(answer.as_bytes()).await.unwrap();
        theirs
    });
    let request = upgrade::request("h", "/", key);
    let (_stream, pending) = upgrade::upgrade(ours, request.as_bytes(), key).await.unwrap();
    assert_eq!(pending, b"after");
    let _ = server.await;
}
