//! The pieces of wstunnel's protocol (T-441): the token against vectors
//! made by Python's hmac and json, which podssh did not write, from the
//! form that wstunnel's source gives; the URL, the secret file, the
//! request, and each answer of the server in its words.

use super::upgrade::{self, REFUSED_10, REFUSED_9};
use super::*;

/// The claims and the token of a tunnel to sshd.test:22 with the id of
/// zeros, as `json.dumps(..., separators=(",",":"))` and
/// `hmac.new(b"champignonfrais", ..., hashlib.sha256)` make them.
const CLAIMS_22: &str =
    r#"{"id":"00000000-0000-4000-8000-000000000000","p":{"Tcp":{"proxy_protocol":false}},"r":"sshd.test","rp":22}"#;
const TOKEN_22: &str =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMC\
     IsInAiOnsiVGNwIjp7InByb3h5X3Byb3RvY29sIjpmYWxzZX19LCJyIjoic3NoZC50ZXN0IiwicnAiOjIyfQ.\
     wzUcypCJQ483rcwsKtZ5r0wHNL9KNuZsO3b9iC4CBAQ";
/// The same for [::1]:2222, its id from the bytes 15 down to 0.
const TOKEN_V6: &str =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjBmMGUwZDBjLTBiMGEtNDkwOC04NzA2LTA1MDQwMzAyMDEwMC\
     IsInAiOnsiVGNwIjp7InByb3h5X3Byb3RvY29sIjpmYWxzZX19LCJyIjoiWzo6MV0iLCJycCI6MjIyMn0.\
     5PgyrOH56uoikZCXgKKExTePxJN5skqBaTDiu1jYpuU";

fn joined(text: &str) -> String {
    text.split_whitespace().collect()
}

#[test]
fn the_token_is_the_one_that_wstunnel_s_old_key_signs() {
    let id = uuid_text([0; 16]);
    assert_eq!(id, "00000000-0000-4000-8000-000000000000");
    assert_eq!(claims(&id, "sshd.test", 22), CLAIMS_22);
    assert_eq!(sign(CLAIMS_22), joined(TOKEN_22));
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = 15 - i as u8;
    }
    let id = uuid_text(bytes);
    assert_eq!(id, "0f0e0d0c-0b0a-4908-8706-050403020100");
    // An IPv6 host goes in brackets, as the server's Host::parse reads it.
    assert_eq!(sign(&claims(&id, "::1", 2222)), joined(TOKEN_V6));
    assert_eq!(host_claim("[::1]"), "[::1]");
    assert_eq!(host_claim("10.0.0.1"), "10.0.0.1");
    // A name with a quote stays one JSON string.
    assert!(claims(&id, "a\"b", 1).contains(r#""r":"a\"b""#));
}

#[test]
fn a_server_is_a_websocket_s_host_and_port_and_nothing_else() {
    let s = Server::parse("wss://wst.example.org").unwrap();
    assert_eq!((s.shown().as_str(), s.port(), s.tls()), ("wss://wst.example.org", 443, true));
    let plain = Server::parse("ws://127.0.0.1:8080/").unwrap();
    assert_eq!((plain.shown().as_str(), plain.tls(), plain.is_loopback()), ("ws://127.0.0.1:8080", false, true));
    assert!(Server::parse("wss://[::1]:8443").unwrap().is_loopback());
    let h2 = Server::parse("https://wst.example.org").unwrap_err();
    assert!(h2.contains("HTTP/2 transport") && h2.contains("wss://HOST"), "{h2}");
    assert!(Server::parse("wts://wst.example.org").unwrap_err().contains("WebTransport"));
    let path = Server::parse("wss://wst.example.org/my-secret").unwrap_err();
    assert!(path.contains("path-prefix") && !path.contains("my-secret"), "{path}");
    for bad in ["wss://wst.example.org/?k=v", "wss://u:p@wst.example.org", "tcp://h:1", "wst.example.org"] {
        assert!(Server::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_secret_file_gives_the_prefix_and_an_authorization() {
    let secret = "s3cr3t-prefix";
    let bare = Secret::parse(&format!("# the server's -r\n{secret}\n")).unwrap();
    assert_eq!((bare.prefix(), bare.authorization()), (secret, None));
    assert!(!format!("{bare:?}").contains(secret));
    let both = Secret::parse(&format!("path-prefix {secret}\ncredentials  alice:pw \n")).unwrap();
    // wstunnel's parse_http_credentials: Basic of the trimmed text.
    assert_eq!(both.authorization(), Some("Basic YWxpY2U6cHc="));
    let bearer = Secret::parse("authorization Bearer abc").unwrap();
    assert_eq!((bearer.prefix(), bearer.authorization()), (DEFAULT_PREFIX, Some("Bearer abc")));
    assert!(Secret::default().is_default() && Secret::parse("v1").unwrap().is_default());
    for (text, why) in [
        ("", "no line"),
        ("a b", "line 1: a line is"),
        (&format!("path-prefix {secret}\npath-prefix x") as &str, "line 2: a second path-prefix"),
        ("credentials a:b\nauthorization Bearer x", "line 2: a second credentials"),
        ("path-prefix a/b", "no / and no %"),
        ("path-prefix a%2Fb", "no / and no %"),
        ("authorization", "line 1: authorization has no value"),
    ] {
        let refused = Secret::parse(text).unwrap_err();
        assert!(refused.contains(why), "{text:?}: {refused}");
        assert!(!refused.contains(secret), "{refused}");
    }
}

#[test]
fn a_secret_goes_over_tls_or_to_this_host() {
    let secret = Secret::parse("path-prefix p").unwrap();
    assert!(check(&Server::parse("wss://h.example").unwrap(), &secret).is_ok());
    assert!(check(&Server::parse("ws://localhost:8080").unwrap(), &secret).is_ok());
    assert!(check(&Server::parse("ws://h.example").unwrap(), &Secret::default()).is_ok());
    let open = check(&Server::parse("ws://h.example:8080").unwrap(), &secret).unwrap_err();
    assert!(open.contains("give wss://"), "{open}");
}

#[test]
fn the_request_is_wstunnel_s_upgrade_with_the_token_and_the_secret() {
    let secret = Secret::parse("path-prefix pfx\ncredentials u:p").unwrap();
    let r = upgrade::request("wst.example:8443", &secret, "TOKEN", "dGhlIHNhbXBsZSBub25jZQ==");
    assert!(r.starts_with("GET /pfx/events HTTP/1.1\r\nHost: wst.example:8443\r\n"), "{}", r.as_str());
    assert!(r.contains("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"));
    assert!(r.contains("\r\nSec-WebSocket-Version: 13\r\n"));
    assert!(r.contains("\r\nSec-WebSocket-Protocol: v1, authorization.bearer.TOKEN\r\n"));
    assert!(r.contains("\r\nAuthorization: Basic dTpw\r\n") && r.ends_with("\r\n\r\n"));
    let plain = upgrade::request("h", &Secret::default(), "T", "k");
    assert!(plain.starts_with("GET /v1/events ") && !plain.to_ascii_lowercase().contains("authorization:"));
}

#[test]
fn a_refusal_is_said_in_the_words_of_its_version() {
    let ten = upgrade::words(400, "Bad Request", REFUSED_10);
    assert!(ten.starts_with("Invalid request; the words of wstunnel 10 and later"), "{ten}");
    let nine = upgrade::words(400, "Bad Request", REFUSED_9);
    assert!(nine.contains("wstunnel 9 and before") && nine.contains("9.0 or before"), "{nine}");
    let other = upgrade::words(502, "Bad Gateway", "");
    assert!(other.starts_with("Bad Gateway; not the answer of a wstunnel server"), "{other}");
    let evil = upgrade::words(400, "x", "a\u{1b}[2Jb");
    assert!(!evil.contains('\u{1b}'), "{evil:?}");
}

/// The answer `head` to an upgrade on a stream in memory: what `upgrade`
/// makes of it.
async fn answered(head: String) -> Result<Vec<u8>, WstunnelError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let _ = theirs.read(&mut buf).await;
        let _ = theirs.write_all(head.as_bytes()).await;
        theirs
    });
    let request = upgrade::request("h", &Secret::default(), "T", "dGhlIHNhbXBsZSBub25jZQ==");
    let result = upgrade::upgrade(ours, request.as_bytes(), "dGhlIHNhbXBsZSBub25jZQ==").await;
    drop(server.await);
    result.map(|(_, pending)| pending)
}

#[tokio::test]
async fn a_101_of_wstunnel_names_v1_and_another_is_no_wstunnel() {
    // RFC 6455's sample key and its accept value.
    let ok = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: v1\r\n\r\nSSH";
    assert_eq!(answered(ok.into()).await.unwrap(), b"SSH");
    let none = ok.replace("Sec-WebSocket-Protocol: v1\r\n", "");
    match answered(none).await.unwrap_err() {
        WstunnelError::NotWstunnel(why) => assert!(why.contains("no subprotocol") && why.contains("9.1 to 11")),
        other => panic!("{other:?}"),
    }
    let refused = "HTTP/1.1 400 Bad Request\r\ncontent-length: 15\r\n\r\nInvalid request".to_string();
    match answered(refused).await.unwrap_err() {
        WstunnelError::Refused { status: 400, words } => assert!(words.contains("wstunnel 10 and later"), "{words}"),
        other => panic!("{other:?}"),
    }
}
