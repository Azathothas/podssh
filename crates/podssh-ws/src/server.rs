//! The server's side of the opening handshake (T-368), for `podssh pipe
//! ws-listen:`: the checks of RFC 6455 section 4.2.1 on a request that
//! `http::request` read, the 101 of section 4.2.2, and the session that
//! writes frames as a server does. No subprotocol and no extension is
//! chosen, so a client that offered one gets none, as the RFC allows.
//! A request with no key opens raw bytes where the caller asks for that
//! (T-645), for a client of WebTunnel's shape; the relay role never does.

use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::WRITE_TIMEOUT;
use crate::handshake;
use crate::http::request::{self, Request};
use crate::session::RelaySession;

/// An upgrade that is refused: its status, its words and its headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub status: u16,
    pub why: String,
    pub headers: Vec<(&'static str, &'static str)>,
}

impl Refused {
    /// The answer, after which the connection closes.
    pub fn answer(&self) -> Vec<u8> {
        request::refusal(self.status, &self.why, &self.headers)
    }
}

fn refused<T>(status: u16, why: &str, headers: Vec<(&'static str, &'static str)>) -> Result<T, Refused> {
    Err(Refused { status, why: why.into(), headers })
}

/// What a good upgrade opens: frames by RFC 6455, with the key that the
/// accept answers, or raw bytes for a client that sent no key, as a client
/// of WebTunnel's shape (T-645).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upgrade {
    Frames(String),
    Raw,
}

/// The key of a client's upgrade, once it is one that RFC 6455 section 4.2.1
/// takes: GET, HTTP/1.1, a Host, `Upgrade: websocket`, `Connection:
/// Upgrade`, version 13 and a key of 16 bytes. A request with an `Origin` is
/// a browser's, and is refused (403): a page that the user opens could else
/// reach the other side of the pipe, which no program of the user's needs.
pub fn check_upgrade(head: &Request) -> Result<String, Refused> {
    opening(head)?;
    let key = keyed(head)?;
    no_origin(head)?;
    Ok(key)
}

/// [`check_upgrade`], or the raw form of a request with no key (T-645), for
/// a listener whose user asked for it: the method, the Host and the two
/// tokens as there; then the key decides, before the version, as a client
/// of WebTunnel's shape sends neither. A key takes the version and the
/// key's checks (a key that is there but not 16 bytes stays 400: a broken
/// client is not carried raw); no key is the raw form. An `Origin` is
/// refused in both, as a page could else reach the other side.
pub fn check_upgrade_or_raw(head: &Request) -> Result<Upgrade, Refused> {
    opening(head)?;
    let upgrade = if head.has("sec-websocket-key") { Upgrade::Frames(keyed(head)?) } else { Upgrade::Raw };
    no_origin(head)?;
    Ok(upgrade)
}

/// GET, HTTP/1.1 that names its Host, and the two tokens of an upgrade.
fn opening(head: &Request) -> Result<(), Refused> {
    if head.method != "GET" {
        return refused(405, "a WebSocket opens with GET", vec![("Allow", "GET")]);
    }
    if head.minor < 1 || !head.has("host") {
        return refused(400, "a WebSocket opens with a request of HTTP/1.1 that names its Host", vec![]);
    }
    if !asks_upgrade(head) {
        let headers = vec![("Upgrade", "websocket"), ("Connection", "Upgrade")];
        return refused(426, "this is a WebSocket: Upgrade: websocket and Connection: Upgrade", headers);
    }
    Ok(())
}

/// Version 13 and a key of 16 bytes: the key.
fn keyed(head: &Request) -> Result<String, Refused> {
    if head.header("sec-websocket-version") != Some("13") {
        return refused(426, "this server speaks version 13 of RFC 6455", vec![("Sec-WebSocket-Version", "13")]);
    }
    let key = head.header("sec-websocket-key").unwrap_or_default();
    let bytes = base64::engine::general_purpose::STANDARD.decode(key).map(|k| k.len()).unwrap_or(0);
    if bytes != 16 {
        return refused(400, "Sec-WebSocket-Key is not 16 bytes in base64", vec![]);
    }
    Ok(key.to_string())
}

/// No `Origin`: a request with one is a browser's.
fn no_origin(head: &Request) -> Result<(), Refused> {
    if head.has("origin") {
        return refused(403, "a request with an Origin is a browser's, which this pipe does not serve", vec![]);
    }
    Ok(())
}

/// Whether a request asks for a WebSocket at all: `Upgrade: websocket` and
/// `Connection: Upgrade`. One that does not is a browser's visit or another
/// protocol's, which `ws-listen:`'s `--cover` may answer with a page (T-639).
pub fn asks_upgrade(head: &Request) -> bool {
    head.has_token("upgrade", "websocket") && head.has_token("connection", "upgrade")
}

/// The answer that opens the session (RFC 6455 section 4.2.2).
pub fn switching(key: &str) -> Vec<u8> {
    let accept = handshake::accept_key(key);
    let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n";
    format!("{head}Sec-WebSocket-Accept: {accept}\r\n\r\n").into_bytes()
}

/// The answer that opens raw bytes (T-645): 101 with the two headers and no
/// accept, as a WebTunnel server answers and its client checks.
pub fn switching_raw() -> Vec<u8> {
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".to_vec()
}

/// The session of a client whose upgrade was answered, `pending` the bytes
/// that came after its request: frames written unmasked, and only masked
/// ones taken (RFC 6455 section 5.1); an unmasked one closes with 1002.
pub fn session<S>(stream: S, pending: Vec<u8>, idle: Option<Duration>) -> RelaySession<S>
where
    S: AsyncRead + AsyncWrite,
{
    RelaySession::new(stream, pending, idle, WRITE_TIMEOUT).as_server().naming("the client")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(extra: &str) -> Request {
        let text = format!(
            "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
        );
        request::parse_request(text.as_bytes()).unwrap()
    }

    #[test]
    fn the_upgrade_of_rfc6455_section_1_3_opens_with_its_accept() {
        let key = check_upgrade(&head("")).unwrap();
        let answer = String::from_utf8(switching(&key)).unwrap();
        assert!(answer.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{answer}");
        assert!(answer.contains("\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), "{answer}");
        assert!(!answer.to_ascii_lowercase().contains("sec-websocket-protocol"), "{answer}");
        let offered = check_upgrade(&head("Sec-WebSocket-Protocol: chat\r\nConnection: keep-alive\r\n"));
        assert!(offered.is_ok(), "a subprotocol offered is answered with none");
    }

    #[test]
    fn an_upgrade_that_rfc6455_refuses_gets_its_status() {
        let status = |text: &str| check_upgrade(&request::parse_request(text.as_bytes()).unwrap()).unwrap_err().status;
        let ok = "Host: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n";
        let key = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
        assert_eq!(status(&format!("POST / HTTP/1.1\r\n{ok}{key}\r\n")), 405);
        assert_eq!(status(&format!("GET / HTTP/1.0\r\n{ok}{key}\r\n")), 400);
        assert_eq!(status("GET / HTTP/1.1\r\nHost: h\r\n\r\n"), 426);
        assert_eq!(status(&format!("GET / HTTP/1.1\r\n{}{key}\r\n", ok.replace(": 13", ": 8"))), 426);
        assert_eq!(status(&format!("GET / HTTP/1.1\r\n{ok}Sec-WebSocket-Key: c2hvcnQ=\r\n\r\n")), 400);
        assert_eq!(status(&format!("GET / HTTP/1.1\r\n{ok}\r\n")), 400);
        assert_eq!(status(&format!("GET / HTTP/1.1\r\n{ok}{key}Origin: https://a.example\r\n\r\n")), 403);
        let refused = check_upgrade(&head("Origin: null\r\n")).unwrap_err();
        assert!(String::from_utf8(refused.answer()).unwrap().starts_with("HTTP/1.1 403 Forbidden: "));
    }

    /// A visit asks for no upgrade, and neither does a request with one of the
    /// two tokens alone; any case and a list hold them (T-639).
    #[test]
    fn a_visit_asks_for_no_upgrade() {
        let asks = |text: &str| asks_upgrade(&request::parse_request(text.as_bytes()).unwrap());
        assert!(asks("GET / HTTP/1.1\r\nHost: h\r\nUpgrade: WebSocket\r\nConnection: keep-alive, upgrade\r\n\r\n"));
        assert!(!asks("GET / HTTP/1.1\r\nHost: h\r\nAccept: text/html\r\n\r\n"));
        assert!(!asks("GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n"));
        assert!(!asks("GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"));
    }

    /// The request of podssh's WebTunnel client, with no key and no version
    /// (T-645): the raw form where the caller asks for it, 426 where it does
    /// not; a key keeps each check of a framed upgrade, and an `Origin` is
    /// 403 either way.
    #[test]
    fn a_request_with_no_key_opens_raw_bytes_where_its_caller_asks() {
        let settings = [("url".to_string(), "http://bridge.example/secret-path".to_string())];
        let webtunnel = crate::webtunnel::request(&crate::webtunnel::Args::parse(&settings).unwrap());
        let parse = |text: &str| request::parse_request(text.as_bytes()).unwrap();
        let keyless = parse(&webtunnel);
        assert!(!keyless.has("sec-websocket-key") && !keyless.has("sec-websocket-version"), "{webtunnel}");
        assert_eq!(check_upgrade_or_raw(&keyless), Ok(Upgrade::Raw));
        assert_eq!(check_upgrade(&keyless).unwrap_err().status, 426, "the framed check is unchanged");
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert_eq!(check_upgrade_or_raw(&head("")), Ok(Upgrade::Frames(key.to_string())));
        let status = |text: String| check_upgrade_or_raw(&parse(&text)).unwrap_err().status;
        let base = webtunnel.trim_end_matches("\r\n").to_string();
        assert_eq!(status(format!("{base}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: c2hvcnQ=\r\n\r\n")), 400);
        assert_eq!(status(format!("{base}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key:\r\n\r\n")), 400);
        assert_eq!(status(format!("{base}\r\nSec-WebSocket-Key: {key}\r\n\r\n")), 426, "a key takes the version");
        assert_eq!(status(format!("{base}\r\nOrigin: https://page.example\r\n\r\n")), 403);
        assert_eq!(check_upgrade_or_raw(&head("Origin: null\r\n")).unwrap_err().status, 403);
        assert_eq!(status(webtunnel.replacen("GET ", "POST ", 1)), 405);
        assert_eq!(status(webtunnel.replace("Upgrade: websocket\r\n", "")), 426);
        assert_eq!(status(webtunnel.replace("Host: bridge.example\r\n", "")), 400);
        let answer = String::from_utf8(switching_raw()).unwrap();
        assert_eq!(answer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        assert_eq!(crate::webtunnel::check_answer(&answer), Ok(()), "podssh's WebTunnel client takes it");
    }
}
