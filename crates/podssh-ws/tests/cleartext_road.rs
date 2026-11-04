//! The cleartext road on the relay's port (T-326), on the loopback: a
//! stand-in proxy takes each CONNECT, as a proxy that intercepts TLS does,
//! then resets a ClientHello and carries cleartext (or resets cleartext), in
//! front of a stand-in relay whose side of the upgrade is podssh-ws's
//! server's. The TLS road fails at the proxy, in a way that the cleartext
//! road may pass, and the cleartext road opens with the token in its header,
//! after the TLS road; bytes go both ways. The probe of GitHub #56 names a
//! reset, the refusal of cleartext in nginx's words (its page of a request
//! of plain HTTP on its TLS port), a refusal by policy, a redirect, a record
//! of TLS, an answer, a close, a silence and a CONNECT that reached nothing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::cleartext::{self, Heard};
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::{ConnectError, Cut, DialError, Endpoint, Proxy, ProxyChoice, Trust, WsClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(20);

/// A token of the test's, in the form of the relay role's tokens of one
/// session, with no secret in it.
const TOKEN: &str = "once1.1.test-nonce.test-tag";

/// The first bytes of OpenSSH's sshd, which the session carries.
const BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";

/// The page of nginx for a request of plain HTTP on its TLS port, its
/// status line and the body of `ngx_http_error_497_page` and its tail, as
/// nginx's source writes them; the body ends at the close.
const NGINX_PLAIN_TO_TLS: &[u8] = b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nContent-Type: text/html\r\n\
    Connection: close\r\n\r\n<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title>\
    </head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<center>The plain HTTP request was sent \
    to HTTPS port</center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";

/// A relay's `/health`, in the start of its form.
const HEALTH: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"service\":\"tcp-ssh-relay\"}";

/// What the stand-in proxy resets of a tunnel's first bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cuts {
    /// A ClientHello, and cleartext passes: a proxy that intercepts TLS by
    /// its SNI or its certificate.
    Tls,
    /// Cleartext, and TLS passes: a proxy that expects TLS alone.
    Cleartext,
}

/// The stand-in proxy, and the first byte of each tunnel, in order.
struct Interceptor {
    port: u16,
    firsts: Arc<Mutex<Vec<u8>>>,
}

impl Interceptor {
    /// A proxy that takes each CONNECT, then resets what `cuts` says and
    /// carries the rest to `far` on the loopback, whatever the CONNECT named.
    async fn start(cuts: Cuts, far: u16) -> Interceptor {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let firsts = Arc::new(Mutex::new(Vec::new()));
        let kept = firsts.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(tunnel(tcp, cuts, far, kept.clone()));
            }
        });
        Interceptor { port, firsts }
    }

    fn proxy(&self) -> ProxyChoice {
        ProxyChoice::Via(Proxy::parse(&format!("http://127.0.0.1:{}", self.port)).unwrap())
    }

    fn firsts(&self) -> Vec<u8> {
        self.firsts.lock().unwrap().clone()
    }
}

async fn tunnel(mut tcp: TcpStream, cuts: Cuts, far: u16, firsts: Arc<Mutex<Vec<u8>>>) {
    // The CONNECT's head byte by byte, so that nothing of the tunnel is read.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(LIMIT, tcp.read(&mut byte)).await {
            Ok(Ok(1)) if head.len() < 16 * 1024 => head.push(byte[0]),
            _ => return,
        }
    }
    if tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
        return;
    }
    let mut first = [0u8; 1];
    let Ok(Ok(1)) = tokio::time::timeout(LIMIT, tcp.peek(&mut first)).await else { return };
    firsts.lock().unwrap().push(first[0]);
    let tls = first[0] == 0x16;
    if tls == (cuts == Cuts::Tls) {
        // A reset, as such a proxy ends what it does not carry.
        let _ = tcp.set_zero_linger();
        return;
    }
    let Ok(mut to) = TcpStream::connect(("127.0.0.1", far)).await else { return };
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut to).await;
}

/// A stand-in relay on the loopback, with no TLS: podssh-ws's server side
/// of the upgrade, which keeps the token of each request and echoes each
/// binary message.
struct Relay {
    port: u16,
    tokens: Arc<Mutex<Vec<String>>>,
}

impl Relay {
    async fn start() -> Relay {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let kept = tokens.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(echo(tcp, kept.clone()));
            }
        });
        Relay { port, tokens }
    }

    fn tokens(&self) -> Vec<String> {
        self.tokens.lock().unwrap().clone()
    }
}

async fn echo(mut tcp: TcpStream, tokens: Arc<Mutex<Vec<String>>>) {
    let Ok((head, pending)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
    tokens.lock().unwrap().push(head.header("x-relay-token").unwrap_or_default().to_string());
    let Ok(key) = podssh_ws::server::check_upgrade(&head) else { return };
    if tcp.write_all(&podssh_ws::server::switching(&key)).await.is_err() {
        return;
    }
    let session = podssh_ws::server::session(tcp, pending, Some(LIMIT));
    while let Ok(f) = session.read_frame().await {
        if f.opcode != OPCODE_BINARY || session.send_binary(&f.payload).await.is_err() {
            break;
        }
    }
}

/// The relay `relay-a.test` on port 443, through `proxy`, which the name
/// goes to with no DNS.
fn config(proxy: ProxyChoice) -> WsClientConfig {
    WsClientConfig {
        endpoint: Endpoint { host: "relay-a.test".into(), port: 443, path: "/connect/github.com/22".into() },
        trust: Trust::Default,
        server_name: "relay-a.test".into(),
        timeout: LIMIT,
        idle_timeout: Some(LIMIT),
        proxy,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tls_road_fails_at_the_proxy_and_the_cleartext_road_carries_the_session() {
    let relay = Relay::start().await;
    let proxy = Interceptor::start(Cuts::Tls, relay.port).await;
    let config = config(proxy.proxy());
    let tls = podssh_ws::connect(&config, TOKEN).await.expect_err("TLS through a proxy that resets it");
    assert!(cleartext::tls_failed(&tls), "a failure that the cleartext road may pass: {tls:?}");
    assert!(relay.tokens().is_empty(), "nothing reached the relay on the TLS road");
    let session = cleartext::connect(&config, TOKEN).await.expect("the cleartext road");
    session.send_binary(BANNER).await.unwrap();
    let echoed = tokio::time::timeout(LIMIT, session.read_frame()).await.expect("in time").unwrap();
    assert_eq!(echoed.payload, BANNER, "the bytes went both ways");
    assert_eq!(proxy.firsts(), vec![0x16, b'G'], "TLS first, then the upgrade in cleartext");
    assert_eq!(relay.tokens(), vec![TOKEN.to_string()], "the token went in its header");
    assert!(session.peer().is_some(), "the session keeps the address of its connection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_that_resets_cleartext_is_named_by_the_probe_and_ends_the_road() {
    let relay = Relay::start().await;
    let proxy = Interceptor::start(Cuts::Cleartext, relay.port).await;
    let heard = cleartext::probe("relay-a.test", 443, &proxy.proxy(), LIMIT).await;
    assert_eq!(heard, Heard::Cut(Cut::Reset), "{}", heard.words());
    assert!(!heard.passed());
    assert_eq!(heard.words(), "reset, with no answer: a hop that expects TLS cuts cleartext");
    let Err(refused) = cleartext::connect(&config(proxy.proxy()), TOKEN).await else { panic!("no session") };
    assert!(matches!(refused, ConnectError::Upgrade(_)), "{refused:?}");
    assert!(relay.tokens().is_empty(), "the relay saw nothing");
    assert_eq!(proxy.firsts(), vec![b'G', b'G'], "the probe and the upgrade, each in cleartext");
}

/// A far end on the loopback that answers each request with `bytes`, then
/// closes; or, with none, closes at once; or, when `silent`, says nothing.
async fn answering(bytes: &'static [u8], silent: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = podssh_ws::http::read_request(&mut tcp, Vec::new()).await;
                if silent {
                    tokio::time::sleep(LIMIT).await;
                    return;
                }
                let _ = tcp.write_all(bytes).await;
                let _ = tcp.shutdown().await;
            });
        }
    });
    port
}

async fn heard(bytes: &'static [u8]) -> Heard {
    let port = answering(bytes, false).await;
    cleartext::probe("127.0.0.1", port, &ProxyChoice::Direct, LIMIT).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_probe_names_each_answer() {
    let edge = heard(NGINX_PLAIN_TO_TLS).await;
    assert!(edge.plain_to_tls() && !edge.passed(), "{edge:?}");
    let said = "the edge's refusal: HTTP 400, the plain HTTP request was sent to its HTTPS port";
    assert_eq!(edge.words(), said);
    let policy = heard(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n").await;
    assert_eq!((policy.passed(), policy.words()), (false, "a refusal by policy: HTTP 403 Forbidden".into()));
    let moved = heard(b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://relay-a.test/health?x=1\r\n\r\n").await;
    assert!(!moved.passed());
    assert_eq!(moved.words(), "a redirect: HTTP 301 to https://relay-a.test/health", "no query shown");
    // A fatal alert, as a server of TLS alone may answer a request that is
    // no ClientHello.
    let tls = heard(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32]).await;
    assert_eq!(tls, Heard::Tls);
    let health = heard(HEALTH).await;
    let Heard::Answered { status: 200, body, .. } = &health else { panic!("an answer: {health:?}") };
    assert!(health.passed() && body.starts_with(b"{\"service\""), "{health:?}");
    let closed = heard(b"").await;
    assert_eq!(closed, Heard::Cut(Cut::Closed), "{}", closed.words());
    let other = heard(b"SSH-2.0-OpenSSH_9.6\r\n").await;
    assert!(matches!(&other, Heard::Other(seen) if seen.starts_with("SSH-2.0")), "{other:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silence_and_a_dial_that_reached_nothing_are_named() {
    let port = answering(b"", true).await;
    let wait = Duration::from_millis(500);
    let silent = cleartext::probe("127.0.0.1", port, &ProxyChoice::Direct, wait).await;
    assert_eq!(silent, Heard::Silent(wait));
    // A port where nothing listens: the one of a listener that went.
    let gone = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let unreached = cleartext::probe("127.0.0.1", gone, &ProxyChoice::Direct, LIMIT).await;
    assert!(matches!(&unreached, Heard::Unreached(DialError::Connect { .. })), "{unreached:?}");
    assert!(unreached.words().starts_with("not reached: "), "{}", unreached.words());
}
