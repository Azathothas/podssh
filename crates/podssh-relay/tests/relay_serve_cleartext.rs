//! The cleartext road at podssh's relay role (T-326), on the loopback. The
//! role takes each connection as `podssh relay serve` takes it
//! (`serve::listener::connection`): TLS, or, by its first byte, the
//! cleartext road. A stand-in proxy of the test's, the host's proxy of the
//! client, intercepts TLS: it resets each ClientHello and carries
//! cleartext. `podssh_relay::open` tries the TLS road first, which fails at
//! the proxy, then, last, the cleartext road: a token of one session minted
//! in cleartext, and the session with it, to a target that greets with
//! OpenSSH's version line. The token works once, and a second use is
//! refused; a token of 72 h is refused in cleartext, and so is each request
//! that the road does not need. With the road off, a request in cleartext
//! gets no answer of HTTP.
#![cfg(feature = "serve")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::failover::Mode;
use podssh_relay::open::Request;
use podssh_relay::relay::{Relay, RelayList};
use podssh_relay::serve::listener::{connection, Door};
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{self, tokens, Config, Limits, Mint};
use podssh_ws::cleartext::{self, Heard};
use podssh_ws::frame::OPCODE_BINARY;
use podssh_ws::tls_server::{acceptor_for, Served, HTTP1};
use podssh_ws::{ConnectError, Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(20);

/// OpenSSH's version line, in the form that its sshd sends it first.
const BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";

/// The role on a free port of the loopback, and what it said.
struct Role {
    port: u16,
    cfg: Arc<Config>,
    events: Arc<Mutex<Vec<String>>>,
}

impl Role {
    /// The role, minting for anyone, its targets on the loopback allowed,
    /// with the cleartext road beside TLS when `cleartext`. TLS has no
    /// certificate here: no ClientHello passes the test's proxy, and one
    /// that came straight would find none.
    async fn start(cleartext: bool) -> Role {
        let bound = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
        let port = bound.local_addr().unwrap().port();
        let events = Arc::new(Mutex::new(Vec::new()));
        let said = events.clone();
        let say: serve::Events = Box::new(move |line: &str| said.lock().unwrap().push(line.to_string()));
        let cfg = Arc::new(Config {
            version: "podssh test".into(),
            mint: Mint::Anyone,
            tokens: tokens::Tokens::new([5; 32]),
            policy: Policy { private: true, ..Policy::default() },
            egress: Default::default(),
            limits: Limits::default(),
            pairs: Default::default(),
            resumes: Default::default(),
            answered: Default::default(),
            brake: Default::default(),
            events: Some(say),
        });
        let acceptor = acceptor_for(Served::new(None), &[HTTP1]).expect("an acceptor");
        let door = Door { acceptor, cleartext };
        let served = cfg.clone();
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = bound.accept().await {
                tokio::spawn(connection(tcp, peer.ip(), door.clone(), served.clone()));
            }
        });
        Role { port, cfg, events }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    /// Whether the role said `line`.
    fn said(&self, line: &str) -> bool {
        self.events().iter().any(|l| l == line)
    }
}

/// A target on the loopback that sends [`BANNER`] to each connection, then
/// reads until its end.
async fn banner() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = tcp.write_all(BANNER).await;
                let mut sink = vec![0u8; 4096];
                while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
            });
        }
    });
    port
}

/// The stand-in proxy: each CONNECT taken, whatever it names; then a
/// ClientHello reset and cleartext carried to the role's port, as a proxy
/// that intercepts TLS by its SNI or its certificate does. It keeps the
/// first byte of each tunnel, in order.
struct Interceptor {
    port: u16,
    firsts: Arc<Mutex<Vec<u8>>>,
}

impl Interceptor {
    async fn start(role: u16) -> Interceptor {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let firsts = Arc::new(Mutex::new(Vec::new()));
        let kept = firsts.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(tunnel(tcp, role, kept.clone()));
            }
        });
        Interceptor { port, firsts }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn firsts(&self) -> Vec<u8> {
        self.firsts.lock().unwrap().clone()
    }
}

async fn tunnel(mut tcp: TcpStream, role: u16, firsts: Arc<Mutex<Vec<u8>>>) {
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
    if first[0] == 0x16 {
        // A reset, as such a proxy ends a ClientHello that it does not carry.
        let _ = tcp.set_zero_linger();
        return;
    }
    let Ok(mut to) = TcpStream::connect(("127.0.0.1", role)).await else { return };
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut to).await;
}

/// The first payload of `session`, past the role's empty keepalives.
async fn first_bytes(session: &RelaySession) -> Vec<u8> {
    loop {
        let frame = tokio::time::timeout(LIMIT, session.read_frame()).await.expect("a frame in time").expect("a frame");
        assert_eq!(frame.opcode, OPCODE_BINARY, "{:?}", String::from_utf8_lossy(&frame.payload));
        if !frame.payload.is_empty() {
            return frame.payload;
        }
    }
}

/// One request in cleartext straight to the role: its status and its body.
async fn http(port: u16, method: &str, path: &str) -> (u16, String) {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let body = if method == "POST" { "Content-Length: 2\r\n\r\n{}" } else { "\r\n" };
    let request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n{body}");
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await.expect("an answer in time").unwrap();
    let text = String::from_utf8_lossy(&answer).into_owned();
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

/// The road's upgrade at `path`, straight to the role.
fn straight(port: u16, path: &str) -> WsClientConfig {
    WsClientConfig {
        endpoint: Endpoint { host: "127.0.0.1".into(), port, path: path.to_string() },
        trust: Trust::Default,
        server_name: "127.0.0.1".into(),
        timeout: LIMIT,
        idle_timeout: Some(LIMIT),
        proxy: ProxyChoice::Direct,
    }
}

/// The one test of this file that reads the environment: the client's
/// proxy, as the opener takes the host's, and no cache, so that no token of
/// an earlier run is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_the_tls_road_failed_the_session_opens_in_cleartext() {
    for name in ["https_proxy", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"] {
        std::env::remove_var(name);
    }
    for name in ["PODSSH_RELAY_TOKEN", "PODSSH_OFFLINE", "PODSSH_CLEARTEXT"] {
        std::env::remove_var(name);
    }
    std::env::set_var("PODSSH_CACHE_DIR", "none");
    let target = banner().await;
    let role = Role::start(true).await;
    let proxy = Interceptor::start(role.port).await;
    std::env::set_var("HTTPS_PROXY", proxy.url());
    // The role by a name that only the proxy reaches, as a relay's name is.
    let relays = RelayList { hosts: vec![Relay { host: "relay-a.test".into(), port: role.port }], explicit: true };
    let path = podssh_relay::relay::forward_path("127.0.0.1", target).unwrap();
    let (shown, trust) = (format!("127.0.0.1:{target}"), Trust::Default);
    let request =
        Request { relays: &relays, path: &path, trust: &trust, target: &shown, rounds: 1, failover: Mode::Staggered };
    let mut notes: Vec<String> = Vec::new();
    let opened = podssh_relay::open(&request, &mut |note: &str| notes.push(note.to_string())).await;
    let opened = opened.unwrap_or_else(|failure| panic!("{:?}; notes {notes:?}", failure.lines(&shown)));
    assert!(opened.cleartext, "the cleartext road carries it");
    let firsts = proxy.firsts();
    let clear = firsts.iter().position(|b| *b != 0x16).expect("a request in cleartext");
    assert!(clear > 0 && firsts[clear..].iter().all(|b| *b != 0x16), "the TLS road first: {firsts:?}");
    assert_eq!(first_bytes(&opened.session).await, BANNER, "OpenSSH's version line through the session");
    for line in ["cleartext POST /v1/mint", "mint once", "cleartext GET /connect/", "upgrade"] {
        assert!(role.said(line), "the role said no {line:?}: {:?}", role.events());
    }
    assert!(!role.said("mint"), "no token of 72 h was minted: {:?}", role.events());
    assert!(notes.iter().any(|n| n.contains("carries the session in cleartext")), "{notes:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_of_one_session_works_once_and_no_other_token_goes_in_cleartext() {
    let target = banner().await;
    let role = Role::start(true).await;
    let path = podssh_relay::relay::forward_path("127.0.0.1", target).unwrap();
    // The client's road, its mint and its upgrade, straight to the role.
    let relay = Relay { host: "127.0.0.1".into(), port: role.port };
    let session = podssh_relay::cleartext::attempt(&relay, &path, &ProxyChoice::Direct, LIMIT).await;
    assert_eq!(first_bytes(&session.expect("the road")).await, BANNER);
    // A token of one session, minted in cleartext as the road mints it: its
    // first upgrade passes, a second is refused.
    let (status, body) = http(role.port, "POST", "/v1/mint?once=1").await;
    assert_eq!(status, 200, "{body}");
    let minted: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(minted["once"], true, "{body}");
    let token = minted["token"].as_str().expect("a token").to_string();
    let config = straight(role.port, &path);
    let first = cleartext::connect(&config, &token).await.expect("the first use");
    assert_eq!(first_bytes(&first).await, BANNER);
    let Err(second) = cleartext::connect(&config, &token).await else { panic!("a second use is refused") };
    let words = "a token of one session alone";
    assert!(matches!(&second, ConnectError::Refused { status: 403, body } if body.contains(words)), "{second:?}");
    // A token of 72 h, as the contract mints it: refused in cleartext.
    let (long, _) = role.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let Err(refused) = cleartext::connect(&config, &long).await else {
        panic!("a token of 72 h is refused in cleartext")
    };
    assert!(matches!(&refused, ConnectError::Refused { status: 403, .. }), "{refused:?}");
    // The mint of a token of 72 h, the documents and the reverse road go
    // over TLS alone.
    for (method, path) in [("POST", "/v1/mint"), ("GET", "/relays.json"), ("POST", "/v1/pair"), ("GET", "/trace")] {
        let (status, body) = http(role.port, method, path).await;
        assert_eq!(status, 403, "{method} {path}: {body}");
    }
    let (status, body) = http(role.port, "GET", "/health").await;
    assert!(status == 200 && body.contains("tcp-ssh-relay"), "{status}: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_road_off_a_request_in_cleartext_gets_no_answer_of_http() {
    let role = Role::start(false).await;
    let heard = cleartext::probe("127.0.0.1", role.port, &ProxyChoice::Direct, LIMIT).await;
    assert!(matches!(heard, Heard::Tls | Heard::Cut(_)), "TLS alone: {heard:?}");
    assert!(!heard.passed());
    assert!(role.events().is_empty(), "nothing was served: {:?}", role.events());
}
