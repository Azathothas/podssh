//! podssh's relay role (T-427) on the loopback, over plain TCP, as the tests
//! of its reverse road run it: `serve_from` for each connection, which
//! `podssh relay serve` runs behind TLS, and a pair of the role's as podssh's
//! client reads one. The clients reach it with the plain `ws://` of the
//! feature `plain-ws`; each event of the role is kept for a test to read. A
//! stand-in proxy of the test's is the host's proxy of T-457 (`proxy`).

// Each test binary uses a part of it.
#![allow(dead_code)]

pub mod proxy;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::pair::{self, Pair};
use podssh_relay::relay::Relay;
use podssh_relay::serve::egress::Egress;
use podssh_relay::serve::layer::Resumes;
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{self, Config, Limits, Mint};
use podssh_ws::session::RelaySession;
use podssh_ws::ConnectError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const LIMIT: Duration = Duration::from_secs(20);

/// The role, where it listens, and what it said.
pub struct Role {
    pub relay: Relay,
    pub cfg: Arc<Config>,
    pub events: Arc<Mutex<Vec<String>>>,
}

impl Role {
    /// The role on a free port of the loopback, minting for anyone.
    pub async fn start() -> Role {
        Role::with(Mint::Anyone).await
    }

    pub async fn with(mint: Mint) -> Role {
        Role::configured(mint, Default::default(), Default::default()).await
    }

    /// The role with its policy of targets and its egress: through a proxy
    /// of the test's, for the role's dial through its host's (T-457).
    pub async fn configured(mint: Mint, policy: Policy, egress: Egress) -> Role {
        Role::configured_with(mint, policy, egress, Default::default()).await
    }

    /// [`Role::configured`] with the sessions of its forward road in the
    /// resumable layer: their budget, their deadline, its own name (T-173).
    pub async fn configured_with(mint: Mint, policy: Policy, egress: Egress, resumes: Resumes) -> Role {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
        let port = listener.local_addr().unwrap().port();
        let events = Arc::new(Mutex::new(Vec::new()));
        let said = events.clone();
        let say: serve::Events = Box::new(move |line: &str| said.lock().unwrap().push(line.to_string()));
        let cfg = Arc::new(Config {
            version: "podssh test".into(),
            mint,
            tokens: serve::tokens::Tokens::new([5; 32]),
            policy,
            egress,
            limits: Limits::default(),
            pairs: Default::default(),
            resumes,
            answered: Default::default(),
            brake: Default::default(),
            events: Some(say),
        });
        let served = cfg.clone();
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = listener.accept().await {
                // Its unsent bytes bounded, as `podssh relay serve` bounds
                // them (T-336).
                serve::sockets::bound_unsent(&tcp);
                // The peer, as `podssh relay serve` gives it, for the brake.
                tokio::spawn(serve::serve_from(tcp, served.clone(), None, Some(peer.ip())));
            }
        });
        Role { relay: Relay { host: "127.0.0.1".into(), port }, cfg, events }
    }

    /// A new pair of the role's, as podssh's client reads the answer of
    /// `/v1/pair`.
    pub fn pair(&self) -> Pair {
        self.pair_made_at(serve::tokens::now_ms())
    }

    /// A pair of the role's as if made at `made_ms`, which ends 72 h after
    /// it: one made `72 h - 3 s` before ends in 3 s (T-592). podssh's client
    /// reads it as at that time, as it refuses a pair with less than 10
    /// minutes left.
    pub fn pair_made_at(&self, made_ms: u64) -> Pair {
        let made = self.cfg.pairs.make(made_ms).expect("a pair");
        let body = serde_json::json!({
            "name": made.name, "node_token": made.node, "connect_token": made.connect,
            "stop_token": made.stop, "expires": made.expires_ms,
        });
        let read = pair::parse(&self.relay, body.to_string().as_bytes(), made_ms as i64);
        read.expect("the role's pair, as podssh reads it")
    }

    /// Whether the role said a line that holds `text`.
    pub fn said(&self, text: &str) -> bool {
        self.events.lock().unwrap().iter().any(|line| line.contains(text))
    }

    /// Until the role says `text`, `LIMIT` at most.
    pub async fn until_said(&self, text: &str) {
        let deadline = Instant::now() + LIMIT;
        while !self.said(text) {
            assert!(Instant::now() < deadline, "the role never said {text:?}: {:?}", self.events.lock().unwrap());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A WebSocket to `path` with `token`, plain, as a client of the
    /// contract that podssh did not shape opens one.
    pub async fn socket(&self, path: &str, token: &str) -> Result<RelaySession<TcpStream>, ConnectError> {
        podssh_ws::plain::connect_loopback("127.0.0.1", self.relay.port, path, token, LIMIT, None).await
    }

    /// One HTTP request, its status and its body.
    pub async fn http(&self, method: &str, path: &str, token: Option<&str>) -> (u16, String) {
        let mut tcp = TcpStream::connect(("127.0.0.1", self.relay.port)).await.unwrap();
        let header = token.map(|t| format!("X-Relay-Token: {t}\r\n")).unwrap_or_default();
        let body = if method == "POST" { "Content-Length: 2\r\n\r\n{}" } else { "\r\n" };
        let request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n{header}{body}");
        tcp.write_all(request.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await.expect("an answer in time").unwrap();
        let text = String::from_utf8_lossy(&answer).into_owned();
        let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
        (status, body)
    }
}

/// The next message of `socket`: its opcode and payload, or `None` at its end
/// or after `LIMIT`.
pub async fn next(socket: &RelaySession<TcpStream>) -> Option<(u8, Vec<u8>)> {
    match tokio::time::timeout(LIMIT, socket.read_frame()).await {
        Ok(Ok(f)) => Some((f.opcode, f.payload)),
        _ => None,
    }
}

/// The next text frame of `socket`, as JSON.
pub async fn next_text(socket: &RelaySession<TcpStream>) -> serde_json::Value {
    let (opcode, payload) = next(socket).await.expect("a frame");
    assert_eq!(opcode, podssh_ws::frame::OPCODE_TEXT, "{:?}", String::from_utf8_lossy(&payload));
    serde_json::from_slice(&payload).expect("JSON")
}

/// The Close that ends `socket`: its code and reason, after any other frames.
pub async fn closed(socket: &RelaySession<TcpStream>) -> (Option<u16>, String) {
    loop {
        match next(socket).await {
            Some((podssh_ws::frame::OPCODE_CLOSE, payload)) => {
                return podssh_ws::session::close_code_and_reason(&payload);
            }
            Some(_) => {}
            None => return (None, "no Close".into()),
        }
    }
}
