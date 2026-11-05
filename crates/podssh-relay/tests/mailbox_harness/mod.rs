//! The mailboxes of the tests of the pairing by code (T-086), on the
//! loopback: magic-wormhole's own mailbox server (magic-wormhole-mailbox-
//! server, in Python, on Twisted and Autobahn), and podssh's relay role at
//! `/v1/mailbox` (with the feature `serve`); and a peer of magic-wormhole's
//! own Python library (`scripts/wormhole-peer.py`). The Python ones are
//! software that podssh did not write. A host with no Python, or without the
//! packages, skips them with the reason, unless
//! `PODSSH_MAILBOX_TEST_SERVER=required`, which a planted run and the
//! workflow set, so that a skip there is a failure.
//!
//!   python3 -m pip install magic-wormhole-mailbox-server magic-wormhole
//!
//! `PODSSH_MAILBOX_TEST_PYTHON` names the interpreter (a virtualenv's).

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use podssh_ws::url::WsUrl;

/// How long a server may take to listen, and a peer to say a line.
pub const LIMIT: Duration = Duration::from_secs(60);

/// What the Python of this host can run.
fn required() -> bool {
    std::env::var("PODSSH_MAILBOX_TEST_SERVER").is_ok_and(|v| v == "required")
}

fn pythons() -> Vec<String> {
    match std::env::var("PODSSH_MAILBOX_TEST_PYTHON") {
        Ok(named) if !named.trim().is_empty() => vec![named],
        _ => vec!["python3".into(), "python".into()],
    }
}

fn imports(python: &str, modules: &str) -> bool {
    let probe = Command::new(python)
        .args(["-c", &format!("import {modules}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    probe.is_ok_and(|status| status.success())
}

/// A Python that imports `modules`; `None`, with the reason on stderr, when
/// none does and the run does not require it.
pub fn python(modules: &str, package: &str) -> Option<String> {
    let found = pythons().into_iter().find(|p| imports(p, modules));
    if found.is_none() {
        let why = format!("no Python with {package} here (pip install {package})");
        assert!(!required(), "PODSSH_MAILBOX_TEST_SERVER=required: {why}");
        eprintln!("did not run: {why}");
    }
    found
}

fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a port of the loopback");
    listener.local_addr().expect("its address").port()
}

/// A mailbox's URL where nothing listens: a port of the loopback just let go.
pub fn nobody_there() -> WsUrl {
    WsUrl::parse(&format!("ws://127.0.0.1:{}/v1", free_port())).unwrap()
}

/// The repository's `scripts/`.
fn scripts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts")
}

/// magic-wormhole's mailbox server, listening on the loopback.
pub struct Server {
    child: Child,
    /// Its WebSocket, `ws://127.0.0.1:PORT/v1`.
    pub url: WsUrl,
    log: PathBuf,
}

impl Server {
    /// The server; `None` when this host cannot run it.
    pub fn start(tag: &str) -> Option<Server> {
        let python = python("wormhole_mailbox_server, autobahn, twisted", "magic-wormhole-mailbox-server")?;
        let dir = std::env::temp_dir().join(format!("podssh-mailbox-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        crate::cleanup::at_test_end(&dir);
        let log = dir.join("server.log");
        let port = free_port();
        // `python -m twisted` is `twist`, which runs the plugin in the
        // foreground; its state in a database of the scratch directory.
        let child = Command::new(&python)
            .args(["-m", "twisted", "wormhole-mailbox"])
            .arg(format!("--port=tcp:{port}:interface=127.0.0.1"))
            .arg(format!("--channel-db={}", dir.join("relay.sqlite").display()))
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&log).expect("the log"))
            .stderr(std::fs::File::create(dir.join("server.err")).expect("the log of errors"))
            .spawn()
            .expect("the mailbox server starts");
        let server = Server { child, url: WsUrl::parse(&format!("ws://127.0.0.1:{port}/v1")).unwrap(), log };
        let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let deadline = Instant::now() + LIMIT;
        while TcpStream::connect_timeout(&at, Duration::from_millis(200)).is_err() {
            assert!(Instant::now() < deadline, "the mailbox server did not listen in time: {}", server.said());
            std::thread::sleep(Duration::from_millis(100));
        }
        Some(server)
    }

    /// What the server wrote, for a message.
    pub fn said(&self) -> String {
        let out = std::fs::read_to_string(&self.log).unwrap_or_default();
        let err = std::fs::read_to_string(self.log.with_file_name("server.err")).unwrap_or_default();
        format!("{out}{err}")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// podssh's relay role on a free port of the loopback, served in this
/// runtime, over plain TCP: its mailbox's URL.
#[cfg(feature = "serve")]
pub async fn role() -> WsUrl {
    use std::sync::Arc;

    use podssh_relay::serve::{self, Config, Limits, Mint};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    let cfg = Arc::new(Config {
        version: "podssh test".into(),
        mint: Mint::Nobody,
        tokens: serve::tokens::Tokens::new([5; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Limits::default(),
        pairs: Default::default(),
        resumes: Default::default(),
        answered: Default::default(),
        brake: Default::default(),
        usage: Default::default(),
        events: None,
    });
    tokio::spawn(async move {
        while let Ok((tcp, peer)) = listener.accept().await {
            tokio::spawn(serve::serve_from(tcp, cfg.clone(), None, Some(peer.ip())));
        }
    });
    WsUrl::parse(&format!("ws://127.0.0.1:{port}/v1/mailbox")).unwrap()
}

/// Each mailbox that this host can run for a test: podssh's role, and
/// magic-wormhole's server, by name, with what keeps the server running.
pub async fn mailboxes(tag: &str) -> Vec<(&'static str, WsUrl, Option<Server>)> {
    let mut all = Vec::new();
    #[cfg(feature = "serve")]
    all.push(("podssh's relay role", role().await, None));
    if let Some(server) = Server::start(tag) {
        all.push(("magic-wormhole's mailbox server", server.url.clone(), Some(server)));
    }
    all
}

/// A peer of magic-wormhole's Python library, which says a line for each
/// step (`scripts/wormhole-peer.py`).
pub struct Peer {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Peer {
    /// The peer at `url` with `appid`, giving or taking a code; `None` when
    /// this host has no Python with the library.
    pub fn start(url: &WsUrl, appid: &str, mode: &str) -> Option<Peer> {
        let python = python("wormhole, twisted", "magic-wormhole")?;
        let shown = url.shown();
        let mut child = Command::new(python)
            .arg(scripts().join("wormhole-peer.py"))
            .args([shown.as_str(), appid, mode])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the Python peer starts");
        let stdout = child.stdout.take().expect("its stdout");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Some(Peer { stdin: child.stdin.take(), child, lines, seen: Vec::new() })
    }

    /// Give the peer the code on its stdin, never in its argv.
    pub fn type_code(&mut self, code: &str) {
        let mut stdin = self.stdin.take().expect("the peer's stdin, once");
        writeln!(stdin, "{code}").expect("the peer reads the code");
    }

    /// The rest of the peer's line that starts with `word`, within
    /// [`LIMIT`]; `None` when it ends or says another last word first.
    pub fn after(&mut self, word: &str) -> Option<String> {
        let deadline = Instant::now() + LIMIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self.lines.recv_timeout(left).ok()?;
            self.seen.push(line.clone());
            if let Some(rest) = line.strip_prefix(word) {
                return Some(rest.trim().to_string());
            }
        }
    }

    /// Each line that the peer said, for a message.
    pub fn said(&self) -> String {
        self.seen.join(" | ")
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
