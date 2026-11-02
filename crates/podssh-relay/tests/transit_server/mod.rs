//! magic-wormhole's own transit relay (magic-wormhole-transit-relay, in
//! Python, on Twisted and Autobahn) on the loopback, for the tests of the
//! transit road (T-436): software that podssh did not write. A host with no
//! Python, or without the package, skips each test with its reason, unless
//! `PODSSH_TRANSIT_TEST_SERVER=required`, which a planted run and the
//! workflow set, so that a skip there is a failure.
//!
//!   python3 -m pip install magic-wormhole-transit-relay
//!
//! `PODSSH_TRANSIT_TEST_PYTHON` names the interpreter (a virtualenv's).

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podssh_ws::url::WsUrl;

/// How long the server may take to listen.
const START_LIMIT: Duration = Duration::from_secs(30);

/// A transit relay of magic-wormhole's, listening on the loopback.
pub struct Relay {
    child: Child,
    /// Its WebSocket.
    pub url: WsUrl,
    /// Its log, for a test that fails to show.
    pub log: PathBuf,
}

/// Each name that the interpreter may have.
fn pythons() -> Vec<String> {
    match std::env::var("PODSSH_TRANSIT_TEST_PYTHON") {
        Ok(named) if !named.trim().is_empty() => vec![named],
        _ => vec!["python3".into(), "python".into()],
    }
}

/// Whether `python` imports the relay and what it runs on.
fn has_relay(python: &str) -> bool {
    let probe = Command::new(python)
        .args(["-c", "import wormhole_transit_relay, autobahn, twisted"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    probe.is_ok_and(|status| status.success())
}

/// A port of the loopback that nobody holds now.
fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a port of the loopback");
    listener.local_addr().expect("its address").port()
}

impl Relay {
    /// The relay, listening; `None`, with the reason on stderr, when this
    /// host cannot run it and the run does not require it.
    pub fn start(tag: &str) -> Option<Relay> {
        let required = std::env::var("PODSSH_TRANSIT_TEST_SERVER").is_ok_and(|v| v == "required");
        let Some(python) = pythons().into_iter().find(|p| has_relay(p)) else {
            let why = "no Python with magic-wormhole-transit-relay here (pip install magic-wormhole-transit-relay)";
            assert!(!required, "PODSSH_TRANSIT_TEST_SERVER=required: {why}");
            eprintln!("did not run: {why}");
            return None;
        };
        let dir = std::env::temp_dir().join(format!("podssh-transit-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        crate::cleanup::at_test_end(&dir);
        let log = dir.join("relay.log");
        let (tcp, ws) = (free_port(), free_port());
        // `python -m twisted` is `twist`, which runs the plugin in the
        // foreground (the package's docs/running.md); its TCP port too, on
        // the loopback, as it always listens on one.
        let child = Command::new(&python)
            .args(["-m", "twisted", "transitrelay"])
            .arg(format!("--port=tcp:{tcp}:interface=127.0.0.1"))
            .arg(format!("--websocket=tcp:{ws}:interface=127.0.0.1"))
            .arg(format!("--websocket-url=ws://127.0.0.1:{ws}/"))
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&log).expect("the log"))
            .stderr(std::fs::File::create(dir.join("relay.err")).expect("the log of errors"))
            .spawn()
            .expect("the transit relay starts");
        let relay = Relay { child, url: WsUrl::parse(&format!("ws://127.0.0.1:{ws}/")).unwrap(), log };
        let at = SocketAddr::from((Ipv4Addr::LOCALHOST, ws));
        let deadline = Instant::now() + START_LIMIT;
        while TcpStream::connect_timeout(&at, Duration::from_millis(200)).is_err() {
            assert!(Instant::now() < deadline, "the transit relay did not listen within 30 s: {}", relay.said());
            std::thread::sleep(Duration::from_millis(100));
        }
        Some(relay)
    }

    /// What the relay wrote, for a message.
    pub fn said(&self) -> String {
        let out = std::fs::read_to_string(&self.log).unwrap_or_default();
        let err = std::fs::read_to_string(self.log.with_file_name("relay.err")).unwrap_or_default();
        format!("{out}{err}")
    }

    /// Stop the relay at once, as a server that goes away: each of its
    /// connections ends with no Close.
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}
