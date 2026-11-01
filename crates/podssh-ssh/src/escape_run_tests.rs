//! `~C` on a session's connection (T-291), against a russh server in this
//! process, over a pipe, that takes each forward and lets each go: `-R`
//! and `-KR` ask it, and after `-KR` a channel for the port is refused;
//! `-L` serves a listener of the test's until `-KL` closes it.

use std::io;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Session as ServerSession};
use russh::ChannelOpenFailure;
use tokio::sync::{oneshot, watch};

use super::*;
use crate::escape_command::{Forwarder, Made};
use crate::hostkey::Policy;
use crate::local::{Accepted, Listen, Listening, Target};
use crate::options::{Hop, LogLevel, Options, RemoteForward, StrictHostKeyChecking};

/// The port that the server chooses for a forward that asks for 0.
const CHOSEN: u32 = 4343;

/// What the server was asked: a forward or a cancel, the address, the port.
type Asked = Arc<Mutex<Vec<(&'static str, String, u32)>>>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Lets anyone in, takes each forward and lets each go, and notes each.
struct Server {
    handle: Option<oneshot::Sender<server::Handle>>,
    asked: Asked,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, session: &mut ServerSession) -> Result<(), Self::Error> {
        if let Some(tx) = self.handle.take() {
            let _ = tx.send(session.handle());
        }
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        lock(&self.asked).push(("forward", address.to_string(), *port));
        if *port == 0 {
            *port = CHOSEN;
        }
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        lock(&self.asked).push(("cancel", address.to_string(), port));
        Ok(true)
    }
}

/// A listener that takes no connection until it is closed.
struct Shut {
    at: String,
    closed: watch::Sender<bool>,
}

impl Listen for Shut {
    fn accept(&self) -> Pin<Box<dyn Future<Output = io::Result<Accepted>> + Send + '_>> {
        let mut closed = self.closed.subscribe();
        Box::pin(async move {
            let _ = closed.wait_for(|c| *c).await;
            Err(io::Error::new(io::ErrorKind::NotConnected, "closed"))
        })
    }

    fn place(&self) -> Option<Listening> {
        Some(Listening::Path(self.at.clone()))
    }

    fn close(&self) -> bool {
        self.closed.send_replace(true);
        true
    }

    fn closed(&self) -> bool {
        *self.closed.borrow()
    }
}

/// The caller's part, as podssh's command line would give it: `-R PORT:HOST`
/// to port 9 of HOST, and `-L` with the test's listener.
struct Stub {
    listener: Arc<Shut>,
}

impl Forwarder for Stub {
    fn local(&self, spec: &str, dynamic: bool) -> Made<'_> {
        let target = if dynamic { Target::Socks } else { Target::Tcp { host: "db".into(), port: 5432 } };
        let listener: Arc<dyn Listen> = self.listener.clone();
        let forward = LocalForward { shown: format!("-L {spec}"), target, listeners: vec![listener] };
        Box::pin(async move { Ok(forward) })
    }

    fn remote(&self, spec: &str) -> Result<RemoteForward, String> {
        let (port, host) = spec.split_once(':').ok_or_else(|| "no port".to_string())?;
        let port = port.parse::<u16>().map_err(|_| format!("{port}: no port"))?;
        Ok(RemoteForward::tcp(None, port, host, 9))
    }
}

struct Run {
    handle: Handle<Client>,
    server: server::Handle,
    table: Table,
    asked: Asked,
    log: Arc<Log>,
    scratch: PathBuf,
}

impl Run {
    fn logged(&self) -> String {
        std::fs::read_to_string(self.scratch.join("log")).unwrap_or_default()
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

/// A logged-in connection, with the handler's table of `-R` at hand.
async fn start(name: &str) -> Run {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let (tx, rx) = oneshot::channel();
    let asked = Asked::default();
    let handler = Server { handle: Some(tx), asked: asked.clone() };
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, handler).await {
            let _ = session.await;
        }
    });
    let scratch = std::env::temp_dir().join(format!("podssh-escape-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("a scratch directory");
    let log = Arc::new(Log::to_file(LogLevel::Info, &scratch.join("log")).expect("a log file"));
    let policy = Policy {
        name: "escape.test".into(),
        strict: StrictHostKeyChecking::No,
        user_files: Vec::new(),
        no_user_file: None,
        global_files: Vec::new(),
        batch_mode: true,
        pin: None,
        fingerprints: Vec::new(),
    };
    let client = Client::new(policy, log.clone());
    let table = client.forwards();
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect_stream(config, client_end, client).await.expect("the handshake");
    assert!(handle.authenticate_none("podtest").await.expect("an answer").success(), "not logged in");
    let server = rx.await.expect("the server's handle");
    Run { handle, server, table, asked, log, scratch }
}

fn order(line: &str) -> Order {
    escape_command::parse(line).unwrap_or_else(|e| panic!("{line}: {e}"))
}

fn shut(at: &str) -> Arc<Shut> {
    Arc::new(Shut { at: at.to_string(), closed: watch::channel(false).0 })
}

/// `-R` asks the server, `-KR` lets the forward go, after which a channel
/// for its port is refused; a second `-KR` finds none.
#[tokio::test]
async fn escape_command_r_asks_the_server_and_kr_lets_it_go() {
    let test = async {
        let run = start("r").await;
        let commands = Commands(Arc::new(Stub { listener: shut("/unused") }));
        let mut added = Added::default();
        let table = Some(&run.table);
        run_order(order("-R 0:escape-r.test"), &run, table, &commands, &mut added).await;
        assert_eq!(*lock(&run.asked), [("forward", "localhost".to_string(), 0)]);
        assert_eq!(
            lock(&run.table).iter().map(|b| b.at.clone()).collect::<Vec<_>>(),
            [crate::remote::Listening::Port(CHOSEN)]
        );
        let logged = run.logged();
        assert!(logged.contains(&format!("Allocated port {CHOSEN}")), "{logged}");
        assert!(logged.contains("Forwarding port."), "{logged}");

        run_order(order(&format!("-KR {CHOSEN}")), &run, table, &commands, &mut added).await;
        assert_eq!(lock(&run.asked).last(), Some(&("cancel", "localhost".to_string(), CHOSEN)));
        assert!(lock(&run.table).is_empty(), "the forward is still in the table");
        assert!(run.logged().contains("Canceled forwarding: -R 0:escape-r.test:9"), "{}", run.logged());
        let channel = run.server.channel_open_forwarded_tcpip("localhost", CHOSEN, "127.0.0.1", 40000).await;
        match channel {
            Err(russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)) => {}
            Err(e) => panic!("refused with another reason: {e:?}"),
            Ok(_) => panic!("a channel for a forward that -KR stopped was accepted"),
        }
        let listed = crate::tally::lines();
        let line = listed.iter().find(|l| l.starts_with("-R 0:escape-r.test:9: ")).expect("~# lists it");
        assert!(line.ends_with("; closed"), "{line}");

        run_order(order(&format!("-KR {CHOSEN}")), &run, table, &commands, &mut added).await;
        assert_eq!(lock(&run.asked).len(), 2, "a forward that is gone was cancelled again");
        assert!(run.logged().contains("Unknown port forwarding."), "{}", run.logged());

        // A new connection of `--persist` asks for the forwards of the
        // command line, but not for one that `-KR` stopped.
        let hop = Hop { user: Some("podtest".into()), host: "escape.test".into(), port: 22, tls: false };
        let mut opts = Options::new(hop, "podtest".into());
        opts.remote_forwards = vec![RemoteForward::tcp(None, 0, "escape-r.test", 9)];
        crate::remote::request(&run.handle, &run.table, &opts, &run.log).await.expect("no refusal");
        assert_eq!(lock(&run.asked).len(), 2, "a forward that -KR stopped was asked for again");
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// `-L` serves its listener beside the session; `-KL` at its place closes
/// it, and the forward ends; `-KD` there finds no forward of `-D`.
#[tokio::test]
async fn escape_command_l_serves_until_kl_closes_its_listener() {
    let test = async {
        let run = start("l").await;
        let at = format!("/podssh-escape-test-{}.sock", std::process::id());
        let listener = shut(&at);
        let commands = Commands(Arc::new(Stub { listener: listener.clone() }));
        let mut added = Added::default();
        run_order(order("-L 7000:escape-l.test:5432"), &run, None, &commands, &mut added).await;
        assert_eq!(added.serving.len(), 1);
        assert!(run.logged().contains("Forwarding port."), "{}", run.logged());
        // Serving, it does not end of itself.
        assert!(tokio::time::timeout(Duration::from_millis(300), added.next()).await.is_err());

        run_order(order(&format!("-KD {at}")), &run, None, &commands, &mut added).await;
        assert!(!listener.closed(), "-KD closed a listener of -L");
        assert!(run.logged().contains("Unknown port forwarding."), "{}", run.logged());

        run_order(order(&format!("-KL {at}")), &run, None, &commands, &mut added).await;
        assert!(listener.closed(), "-KL left the listener open");
        assert!(run.logged().contains("Canceled forwarding: -L 7000:escape-l.test:5432"), "{}", run.logged());
        tokio::time::timeout(Duration::from_secs(5), added.next()).await.expect("the forward ends with its listener");
        assert!(added.serving.is_empty());
        let listed = crate::tally::lines();
        let line = listed.iter().find(|l| l.starts_with("-L 7000:escape-l.test:5432: ")).expect("~# lists it");
        assert!(line.ends_with("; closed"), "{line}");
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// One order on `run`'s connection.
async fn run_order<'a>(order: Order, run: &'a Run, table: Option<&Table>, commands: &Commands, added: &mut Added<'a>) {
    super::run(order, &run.handle, table, Some(commands), added, &run.log).await;
}
