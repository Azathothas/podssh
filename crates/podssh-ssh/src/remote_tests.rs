//! The channels of `-R` against a server that takes forwards: a russh server
//! in this process, over a pipe, that listens on nothing; it opens the
//! `forwarded-tcpip` channels itself, as a server does for each connection
//! that it takes on a forwarded port.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelMsg, ChannelOpenFailure};
use tokio::sync::oneshot;

use crate::log::Log;
use crate::options::{Agent, Hop, LogLevel, Options, RemoteForward, StrictHostKeyChecking};
use crate::run::HopError;

/// The port that the server chooses for a forward that asks for 0.
const CHOSEN: u32 = 4242;

/// Lets anyone in, gives its session handle to the test, and takes each
/// forward when `take` is set: the requests it saw are kept.
struct Forwarder {
    handle: Option<oneshot::Sender<server::Handle>>,
    take: bool,
    asked: Arc<Mutex<Vec<(String, u32)>>>,
}

impl server::Handler for Forwarder {
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
        self.asked.lock().unwrap().push((address.to_string(), *port));
        if *port == 0 {
            *port = CHOSEN;
        }
        Ok(self.take)
    }
}

struct Run {
    client: Result<russh::client::Handle<crate::handler::Client>, HopError>,
    server: Option<server::Handle>,
    asked: Arc<Mutex<Vec<(String, u32)>>>,
    logged: String,
}

/// Log in with `forwards`, the server taking them or not.
async fn log_in(forwards: Vec<RemoteForward>, take: bool, exit_on_failure: bool) -> Run {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let (tx, rx) = oneshot::channel();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let forwarder = Forwarder { handle: Some(tx), take, asked: asked.clone() };
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, forwarder).await {
            let _ = session.await;
        }
    });

    let dir = std::env::temp_dir().join(format!("podssh-remote-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    let log_file = dir.join("log");
    let hop = Hop { user: Some("podtest".into()), host: "forwarder.test".into(), port: 22 };
    let mut opts = Options::new(hop.clone(), "podtest".into());
    opts.connect_timeout = Duration::from_secs(10);
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.remote_forwards = forwards;
    opts.exit_on_forward_failure = exit_on_failure;
    let log = Arc::new(Log::to_file(LogLevel::Info, &log_file).expect("a log file"));
    let client = crate::run::connect(client_end, &hop, true, &opts, &log).await;
    let server = match &client {
        Ok(_) => Some(rx.await.expect("the server's handle")),
        Err(_) => None,
    };
    let logged = std::fs::read_to_string(&log_file).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    Run { client, server, asked, logged }
}

fn forward(port: u16, host: &str, host_port: u16) -> RemoteForward {
    RemoteForward { bind: None, port, host: host.into(), host_port }
}

/// A forwarded channel for the port that the server chose reaches the
/// forward's target, both ways and with the end of each; one for a port
/// that podssh did not ask for is refused, and the session goes on.
#[tokio::test]
async fn a_forwarded_channel_reaches_its_target_and_another_is_refused() {
    let test = async {
        // The target: an echo on the loopback.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut tcp, _) = echo.accept().await.expect("one connection");
            let (mut r, mut w) = tcp.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let run = log_in(vec![forward(0, "127.0.0.1", echo_port)], true, false).await;
        let _client = run.client.expect("logged in");
        let server = run.server.expect("the server's handle");
        assert_eq!(*run.asked.lock().unwrap(), [("localhost".to_string(), 0)]);
        assert!(
            run.logged.contains(&format!("Allocated port {CHOSEN} for remote forward to 127.0.0.1:{echo_port}")),
            "{}",
            run.logged
        );

        let mut channel: Channel<ServerMsg> = server
            .channel_open_forwarded_tcpip("localhost", CHOSEN, "192.0.2.1", 40000)
            .await
            .expect("the client accepts the channel it asked for");
        channel.data(&b"through the forward"[..]).await.expect("data sent");
        channel.eof().await.expect("eof sent");
        let mut back = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => back.extend_from_slice(&data),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(back, b"through the forward", "the target's answer, whole");

        match server.channel_open_forwarded_tcpip("localhost", 8080, "192.0.2.1", 40001).await {
            Err(russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)) => {}
            Err(e) => panic!("refused with another reason: {e:?}"),
            Ok(_) => panic!("the client accepted a forwarded channel for a port it did not ask for"),
        }
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// A target that cannot be reached closes that channel only, and says why.
#[tokio::test]
async fn a_forwarded_channel_whose_target_is_down_is_closed() {
    let test = async {
        // A port that nothing listens on: bound, then let go.
        let gone = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let gone_port = gone.local_addr().unwrap().port();
        drop(gone);
        let run = log_in(vec![forward(2290, "127.0.0.1", gone_port)], true, false).await;
        let _client = run.client.expect("logged in");
        let server = run.server.expect("the server's handle");
        let mut channel = server
            .channel_open_forwarded_tcpip("localhost", 2290, "192.0.2.1", 40000)
            .await
            .expect("accepted, then closed");
        let mut closed = false;
        while let Some(msg) = channel.wait().await {
            if matches!(msg, ChannelMsg::Close) {
                closed = true;
            }
        }
        assert!(closed, "the channel is closed");
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// A forward that the server refuses is a warning, and with
/// `ExitOnForwardFailure` the end of the run.
#[tokio::test]
async fn a_refused_forward_warns_or_ends_the_run() {
    let test = async {
        let run = log_in(vec![forward(22, "127.0.0.1", 2203)], false, false).await;
        assert!(run.client.is_ok(), "the run goes on");
        assert!(run.logged.contains("Warning: remote port forwarding failed for listen port 22"), "{}", run.logged);

        let run = log_in(vec![forward(22, "127.0.0.1", 2203)], false, true).await;
        match run.client {
            Err(HopError::Forward(m)) => assert_eq!(m, "Error: remote port forwarding failed for listen port 22"),
            Err(e) => panic!("another error: {e}"),
            Ok(_) => panic!("ExitOnForwardFailure did not end the run"),
        }
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// The address decides between two forwards on one port; the port alone
/// decides else.
#[test]
fn the_port_finds_the_forward_and_the_address_between_two() {
    let table: super::Table = Arc::new(Mutex::new(vec![
        super::Bound { port: 80, forward: RemoteForward { bind: None, port: 80, host: "a".into(), host_port: 1 } },
        super::Bound {
            port: 81,
            forward: RemoteForward { bind: Some(String::new()), port: 81, host: "b".into(), host_port: 2 },
        },
        super::Bound {
            port: 81,
            forward: RemoteForward { bind: Some("10.0.0.1".into()), port: 81, host: "c".into(), host_port: 3 },
        },
    ]));
    assert_eq!(super::find(&table, "127.0.0.1", 80).map(|f| f.host), Some("a".into()));
    assert_eq!(super::find(&table, "10.0.0.1", 81).map(|f| f.host), Some("c".into()));
    assert_eq!(super::find(&table, "", 81).map(|f| f.host), Some("b".into()));
    assert_eq!(super::find(&table, "192.0.2.9", 81), None);
    assert_eq!(super::find(&table, "localhost", 8080), None);
}
