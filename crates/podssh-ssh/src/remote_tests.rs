//! The channels of `-R` against a server that takes forwards: a russh server
//! in this process, over a pipe, that listens on nothing; it opens the
//! `forwarded-tcpip` channels itself, as a server does for each connection
//! that it takes on a forwarded port.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId, ChannelMsg, ChannelOpenFailure};
use tokio::sync::oneshot;

use crate::log::Log;
use crate::options::{Again, Agent, Hop, LogLevel, Options, RemoteForward, StrictHostKeyChecking};
use crate::run::HopError;

/// The port that the server chooses for a forward that asks for 0.
const CHOSEN: u32 = 4242;

/// What `asked` keeps for a path, which has no port.
const PATH: u32 = u32::MAX;

/// Lets anyone in, gives its session handle to the test, and takes each
/// forward after refusing the first `refuse` requests: the requests it saw
/// are kept. With `open_first`, it opens a channel for a taken port before
/// it answers, as a connection that comes at once can make a server do;
/// `opened` keeps each channel that the client accepted.
struct Forwarder {
    handle: Option<oneshot::Sender<server::Handle>>,
    refuse: usize,
    asked: Arc<Mutex<Vec<(String, u32)>>>,
    open_first: bool,
    opened: Arc<Mutex<Vec<ChannelId>>>,
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
        session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        let mut asked = self.asked.lock().unwrap();
        asked.push((address.to_string(), *port));
        if *port == 0 {
            *port = CHOSEN;
        }
        let take = asked.len() > self.refuse;
        if take && self.open_first {
            // Written now, so it goes out before the answer to the request.
            session.channel_open_forwarded_tcpip(address, *port, "192.0.2.1", 40000)?;
        }
        Ok(take)
    }

    async fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        let mut asked = self.asked.lock().unwrap();
        asked.push((socket_path.to_string(), PATH));
        Ok(asked.len() > self.refuse)
    }

    async fn channel_open_confirmation(
        &mut self,
        id: ChannelId,
        _max_packet_size: u32,
        _window_size: u32,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.opened.lock().unwrap().push(id);
        Ok(())
    }
}

struct Run {
    client: Result<russh::client::Handle<crate::handler::Client>, HopError>,
    server: Option<server::Handle>,
    asked: Arc<Mutex<Vec<(String, u32)>>>,
    opened: Arc<Mutex<Vec<ChannelId>>>,
    logged: String,
}

/// Log in with `forwards`, the server taking them or not.
async fn log_in(forwards: Vec<RemoteForward>, take: bool, exit_on_failure: bool) -> Run {
    log_in_again(forwards, if take { 0 } else { usize::MAX }, exit_on_failure, None).await
}

/// Log in with `forwards`, the server refusing the first `refuse` requests,
/// and a refused one asked again as `again` says.
async fn log_in_again(forwards: Vec<RemoteForward>, refuse: usize, exit_on_failure: bool, again: Option<Again>) -> Run {
    log_in_with(forwards, refuse, exit_on_failure, again, false).await
}

/// `log_in_again`, the server opening a channel for each forward that it
/// takes before it answers, when `open_first` says so.
async fn log_in_with(
    forwards: Vec<RemoteForward>,
    refuse: usize,
    exit_on_failure: bool,
    again: Option<Again>,
    open_first: bool,
) -> Run {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let (tx, rx) = oneshot::channel();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let opened = Arc::new(Mutex::new(Vec::new()));
    let forwarder = Forwarder { handle: Some(tx), refuse, asked: asked.clone(), open_first, opened: opened.clone() };
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, forwarder).await {
            let _ = session.await;
        }
    });

    let dir = std::env::temp_dir().join(format!("podssh-remote-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    let log_file = dir.join("log");
    let hop = Hop { user: Some("podtest".into()), host: "forwarder.test".into(), port: 22, tls: false };
    let mut opts = Options::new(hop.clone(), "podtest".into());
    opts.connect_timeout = Duration::from_secs(10);
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.remote_forwards = forwards;
    opts.exit_on_forward_failure = exit_on_failure;
    opts.forwards_again = again;
    let log = Arc::new(Log::to_file(LogLevel::Info, &log_file).expect("a log file"));
    let client = crate::run::connect(client_end, &hop, true, &opts, &log).await;
    let server = match &client {
        Ok(_) => Some(rx.await.expect("the server's handle")),
        Err(_) => None,
    };
    let logged = std::fs::read_to_string(&log_file).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    Run { client, server, asked, opened, logged }
}

fn forward(port: u16, host: &str, host_port: u16) -> RemoteForward {
    RemoteForward::tcp(None, port, host, host_port)
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

/// After a loss of `--persist` (T-042), a forward that the server refuses
/// is asked again until it takes it, as the old connection may hold its
/// port; with no loss, once, as OpenSSH asks.
#[tokio::test]
async fn a_forward_refused_after_a_loss_is_asked_again_until_the_server_takes_it() {
    let test = async {
        let again = Again { within: Duration::from_secs(20), wait: |_| Duration::from_millis(20) };
        let run = log_in_again(vec![forward(2291, "127.0.0.1", 2203)], 2, true, Some(again)).await;
        assert!(run.client.is_ok(), "{}", run.logged);
        assert_eq!(run.asked.lock().unwrap().len(), 3, "{}", run.logged);
        let said = "the server refused -R 2291:127.0.0.1:2203, which it may still hold for the lost connection; \
                    asking again in";
        assert_eq!(run.logged.matches(said).count(), 2, "{}", run.logged);
        assert!(!run.logged.contains("remote port forwarding failed"), "{}", run.logged);

        let run = log_in_again(vec![forward(2291, "127.0.0.1", 2203)], 2, false, None).await;
        assert_eq!(run.asked.lock().unwrap().len(), 1, "{}", run.logged);
        assert!(run.logged.contains("Warning: remote port forwarding failed for listen port 2291"), "{}", run.logged);
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// A forward that the server still refuses when the time is up is refused
/// as on the first connection: a warning, or with `ExitOnForwardFailure`
/// the end of the run (T-042).
#[tokio::test]
async fn a_forward_refused_for_the_whole_time_warns_or_ends_the_run() {
    let test = async {
        // Each ask is a round trip, which took more than 260 ms on a loaded
        // host; 300 ms then held one ask again, not two. 2 s holds several.
        let again = Again { within: Duration::from_secs(2), wait: |_| Duration::from_millis(40) };
        let run = log_in_again(vec![forward(2291, "127.0.0.1", 2203)], usize::MAX, false, Some(again)).await;
        assert!(run.client.is_ok(), "the run goes on: {}", run.logged);
        assert!(run.asked.lock().unwrap().len() > 2, "{}", run.logged);
        assert!(run.logged.contains("Warning: remote port forwarding failed for listen port 2291"), "{}", run.logged);

        let run = log_in_again(vec![forward(2291, "127.0.0.1", 2203)], usize::MAX, true, Some(again)).await;
        assert!(run.asked.lock().unwrap().len() > 2, "{}", run.logged);
        match run.client {
            Err(HopError::Forward(m)) => assert_eq!(m, "Error: remote port forwarding failed for listen port 2291"),
            Err(e) => panic!("another error: {e}"),
            Ok(_) => panic!("ExitOnForwardFailure did not end the run"),
        }
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// A server may open a channel for a forward as soon as it takes it, before
/// podssh reads its answer: a port named in advance is podssh's from the
/// request on, as in OpenSSH's client, so the channel is accepted (T-042,
/// a test of `--persist` that failed once at random so).
#[tokio::test]
async fn a_channel_that_comes_before_the_answer_is_accepted() {
    let test = async {
        let run = log_in_with(vec![forward(2292, "127.0.0.1", 9)], 0, false, None, true).await;
        assert!(run.client.is_ok(), "{}", run.logged);
        let started = std::time::Instant::now();
        while run.opened.lock().unwrap().is_empty() && started.elapsed() < Duration::from_secs(10) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(run.opened.lock().unwrap().len(), 1, "the channel was refused: {}", run.logged);
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// The address decides between two forwards on one port; the port alone
/// decides else.
#[test]
fn the_port_finds_the_forward_and_the_address_between_two() {
    use super::Listening::Port;
    let table: super::Table = Arc::new(Mutex::new(vec![
        super::Bound { at: Port(80), forward: RemoteForward::tcp(None, 80, "a", 1) },
        super::Bound { at: Port(81), forward: RemoteForward::tcp(Some(String::new()), 81, "b", 2) },
        super::Bound { at: Port(81), forward: RemoteForward::tcp(Some("10.0.0.1".into()), 81, "c", 3) },
    ]));
    let host = |f: RemoteForward| match f.target {
        crate::options::RemoteTarget::Tcp { host, .. } => host,
        other => panic!("{other:?}"),
    };
    assert_eq!(super::find(&table, "127.0.0.1", 80).map(host), Some("a".into()));
    assert_eq!(super::find(&table, "10.0.0.1", 81).map(host), Some("c".into()));
    assert_eq!(super::find(&table, "", 81).map(host), Some("b".into()));
    assert_eq!(super::find(&table, "192.0.2.9", 81), None);
    assert_eq!(super::find(&table, "localhost", 8080), None);
}

/// Bytes of `channel` until `n` came, or its end.
async fn read_n(channel: &mut Channel<ServerMsg>, n: usize) -> Vec<u8> {
    let mut back = Vec::new();
    while back.len() < n {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => back.extend_from_slice(&data),
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
            _ => {}
        }
    }
    back
}

/// An echo of one connection on the loopback, and its port.
async fn echo() -> u16 {
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut tcp, _) = echo.accept().await.expect("one connection");
        let (mut r, mut w) = tcp.split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });
    port
}

/// A path on the server is asked for with `streamlocal-forward`; a channel
/// for that path reaches the target whole, and one for another path is
/// refused (T-365).
#[tokio::test]
async fn a_streamlocal_channel_for_the_path_asked_for_reaches_its_target_and_another_is_refused() {
    let test = async {
        let echo_port = echo().await;
        let forward = RemoteForward {
            listen: crate::options::RemoteListen::Path("/srv/r.sock".into()),
            target: crate::options::RemoteTarget::Tcp { host: "127.0.0.1".into(), port: echo_port },
        };
        let run = log_in(vec![forward], true, false).await;
        let _client = run.client.expect("logged in");
        let server = run.server.expect("the server's handle");
        assert_eq!(*run.asked.lock().unwrap(), [("/srv/r.sock".to_string(), PATH)]);
        let mut channel = server
            .channel_open_forwarded_streamlocal("/srv/r.sock")
            .await
            .expect("the client accepts the channel of the path it asked for");
        channel.data(&b"through the socket's forward"[..]).await.expect("data sent");
        channel.eof().await.expect("eof sent");
        assert_eq!(read_n(&mut channel, 28).await, b"through the socket's forward", "the target's answer, whole");
        match server.channel_open_forwarded_streamlocal("/srv/other.sock").await {
            Err(russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)) => {}
            Err(e) => panic!("refused with another reason: {e:?}"),
            Ok(_) => panic!("the client accepted a channel for a path it did not ask for"),
        }
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// A socket on this host as the target: each channel reaches it.
#[cfg(unix)]
#[tokio::test]
async fn a_socket_on_this_host_is_the_target_of_each_channel() {
    let test = async {
        let dir = std::env::temp_dir().join(format!("podssh-r-sock-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).expect("a directory");
        let path = dir.join("echo.sock");
        let echo = tokio::net::UnixListener::bind(&path).expect("an echo on a socket");
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.expect("one connection");
            let (mut r, mut w) = stream.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        let forward = RemoteForward {
            listen: crate::options::RemoteListen::Port { bind: None, port: 0 },
            target: crate::options::RemoteTarget::Socket(path.to_string_lossy().into_owned()),
        };
        let run = log_in(vec![forward], true, false).await;
        let _client = run.client.expect("logged in");
        let server = run.server.expect("the server's handle");
        let mut channel =
            server.channel_open_forwarded_tcpip("localhost", CHOSEN, "192.0.2.1", 40000).await.expect("accepted");
        channel.data(&b"to a socket here"[..]).await.expect("data sent");
        channel.eof().await.expect("eof sent");
        assert_eq!(read_n(&mut channel, 16).await, b"to a socket here");
        let _ = std::fs::remove_dir_all(&dir);
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}

/// The SOCKS form: a SOCKS5 request on the channel reaches its target, and
/// is answered after the dial; a target that is down gets its code, 5.
#[tokio::test]
async fn the_socks_form_answers_after_its_dial_and_names_a_target_that_is_down() {
    let test = async {
        let echo_port = echo().await;
        let gone = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let gone_port = gone.local_addr().unwrap().port();
        drop(gone);
        let forward = RemoteForward {
            listen: crate::options::RemoteListen::Port { bind: None, port: 1080 },
            target: crate::options::RemoteTarget::Socks,
        };
        let run = log_in(vec![forward], true, false).await;
        let _client = run.client.expect("logged in");
        let server = run.server.expect("the server's handle");
        let request = |port: u16| [&[5, 1, 0, 1, 127, 0, 0, 1][..], &port.to_be_bytes()[..]].concat();
        let mut channel =
            server.channel_open_forwarded_tcpip("localhost", 1080, "192.0.2.1", 40000).await.expect("accepted");
        channel.data(&[5u8, 1, 0][..]).await.expect("the greeting");
        assert_eq!(read_n(&mut channel, 2).await, [5, 0], "no authentication");
        channel.data(&request(echo_port)[..]).await.expect("the request");
        assert_eq!(read_n(&mut channel, 10).await, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0], "granted after the dial");
        channel.data(&b"through SOCKS"[..]).await.expect("data sent");
        channel.eof().await.expect("eof sent");
        assert_eq!(read_n(&mut channel, 13).await, b"through SOCKS");

        let mut down =
            server.channel_open_forwarded_tcpip("localhost", 1080, "192.0.2.1", 40001).await.expect("accepted");
        down.data(&[5u8, 1, 0][..]).await.expect("the greeting");
        assert_eq!(read_n(&mut down, 2).await, [5, 0]);
        down.data(&request(gone_port)[..]).await.expect("the request");
        assert_eq!(read_n(&mut down, 10).await, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0], "refused: the target is down");
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}
