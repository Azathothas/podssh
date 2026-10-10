//! `-L` and `-D` against a russh server in this process, over a pipe, with
//! a listener that yields the connections that each test hands it. The
//! server greets each channel that it opens with the target it was asked
//! for, then echoes one read back.

use std::sync::{Arc, Mutex};

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use super::*;
use crate::options::{Agent, Hop, LogLevel, Options, StrictHostKeyChecking};

type Opened = Arc<Mutex<Vec<String>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Lets anyone in, notes each channel asked for, and opens it, or refuses
/// it with `refuse`.
struct Server {
    opened: Opened,
    refuse: Option<ChannelOpenFailure>,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<ServerMsg>,
        host: &str,
        port: u32,
        from: &str,
        from_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        lock(&self.opened).push(format!("tcp {host}:{port} from {from}:{from_port}"));
        self.answer(channel, format!("{host}:{port}"), reply).await;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<ServerMsg>,
        path: &str,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        lock(&self.opened).push(format!("socket {path}"));
        self.answer(channel, path.to_string(), reply).await;
        Ok(())
    }
}

impl Server {
    async fn answer(&self, channel: Channel<ServerMsg>, target: String, reply: server::ChannelOpenHandle) {
        if let Some(reason) = &self.refuse {
            reply.reject(reason.clone()).await;
            return;
        }
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = stream.write_all(format!("hello from {target}\n").as_bytes()).await;
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = stream.write_all(&buf[..n]).await;
            }
        });
    }
}

/// A listener that yields the connections that a test hands it, and fails
/// once the test hands no more.
struct Handed(tokio::sync::Mutex<mpsc::Receiver<Accepted>>);

impl Listen for Handed {
    fn accept(&self) -> Pin<Box<dyn Future<Output = io::Result<Accepted>> + Send + '_>> {
        Box::pin(async move { self.0.lock().await.recv().await.ok_or_else(|| io::Error::other("no more connections")) })
    }
}

/// A forward to `target` with a listener of its own, and the sender that
/// hands it connections.
fn forward(target: Target) -> (LocalForward, mpsc::Sender<Accepted>) {
    let (tx, rx) = mpsc::channel(4);
    let listener: Arc<dyn Listen> = Arc::new(Handed(tokio::sync::Mutex::new(rx)));
    (LocalForward { shown: format!("forward to {target}"), target, listeners: vec![listener] }, tx)
}

/// A client end of a connection, and the `Accepted` of the listener's side.
fn connection(from: Option<SocketAddr>) -> (DuplexStream, Accepted) {
    let (client, ours) = tokio::io::duplex(1 << 16);
    let (read, write) = tokio::io::split(ours);
    (client, Accepted { read: Box::new(read), write: Box::new(write), from })
}

async fn login(refuse: Option<ChannelOpenFailure>) -> (Handle<Client>, Opened, Arc<Log>) {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let opened = Opened::default();
    let handler = Server { opened: opened.clone(), refuse };
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, handler).await {
            let _ = session.await;
        }
    });
    let hop = Hop { user: Some("podtest".into()), host: "forward.test".into(), port: 22 };
    let mut opts = Options::new(hop.clone(), "podtest".into());
    opts.connect_timeout = Duration::from_secs(10);
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let client = crate::run::connect(client_end, &hop, true, &opts, &log).await.expect("logged in");
    (client, opened, log)
}

/// One line from `stream`.
async fn line(stream: &mut DuplexStream) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).await.expect("a read") == 1 && byte[0] != b'\n' {
        out.push(byte[0]);
    }
    String::from_utf8(out).expect("UTF-8")
}

async fn bounded<F: Future>(test: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s")
}

#[tokio::test]
async fn local_forward_carries_each_connection_to_its_target() {
    bounded(async {
        let (client, opened, log) = login(None).await;
        let (fwd, hand) = forward(Target::Tcp { host: "db.internal".into(), port: 5432 });
        let work = async {
            for n in 0..2u16 {
                let (mut ours, accepted) = connection(Some(SocketAddr::from(([127, 0, 0, 1], 40000 + n))));
                hand.send(accepted).await.expect("handed");
                assert_eq!(line(&mut ours).await, "hello from db.internal:5432");
                ours.write_all(b"ping\n").await.expect("a write");
                assert_eq!(line(&mut ours).await, "ping");
            }
        };
        alongside(&client, std::slice::from_ref(&fwd), &log, work).await;
        assert_eq!(
            *lock(&opened),
            ["tcp db.internal:5432 from 127.0.0.1:40000", "tcp db.internal:5432 from 127.0.0.1:40001"]
        );
    })
    .await;
}

#[tokio::test]
async fn local_forward_to_a_socket_of_the_server_opens_streamlocal() {
    bounded(async {
        let (client, opened, log) = login(None).await;
        let (fwd, hand) = forward(Target::Socket("/run/db.sock".into()));
        let work = async {
            let (mut ours, accepted) = connection(None);
            hand.send(accepted).await.expect("handed");
            assert_eq!(line(&mut ours).await, "hello from /run/db.sock");
        };
        alongside(&client, std::slice::from_ref(&fwd), &log, work).await;
        assert_eq!(*lock(&opened), ["socket /run/db.sock"]);
    })
    .await;
}

#[tokio::test]
async fn dynamic_forward_opens_where_each_socks_request_says() {
    bounded(async {
        let (client, opened, log) = login(None).await;
        let (fwd, hand) = forward(Target::Socks);
        let work = async {
            let (mut ours, accepted) = connection(None);
            hand.send(accepted).await.expect("handed");
            let mut request = vec![5, 1, 0, 5, 1, 0, 3, 11];
            request.extend_from_slice(b"db.internal");
            request.extend_from_slice(&5432u16.to_be_bytes());
            ours.write_all(&request).await.expect("a write");
            let mut reply = [0u8; 12];
            ours.read_exact(&mut reply).await.expect("the method and the answer");
            assert_eq!(reply, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0], "granted after the channel opened");
            assert_eq!(line(&mut ours).await, "hello from db.internal:5432");
            // SOCKS4a too.
            let (mut ours, accepted) = connection(None);
            hand.send(accepted).await.expect("handed");
            ours.write_all(b"\x04\x01\x00\x16\x00\x00\x00\x01\x00gate.internal\x00").await.expect("a write");
            let mut reply = [0u8; 8];
            ours.read_exact(&mut reply).await.expect("the answer");
            assert_eq!(reply[1], 90, "granted");
            assert_eq!(line(&mut ours).await, "hello from gate.internal:22");
        };
        alongside(&client, std::slice::from_ref(&fwd), &log, work).await;
        assert_eq!(*lock(&opened), ["tcp db.internal:5432 from 127.0.0.1:0", "tcp gate.internal:22 from 127.0.0.1:0"]);
    })
    .await;
}

#[tokio::test]
async fn a_channel_that_the_server_refuses_is_said_to_the_client() {
    bounded(async {
        for (refusal, code) in
            [(ChannelOpenFailure::ConnectFailed, 5), (ChannelOpenFailure::AdministrativelyProhibited, 2)]
        {
            let (client, _, log) = login(Some(refusal.clone())).await;
            let (socks, hand_socks) = forward(Target::Socks);
            let (plain, hand_plain) = forward(Target::Tcp { host: "db.internal".into(), port: 1 });
            let work = async {
                let (mut ours, accepted) = connection(None);
                hand_socks.send(accepted).await.expect("handed");
                ours.write_all(&[5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 1, 0, 80]).await.expect("a write");
                let mut reply = [0u8; 12];
                ours.read_exact(&mut reply).await.expect("the method and the answer");
                assert_eq!(reply[3], code, "SOCKS5 code of {refusal:?}");
                // -L: the client's connection is closed.
                let (mut ours, accepted) = connection(None);
                hand_plain.send(accepted).await.expect("handed");
                let mut byte = [0u8; 1];
                assert_eq!(ours.read(&mut byte).await.expect("a read"), 0, "closed");
            };
            alongside(&client, &[socks, plain], &log, work).await;
        }
    })
    .await;
}

#[tokio::test]
async fn serving_ends_once_no_listener_is_left_and_the_work_goes_on() {
    bounded(async {
        let (client, _, log) = login(None).await;
        let (fwd, hand) = forward(Target::Tcp { host: "db.internal".into(), port: 1 });
        drop(hand);
        let served =
            tokio::time::timeout(Duration::from_secs(10), serve(&client, std::slice::from_ref(&fwd), &log)).await;
        assert!(served.is_ok(), "serve ended when its one listener failed");
        let worked = alongside(&client, &[fwd], &log, async { 7 }).await;
        assert_eq!(worked, 7);
    })
    .await;
}

#[tokio::test]
async fn closed_waits_for_the_end_of_the_connection() {
    bounded(async {
        let (client, _, _) = login(None).await;
        assert!(tokio::time::timeout(Duration::from_millis(500), closed(&client)).await.is_err(), "still open");
        client.disconnect(russh::Disconnect::ByApplication, "", "en").await.expect("disconnected");
        tokio::time::timeout(Duration::from_secs(10), closed(&client)).await.expect("closed after the disconnect");
    })
    .await;
}
