//! A podssh master and podssh's client on a control socket in a scratch
//! directory, over a connection to a russh server in this process: `-O
//! check`, a session on pipes, a stdio forward, the forwards of `-O
//! forward` and `-O cancel`, `-O stop`, `-O exit` and `ControlPersist`.
//! The protocol itself is checked against OpenSSH's bytes in
//! `proto_tests.rs`, and against OpenSSH's processes in the gate.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

use super::client::{self, SessionRequest, Unreached};
use super::master::{Binder, Control, Persist, Served};
use super::proto::{Fwd, FwdKind};
use super::{alongside, Mastered};
use crate::handler::Client;
use crate::local::{Accepted, Listen, LocalForward, Target};
use crate::log::Log;
use crate::options::{Agent, Hop, LogLevel, Options, StrictHostKeyChecking};

/// The port that the server chooses for a forward of port 0.
const CHOSEN: u32 = 40309;

/// Lets anyone in; an exec of `exit N` prints the command on stdout and
/// `err` on stderr, then exits N; a direct-tcpip channel greets with its
/// target and echoes one read; a forward of port 0 gets [`CHOSEN`].
struct Far;

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<ServerMsg>,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let command = String::from_utf8_lossy(data).into_owned();
        let code = command.strip_prefix("exit ").and_then(|n| n.parse().ok()).unwrap_or(0);
        let handle = session.handle();
        tokio::spawn(async move {
            let _ = handle.data(channel, format!("out:{command}\n").into_bytes()).await;
            let _ = handle.extended_data(channel, 1, b"err\n".to_vec()).await;
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<ServerMsg>,
        host: &str,
        port: u32,
        _from: &str,
        _from_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let greeting = format!("hello from {host}:{port}\n");
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = stream.write_all(greeting.as_bytes()).await;
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = stream.write_all(&buf[..n]).await;
            }
        });
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        port: &mut u32,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        if *port == 0 {
            *port = CHOSEN;
        }
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        _address: &str,
        _port: u32,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A directory of the test's own, gone at its end.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("podssh-mux-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        Scratch(dir)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("ctl")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A listener that yields the connections that a test hands it.
struct Handed(tokio::sync::Mutex<mpsc::Receiver<Accepted>>);

impl Listen for Handed {
    fn accept(&self) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<Accepted>> + Send + '_>> {
        Box::pin(async move { self.0.lock().await.recv().await.ok_or_else(|| std::io::Error::other("no more")) })
    }
}

async fn login() -> (russh::client::Handle<Client>, Arc<Log>) {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, Far).await {
            let _ = session.await;
        }
    });
    let hop = Hop { user: Some("podtest".into()), host: "mux.test".into(), port: 22 };
    let mut opts = Options::new(hop.clone(), "podtest".into());
    opts.connect_timeout = Duration::from_secs(10);
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let client = crate::run::connect(client_end, &hop, true, &opts, &log).await.expect("logged in");
    (client, log)
}

fn control(scratch: &Scratch, persist: Persist, binder: Option<Binder>) -> Control {
    let listener = UnixListener::bind(scratch.socket()).expect("the control socket binds");
    Control { listener, path: scratch.socket(), persist, binder, ask: false, agent: false, host: "mux.test".into() }
}

async fn bounded<F: std::future::Future>(test: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s")
}

#[tokio::test]
async fn mux_master_serves_check_a_session_and_a_stdio_forward() {
    bounded(async {
        let scratch = Scratch::new("serve");
        let (client, log) = login().await;
        let path = scratch.socket();
        let work = async {
            let mut c = client::connect(&path).await.expect("a master");
            assert_eq!(c.alive().await, Ok(std::process::id()), "-O check gives the master's pid");
            // A session on pipes: stdin at its end, stdout and stderr read after.
            let (stdin_r, stdin_w) = std::io::pipe().unwrap();
            drop(stdin_w);
            let (mut out_r, out_w) = std::io::pipe().unwrap();
            let (mut err_r, err_w) = std::io::pipe().unwrap();
            let request = SessionRequest { command: b"exit 3".to_vec(), host: "mux.test".into(), ..Default::default() };
            let c = client::connect(&path).await.expect("a master");
            let fds = [stdin_r.as_raw_fd(), out_w.as_raw_fd(), err_w.as_raw_fd()];
            assert_eq!(c.session_on(request, fds, &log).await, 3, "the session's status");
            // The master made them non-blocking while it used them, and put
            // the flags back: they are the client's terminal too.
            for fd in fds {
                // SAFETY: fcntl on a descriptor that this test holds open.
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                assert_eq!(flags & libc::O_NONBLOCK, 0, "descriptor {fd} was left non-blocking");
            }
            drop((stdin_r, out_w, err_w));
            let (mut out, mut err) = (String::new(), String::new());
            out_r.read_to_string(&mut out).unwrap();
            err_r.read_to_string(&mut err).unwrap();
            assert_eq!((out.as_str(), err.as_str()), ("out:exit 3\n", "err\n"));
            // A stdio forward: what the server greets with, then the echo.
            let (stdin_r, mut stdin_w) = std::io::pipe().unwrap();
            stdin_w.write_all(b"ping\n").unwrap();
            drop(stdin_w);
            let (mut out_r, out_w) = std::io::pipe().unwrap();
            let c = client::connect(&path).await.expect("a master");
            let db = crate::options::StdioTarget::Tcp { host: "db.internal".into(), port: 5432 };
            assert_eq!(c.stdio_on(&db, [stdin_r.as_raw_fd(), out_w.as_raw_fd()], &log).await, 0);
            drop((stdin_r, out_w));
            let mut got = String::new();
            out_r.read_to_string(&mut got).unwrap();
            assert_eq!(got, "hello from db.internal:5432\nping\n");
        };
        match alongside(&client, Some(control(&scratch, Persist::No, None)), &log, work).await {
            Mastered::Done(()) => {}
            Mastered::Ended(why) => panic!("the master ended the run: {why:?}"),
        }
        assert!(!scratch.socket().exists(), "the socket goes with the master");
    })
    .await;
}

#[tokio::test]
async fn mux_master_takes_forwards_and_stops_listening() {
    bounded(async {
        let scratch = Scratch::new("forwards");
        let (client, log) = login().await;
        let path = scratch.socket();
        let (hand, handed) = mpsc::channel::<Accepted>(4);
        let handed = Arc::new(Handed(tokio::sync::Mutex::new(handed)));
        let binder: Binder = Arc::new(move |fwd: Fwd| {
            let listener: Arc<dyn Listen> = handed.clone();
            Box::pin(async move {
                let target = Target::Tcp { host: fwd.connect_host.clone(), port: fwd.connect_port as u16 };
                Ok(LocalForward { shown: "-O forward -L".into(), target, listeners: vec![listener] })
            })
        });
        let work = async {
            let mut c = client::connect(&path).await.expect("a master");
            let remote = Fwd {
                kind: FwdKind::Remote,
                listen_host: String::new(),
                listen_port: 0,
                connect_host: "127.0.0.1".into(),
                connect_port: 22,
            };
            assert_eq!(c.forward(remote.clone(), false).await, Ok(Some(CHOSEN)), "the port the server chose");
            assert_eq!(c.forward(remote, true).await, Ok(None), "cancelled");
            let local = Fwd {
                kind: FwdKind::Local,
                listen_host: String::new(),
                listen_port: 8085,
                connect_host: "db.internal".into(),
                connect_port: 5432,
            };
            assert_eq!(c.forward(local.clone(), false).await, Ok(None));
            let (mut ours, theirs) = tokio::io::duplex(1 << 12);
            let (read, write) = tokio::io::split(theirs);
            hand.send(Accepted { read: Box::new(read), write: Box::new(write), from: None }).await.unwrap();
            let mut greeting = vec![0u8; "hello from db.internal:5432\n".len()];
            ours.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, b"hello from db.internal:5432\n", "the master serves the new forward");
            assert_eq!(c.forward(local.clone(), true).await, Ok(None));
            assert!(c.forward(local, true).await.unwrap_err().contains("no such forward"));
            // -O stop: the socket goes, and nobody new gets in.
            assert_eq!(c.stop().await, Ok(()));
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(matches!(client::connect(&path).await, Err(Unreached::NoMaster(_))), "no master after -O stop");
        };
        assert!(matches!(
            alongside(&client, Some(control(&scratch, Persist::No, Some(binder))), &log, work).await,
            Mastered::Done(())
        ));
    })
    .await;
}

#[tokio::test]
async fn mux_master_ends_at_exit_and_when_idle() {
    bounded(async {
        let scratch = Scratch::new("exit");
        let (client, log) = login().await;
        let path = scratch.socket();
        let work = async {
            let mut c = client::connect(&path).await.expect("a master");
            assert_eq!(c.terminate().await, Ok(()));
            std::future::pending::<()>().await;
        };
        let ended = alongside(&client, Some(control(&scratch, Persist::No, None)), &log, work).await;
        assert!(matches!(ended, Mastered::Ended(Served::Terminated)), "-O exit ends the run");
        assert!(!scratch.socket().exists());
        // ControlPersist: no client for that long ends the run.
        let idle = control(&scratch, Persist::For(Duration::from_millis(300)), None);
        let ended = alongside(&client, Some(idle), &log, std::future::pending::<()>()).await;
        assert!(matches!(ended, Mastered::Ended(Served::Idle)), "an idle master ends");
    })
    .await;
}
