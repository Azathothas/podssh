//! A server that opens channels toward podssh that podssh did not ask for:
//! a russh server in this process, over a pipe.

use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId, ChannelMsg, ChannelOpenFailure};
use tokio::sync::oneshot;

use crate::log::Log;
use crate::options::{Agent, Hop, LogLevel, Options, StrictHostKeyChecking};

/// Lets anyone in, gives its session handle to the test, and answers an exec
/// with exit status 0.
struct Opener(Option<oneshot::Sender<server::Handle>>);

impl server::Handler for Opener {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, session: &mut ServerSession) -> Result<(), Self::Error> {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(session.handle());
        }
        Ok(())
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
        _data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

fn prohibited<T>(what: &str, opened: Result<T, russh::Error>) {
    match opened {
        Err(russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)) => {}
        Err(e) => panic!("{what}: refused with another reason: {e:?}"),
        Ok(_) => panic!("{what}: the client accepted a channel that it did not ask for"),
    }
}

#[tokio::test]
async fn unrequested_channels_are_refused() {
    let test = async {
        let (client_end, server_end) = tokio::io::duplex(1 << 16);
        let mut config = server::Config::default();
        config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
        config.auth_rejection_time = Duration::from_millis(10);
        config.auth_rejection_time_initial = Some(Duration::ZERO);
        let (tx, rx) = oneshot::channel();
        let config = Arc::new(config);
        tokio::spawn(async move {
            if let Ok(session) = server::run_stream(config, server_end, Opener(Some(tx))).await {
                let _ = session.await;
            }
        });

        let dir = std::env::temp_dir().join(format!("podssh-channels-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temporary directory");
        let log_file = dir.join("log");
        let hop = Hop { user: Some("podtest".into()), host: "opener.test".into(), port: 22 };
        let mut opts = Options::new(hop.clone(), "podtest".into());
        opts.connect_timeout = Duration::from_secs(10);
        opts.strict_host_key_checking = StrictHostKeyChecking::No;
        opts.agent = Agent::Off;
        opts.batch_mode = true;
        let log = Arc::new(Log::to_file(LogLevel::Info, &log_file).expect("a log file"));
        let client = crate::run::connect(client_end, &hop, true, &opts, &log).await.expect("logged in");
        let server = rx.await.expect("the server's handle");

        prohibited("forwarded-tcpip", server.channel_open_forwarded_tcpip("127.0.0.1", 8080, "192.0.2.1", 40000).await);
        prohibited("forwarded-streamlocal", server.channel_open_forwarded_streamlocal("/tmp/s").await);
        prohibited("auth-agent", server.channel_open_agent().await);
        prohibited("session", server.channel_open_session().await);
        prohibited("direct-tcpip", server.channel_open_direct_tcpip("127.0.0.1", 22, "192.0.2.1", 40001).await);
        prohibited("direct-streamlocal", server.channel_open_direct_streamlocal("/tmp/s").await);
        prohibited("x11", server.channel_open_x11("192.0.2.1", 6010).await);

        // The session goes on: a command that podssh asked for still runs.
        let mut channel = client.channel_open_session().await.expect("a session channel");
        channel.exec(true, "true").await.expect("exec sent");
        let mut status = None;
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::ExitStatus { exit_status } = msg {
                status = Some(exit_status);
            }
        }
        assert_eq!(status, Some(0), "the exit status of the command");

        let logged = std::fs::read_to_string(&log_file).expect("the log");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(logged.contains("tried agent forwarding"), "{logged}");
        assert!(logged.contains("tried X11 forwarding"), "{logged}");
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}
