//! T-661 through russh, both ends in this process over a pipe: podssh's
//! client grants each channel's window to the target that its handler
//! gives, here a road's cap of 64 KiB, where russh 0.65.0 granted its
//! configured window (512 KiB) whatever the handler returned. Without the
//! patch of `vendor/patches/russh/`, or with the hook not taken, the server
//! sees a window far over the cap. And the channel asks for messages of
//! [`super::PACKET`] at most, which the server keeps to (T-670).

use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId, ChannelMsg};

use crate::log::Log;
use crate::options::{Agent, Hop, LogLevel, Options, StrictHostKeyChecking};

const CAP: u32 = 64 * 1024;
/// What the server sends: 64 windows of the cap.
const BULK: usize = 4 << 20;

/// What the server saw of podssh's windows: the largest after an adjust,
/// and the adjusts.
#[derive(Default)]
struct Seen {
    largest: AtomicU32,
    adjusts: AtomicU32,
}

/// Lets anyone in, and answers an exec with [`BULK`] bytes, each as the
/// window lets it go, then status 0.
struct Sender {
    channel: Option<Channel<ServerMsg>>,
    seen: Arc<Seen>,
}

impl server::Handler for Sender {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<ServerMsg>,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.channel = Some(channel);
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
        if let Some(channel) = self.channel.take() {
            tokio::spawn(async move {
                let bulk = vec![0x5a_u8; BULK];
                let _ = channel.data(&bulk[..]).await;
                let _ = channel.exit_status(0).await;
                let _ = channel.eof().await;
                let _ = channel.close().await;
            });
        }
        Ok(())
    }

    /// No data waits in the server's queue (the channel sends only what
    /// its window takes), so `new_size` is the whole window after the
    /// adjust.
    async fn window_adjusted(
        &mut self,
        _channel: ChannelId,
        new_size: u32,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.seen.largest.fetch_max(new_size, Relaxed);
        self.seen.adjusts.fetch_add(1, Relaxed);
        Ok(())
    }
}

#[tokio::test]
async fn a_channel_is_granted_the_handlers_target_not_russhs_window() {
    let test = async {
        let (client_end, server_end) = tokio::io::duplex(1 << 16);
        let mut config = server::Config::default();
        config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
        config.auth_rejection_time = Duration::from_millis(10);
        config.auth_rejection_time_initial = Some(Duration::ZERO);
        let config = Arc::new(config);
        let seen = Arc::new(Seen::default());
        let handler = Sender { channel: None, seen: seen.clone() };
        tokio::spawn(async move {
            if let Ok(session) = server::run_stream(config, server_end, handler).await {
                let _ = session.await;
            }
        });

        let dir = std::env::temp_dir().join(format!("podssh-pace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temporary directory");
        let hop = Hop { user: Some("podtest".into()), host: "pace.test".into(), port: 22, tls: false };
        let mut opts = Options::new(hop.clone(), "podtest".into());
        opts.connect_timeout = Duration::from_secs(10);
        opts.strict_host_key_checking = StrictHostKeyChecking::No;
        opts.user_known_hosts = vec![dir.join("known_hosts")];
        opts.agent = Agent::Off;
        opts.batch_mode = true;
        opts.window_cap = CAP;
        let log = Arc::new(Log::to_file(LogLevel::Info, &dir.join("log")).expect("a log file"));
        let client = crate::run::connect(client_end, &hop, true, &opts, &log).await.expect("logged in");

        let mut channel = client.channel_open_session().await.expect("a session channel");
        channel.exec(true, "bulk").await.expect("exec sent");
        let (mut got, mut status, mut largest_message) = (0usize, None, 0usize);
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    got += data.len();
                    largest_message = largest_message.max(data.len());
                }
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got, BULK, "each byte came");
        assert_eq!(status, Some(0));
        let (largest, adjusts) = (seen.largest.load(Relaxed), seen.adjusts.load(Relaxed));
        assert!(adjusts >= 32, "the window was adjusted as the data came: {adjusts} adjusts");
        assert!(largest <= CAP, "the server was granted {largest} bytes at once, over the cap of {CAP}");
        let packet = super::PACKET as usize;
        assert!(largest_message <= packet, "a message of {largest_message} bytes, over the {packet} asked for");
        assert_eq!(largest_message, packet, "the server sent as much as each message took");
    };
    tokio::time::timeout(Duration::from_secs(60), test).await.expect("the test ends within 60 s");
}
