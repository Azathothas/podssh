//! Fewer round trips before the first command (T-664), against russh's own
//! server in this process:
//!
//! - the key that a host took is kept, and the next login signs it in its
//!   first request: the server sees no `none` and no query before it;
//! - a host that no longer takes that key lets the usual way go on, with the
//!   other keys, and the record moves to the key that it took;
//! - the pty's request and the command's go together: a server that answers
//!   the pty only once the command's request came still starts the command
//!   at once, where a client that waits for the pty's answer first waits 30 s.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_ssh::accepted::{self, KeptFile};
use podssh_ssh::run::{connect_hops, disconnect_all};
use podssh_ssh::{Agent, Hop, Log, LogLevel, Options, Request, RequestTty, StrictHostKeyChecking};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg as ServerMsg, Session as ServerSession};
use russh::{Channel, ChannelId, Pty};

const USER: &str = "podtest";
const LIMIT: Duration = Duration::from_secs(10);

/// The record of the keys that hosts took, in this process's memory: one
/// for the whole test binary, as a run has one. Each test's server has a
/// host key of its own, so its lines are its own.
#[derive(Clone, Default)]
struct Memory(Arc<Mutex<Option<String>>>);

impl KeptFile for Memory {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }

    fn store(&self, text: &[u8]) {
        *self.0.lock().unwrap() = Some(String::from_utf8_lossy(text).into_owned());
    }
}

fn record() -> &'static Memory {
    static RECORD: OnceLock<Memory> = OnceLock::new();
    RECORD.get_or_init(|| {
        let memory = Memory::default();
        accepted::keep_in(Box::new(memory.clone()));
        memory
    })
}

/// A test's directory of its own, gone when the test ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Key files of `count` new Ed25519 keys, mode 0600, under a new directory.
fn key_files(tag: &str, count: usize) -> (Scratch, Vec<(PathBuf, PublicKey)>) {
    let dir = std::env::temp_dir().join(format!("podssh-cold-connect-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a directory for the keys");
    let mut files = Vec::new();
    for n in 0..count {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a key");
        let path = dir.join(format!("id_{n}"));
        write_private(&path, key.to_openssh(LineEnding::LF).expect("the key's text").as_bytes());
        files.push((path, key.public_key().clone()));
    }
    (Scratch(dir), files)
}

fn write_private(path: &Path, body: &[u8]) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).and_then(|mut file| file.write_all(body)).expect("the key file");
}

/// podssh's options for the stand-in: no agent, never a prompt, the key
/// files given, any host key taken and none recorded.
fn options(files: &[(PathBuf, PublicKey)]) -> Options {
    let hop = Hop { user: Some(USER.into()), host: "stand-in.test".into(), port: 22, tls: false };
    let mut opts = Options::new(hop, USER.into());
    opts.connect_timeout = LIMIT;
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.identities_only = true;
    opts.identity_files = files.iter().map(|(path, _)| path.clone()).collect();
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.log_level = LogLevel::Quiet;
    opts
}

/// A server's configuration with `host` as its key, and no wait after a
/// refusal.
fn config(host: &PrivateKey) -> Arc<server::Config> {
    let mut config = server::Config::default();
    config.keys.push(host.clone());
    config.auth_rejection_time = Duration::from_millis(1);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    Arc::new(config)
}

/// What the stand-in of the keys saw: each `none`, and the key it takes.
#[derive(Clone, Default)]
struct Keys {
    takes: Arc<Mutex<Option<PublicKey>>>,
    nones: Arc<AtomicUsize>,
}

impl Keys {
    fn verdict(&self, key: &PublicKey) -> Auth {
        let takes = self.takes.lock().unwrap();
        if takes.as_ref().is_some_and(|taken| taken.key_data() == key.key_data()) {
            Auth::Accept
        } else {
            Auth::reject()
        }
    }
}

impl server::Handler for Keys {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        self.nones.fetch_add(1, Ordering::SeqCst);
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(self.verdict(offer.public_key))
    }

    async fn auth_publickey(&mut self, _user: &str, key: server::VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        Ok(self.verdict(key.public_key))
    }
}

/// One login to a stand-in with `host` as its key: whether it got in, and
/// how many `none` requests it saw.
async fn login(host: &PrivateKey, seen: &Keys, opts: &Options) -> (Result<(), String>, usize) {
    let before = seen.nones.load(Ordering::SeqCst);
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let (config, handler) = (config(host), seen.clone());
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, handler).await {
            let _ = session.await;
        }
    });
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let logged = tokio::time::timeout(LIMIT * 2, connect_hops(client_end, opts, &log)).await.expect("in time");
    let got = match logged {
        Ok(handles) => {
            disconnect_all(&handles).await;
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    };
    (got, seen.nones.load(Ordering::SeqCst) - before)
}

/// The fingerprint that the record holds for `host` and [`USER`].
fn kept_for(host: &PrivateKey) -> Option<String> {
    let id = accepted::host_id(USER, &host.public_key().to_bytes().expect("the host key's blob"));
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("a clock after 1970").as_millis();
    let record = accepted::Accepted::read(&record().load()?, i64::try_from(now).expect("a time")).expect("it reads");
    record.key(&id).map(str::to_string)
}

#[tokio::test]
async fn a_second_login_signs_the_key_that_the_host_took_at_once() {
    record();
    let (_scratch, files) = key_files("again", 1);
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key");
    let seen = Keys::default();
    *seen.takes.lock().unwrap() = Some(files[0].1.clone());
    let opts = options(&files);
    let (first, nones) = login(&host, &seen, &opts).await;
    assert_eq!(first, Ok(()));
    assert_eq!(nones, 1, "the first login asks with none");
    let fingerprint = podssh_ssh::known_hosts::fingerprint(&files[0].1);
    assert_eq!(kept_for(&host), Some(fingerprint), "the key that the host took is kept");
    let (second, nones) = login(&host, &seen, &opts).await;
    assert_eq!(second, Ok(()));
    assert_eq!(nones, 0, "the second login signs the kept key first, with no none and no query");
}

#[tokio::test]
async fn a_host_that_no_longer_takes_the_key_lets_the_other_keys_in() {
    record();
    let (_scratch, files) = key_files("moved", 2);
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key");
    let seen = Keys::default();
    *seen.takes.lock().unwrap() = Some(files[0].1.clone());
    let opts = options(&files);
    assert_eq!(login(&host, &seen, &opts).await.0, Ok(()));
    assert_eq!(kept_for(&host), Some(podssh_ssh::known_hosts::fingerprint(&files[0].1)));
    // The host now takes the second key alone.
    *seen.takes.lock().unwrap() = Some(files[1].1.clone());
    let (moved, nones) = login(&host, &seen, &opts).await;
    assert_eq!(moved, Ok(()), "the usual way goes on after the refusal");
    assert_eq!(nones, 0, "the refusal's list of methods stood in for none's");
    assert_eq!(kept_for(&host), Some(podssh_ssh::known_hosts::fingerprint(&files[1].1)));
}

/// A server that answers the pty's request only once the command's came:
/// the command's request must go before the pty's answer.
#[derive(Clone, Default)]
struct Holds {
    pty: Arc<Mutex<Option<ChannelId>>>,
    together: Arc<AtomicUsize>,
}

impl server::Handler for Holds {
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

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _px_width: u32,
        _px_height: u32,
        _modes: &[(Pty, u32)],
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        *self.pty.lock().unwrap() = Some(channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        // The pty's answer, late, then the command's: in the order asked.
        if self.pty.lock().unwrap().take().is_some() {
            self.together.fetch_add(1, Ordering::SeqCst);
            session.channel_success(channel)?;
        }
        session.channel_success(channel)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

#[tokio::test]
async fn the_pty_and_the_command_go_together() {
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key");
    let seen = Holds::default();
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let (config, handler) = (config(&host), seen.clone());
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, handler).await {
            let _ = session.await;
        }
    });
    let mut opts = options(&[]);
    opts.request = Request::Exec("true".into());
    opts.request_tty = RequestTty::Force;
    opts.stdin_null = true;
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let handles = connect_hops(client_end, &opts, &log).await.expect("logged in");
    let handle = handles.last().expect("the destination");
    let ran = tokio::time::timeout(LIMIT, podssh_ssh::session::run(handle, &opts, "stand-in.test", &log)).await;
    assert_eq!(
        ran.map_err(|_| "a client that waits for the pty's answer first waits 30 s"),
        Ok(Ok(0)),
        "the command ran at once"
    );
    assert_eq!(seen.together.load(Ordering::SeqCst), 1, "the command's request came before the pty's answer");
    disconnect_all(&handles).await;
}
