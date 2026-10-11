//! The limit on each answer of the server, against a russh server in this
//! process that completes the key exchange and then stops answering.

use std::sync::Arc;
use std::time::Duration;

use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth};
use russh::{MethodKind, MethodSet};

use super::*;
use crate::log::Log;
use crate::options::{Agent, Hop, LogLevel, Options, StrictHostKeyChecking};

/// Where the server stops answering.
#[derive(Clone, Copy)]
enum Stall {
    /// The first request to log in (`none`).
    First,
    /// The publickey request, after `none` was refused.
    PublicKey,
}

struct Mute(Stall);

impl server::Handler for Mute {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        match self.0 {
            Stall::First => std::future::pending().await,
            Stall::PublicKey => Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::PublicKey][..])),
                partial_success: false,
            }),
        }
    }

    async fn auth_publickey_offered(&mut self, _user: &str, _key: &PublicKey) -> Result<Auth, Self::Error> {
        std::future::pending().await
    }

    async fn auth_publickey(&mut self, _user: &str, _key: &PublicKey) -> Result<Auth, Self::Error> {
        std::future::pending().await
    }
}

/// Log in to a [`Mute`] server with a limit of 2 s; the error. The test's own
/// limit (30 s) shows a run that nothing ends.
async fn log_in(stall: Stall, key_file: Option<std::path::PathBuf>) -> String {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, Mute(stall)).await {
            let _ = session.await;
        }
    });
    let hop = Hop { user: Some("podtest".into()), host: "stall.test".into(), port: 22 };
    let mut opts = Options::new(hop.clone(), "podtest".into());
    opts.connect_timeout = Duration::from_secs(2);
    opts.strict_host_key_checking = StrictHostKeyChecking::No;
    opts.agent = Agent::Off;
    opts.batch_mode = true;
    opts.identity_files = key_file.into_iter().collect();
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let run = crate::run::connect(client_end, &hop, true, &opts, &log);
    match tokio::time::timeout(Duration::from_secs(30), run).await {
        Ok(Ok(_)) => panic!("logged in to a server that never answers"),
        Ok(Err(e)) => e.to_string(),
        Err(_) => panic!("nothing ended the wait within 30 s"),
    }
}

#[tokio::test]
async fn auth_answer_limit_ends_the_first_request() {
    let err = log_in(Stall::First, None).await;
    assert_eq!(err, "stall.test did not answer the first request to log in within 2 s");
}

#[tokio::test]
async fn auth_answer_limit_ends_the_publickey_request() {
    let dir = std::env::temp_dir().join(format!("podssh-answer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    let path = dir.join("id_ed25519");
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a key");
    std::fs::write(&path, key.to_openssh(LineEnding::LF).expect("encoded").as_bytes()).expect("written");
    let err = log_in(Stall::PublicKey, Some(path)).await;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(err, "stall.test did not answer the publickey request within 2 s");
}

/// The agent's time does not count: a signature that takes 3 s, under a
/// limit of 2 s, still gets the server's answer.
#[tokio::test]
async fn auth_answer_limit_leaves_out_the_agents_time() {
    let time = Mutex::new(AgentTime::default());
    let call = async {
        time.lock().unwrap().since = Some(Instant::now());
        tokio::time::sleep(Duration::from_secs(3)).await;
        // The guard ends before the next wait, as the signer's does.
        {
            let mut t = time.lock().unwrap();
            let start = t.since.take().unwrap();
            t.spent += start.elapsed();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        "answered"
    };
    let got = within_signing(Duration::from_secs(2), "slow.test", "the publickey request", &time, call).await;
    assert_eq!(got, Ok("answered"));
    // The control: the same wait with no time in the agent ends at the limit.
    let slow = tokio::time::sleep(Duration::from_secs(3));
    let got = within_signing(Duration::from_secs(2), "slow.test", "the publickey request", &time_zero(), slow).await;
    assert_eq!(got, Err("slow.test did not answer the publickey request within 2 s".to_string()));
}

fn time_zero() -> Mutex<AgentTime> {
    Mutex::new(AgentTime::default())
}

/// A server that takes each key that is offered, after a signature that
/// verifies.
struct TakesAny;

impl server::Handler for TakesAny {
    type Error = russh::Error;

    async fn auth_publickey_offered(&mut self, _user: &str, _key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_publickey(&mut self, _user: &str, _key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
}

/// A client that takes each host key.
struct AnyHost;

impl russh::client::Handler for AnyHost {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// An agent that refuses each signature.
struct Refuses;

#[derive(Debug)]
struct NoSignature;

impl From<russh::SendError> for NoSignature {
    fn from(_: russh::SendError) -> Self {
        NoSignature
    }
}

impl std::fmt::Display for NoSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the agent refused to sign")
    }
}

impl russh::Signer for Refuses {
    type Error = NoSignature;

    async fn auth_sign(&mut self, _: &AgentIdentity, _: Option<HashAlg>, _: Vec<u8>) -> Result<Vec<u8>, NoSignature> {
        Err(NoSignature)
    }
}

/// Log in to a [`TakesAny`] server: first with `agent_key`, whose agent
/// fails to sign, then with a key file. The answers to both, and why the
/// agent failed.
async fn agent_fails_then_a_file(
    agent_key: PrivateKey,
    hash: Option<HashAlg>,
) -> (Result<russh::client::AuthResult, NoSignature>, russh::client::AuthResult, Option<String>) {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key"));
    config.methods = MethodSet::from(&[MethodKind::PublicKey][..]);
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, TakesAny).await {
            let _ = session.await;
        }
    });
    let client = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect_stream(client, client_end, AnyHost).await.expect("connected");
    let mut refuses = Refuses;
    let mut timed = Timed { inner: &mut refuses, time: Arc::new(Mutex::new(AgentTime::default())), failed: None };
    let first = handle.authenticate_publickey_with("podtest", agent_key.public_key().clone(), hash, &mut timed).await;
    let file_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a key");
    let offered = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(file_key), None);
    let second = tokio::time::timeout(Duration::from_secs(10), handle.authenticate_publickey("podtest", offered))
        .await
        .expect("the server's answer to the next key within 10 s")
        .expect("an answer");
    (first, second, timed.failed)
}

/// The server takes the agent's key and the agent fails to sign: the server
/// refuses the signature that stands in, of each kind of key, and the next
/// key, a key file, logs in at once on the same connection, where russh
/// dropped its request and the login waited for its limit (T-285).
#[tokio::test]
async fn agent_sign_failure_lets_the_login_go_on() {
    let ecdsa = Algorithm::Ecdsa { curve: russh::keys::EcdsaCurve::NistP256 };
    let keys = [
        (PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a key"), None),
        (PrivateKey::random(&mut rand::rng(), ecdsa).expect("a key"), None),
        (PrivateKey::from(crate::rsa_key::generate(2048).expect("a key")), Some(HashAlg::Sha512)),
    ];
    for (agent_key, hash) in keys {
        let kind = agent_key.algorithm().to_string();
        let (first, second, failed) = agent_fails_then_a_file(agent_key, hash).await;
        assert!(matches!(second, russh::client::AuthResult::Success), "{kind}");
        assert!(matches!(first, Ok(russh::client::AuthResult::Failure { .. })), "{kind}: the stand-in was not refused");
        assert_eq!(failed.as_deref(), Some("the agent refused to sign"), "{kind}");
    }
}
