//! A whole `podssh ssh` run: the SSH handshake over the caller's stream, each
//! `-J` hop in turn, authentication, then the request. Returns the process
//! exit code.

use std::borrow::Cow;
use std::sync::Arc;

use russh::client::{Config, Handle};
use russh::keys::{Algorithm, HashAlg};
use russh::{Disconnect, Preferred, SshId};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::handler::Client;
use crate::hostkey::Policy;
use crate::known_hosts;
use crate::log::Log;
use crate::options::{Hop, Options, Request};
use crate::relay_stream::RelayStatus;
use crate::{auth, forward, session};

/// podssh's own failures, as OpenSSH's: connection, host key, authentication,
/// and a session that ends without an exit status.
pub const EXIT_FAILURE: i32 = 255;

/// The SSH window advertised to the server. The relay drops a frame when more
/// than 1 MiB waits for a slow receiver (`1011 relay backpressure`), and a
/// dropped frame is a broken SSH connection; a window under 1 MiB keeps the
/// server from ever having that much in flight (russh's default is 2 MiB).
const WINDOW: u32 = 512 * 1024;

/// Run `opts` over `stream`, which reaches the first `-J` hop or, without one,
/// the destination. `relay` is the relay leg's status, when there is one, so a
/// failure can say what the relay reported.
pub async fn run<S>(stream: S, opts: &Options, relay: Option<RelayStatus>, log: Arc<Log>) -> i32
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match run_inner(stream, opts, &log).await {
        Ok(code) => code,
        Err(message) => {
            log.error(&message);
            if let Some(why) = relay.and_then(|r| r.get()).and_then(|end| end.explain()) {
                log.error(&why);
            }
            EXIT_FAILURE
        }
    }
}

async fn run_inner<S>(stream: S, opts: &Options, log: &Arc<Log>) -> Result<i32, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hops: Vec<&Hop> = opts.jump.iter().chain(std::iter::once(&opts.destination)).collect();
    let last = hops.len() - 1;
    // Every handle stays alive until the end: each hop's channel runs inside
    // the previous hop's connection.
    let mut handles: Vec<Handle<Client>> = vec![connect(stream, hops[0], last == 0, opts, log).await?];
    for (i, hop) in hops.iter().enumerate().skip(1) {
        let previous = handles.last().expect("one handle per hop so far");
        let channel = forward::open(previous, &hop.host, hop.port).await?;
        handles.push(connect(channel, hop, i == last, opts, log).await?);
    }
    let host = display(&opts.destination);
    let result = match &opts.request {
        Request::StdioForward { host, port } => {
            Ok(forward::stdio(handles.last().expect("the destination"), host, *port, log).await)
        }
        Request::Nothing => {
            let mut handle = handles.pop().expect("the destination");
            let ended = (&mut handle).await;
            handles.push(handle);
            match ended {
                Ok(()) => Ok(0),
                Err(e) => Err(format!("connection to {host} lost: {}", describe(&e))),
            }
        }
        _ => session::run(handles.last().expect("the destination"), opts, &host, log).await,
    };
    for handle in handles.iter().rev() {
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    result
}

/// The SSH handshake and login for one hop.
async fn connect<S>(stream: S, hop: &Hop, is_destination: bool, opts: &Options, log: &Arc<Log>) -> Result<Handle<Client>, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let user = hop.user.clone().unwrap_or_else(|| opts.user.clone());
    let alias = match (&opts.host_key_alias, is_destination) {
        (Some(alias), true) => alias.clone(),
        _ => hop.host.clone(),
    };
    let policy = Policy {
        name: known_hosts::host_name(&alias, hop.port),
        strict: opts.strict_host_key_checking,
        user_files: opts.user_known_hosts.clone(),
        global_files: opts.global_known_hosts.clone(),
        batch_mode: opts.batch_mode,
    };
    let config = Arc::new(client_config(opts, &policy));
    let client = Client::new(policy, log.clone());
    let refusal = client.refusal();
    let label = display(hop);
    log.verbose(&format!("SSH handshake with {label}"));
    let handshake = russh::client::connect_stream(config, stream, client);
    let mut handle = match tokio::time::timeout(opts.connect_timeout, handshake).await {
        Err(_) => {
            return Err(format!(
                "{label}: the SSH handshake did not finish within {} s",
                opts.connect_timeout.as_secs()
            ))
        }
        Ok(Err(russh::Error::UnknownKey)) => {
            let why = refusal.lock().unwrap_or_else(|e| e.into_inner()).take();
            return Err(why.unwrap_or_else(|| "host key verification failed.".into()));
        }
        Ok(Err(e)) => return Err(format!("{label}: {}", describe(&e))),
        Ok(Ok(handle)) => handle,
    };
    auth::authenticate(&mut handle, &user, &hop.host, opts, log).await?;
    log.verbose(&format!("authenticated to {label} as {user}"));
    Ok(handle)
}

fn client_config(opts: &Options, policy: &Policy) -> Config {
    let mut preferred = Preferred::default();
    // Host-key algorithms already recorded for this host go first, as in
    // OpenSSH, so a host known by its RSA key is not asked for an unknown
    // Ed25519 one. An RSA key is asked for with SHA-2 signatures, never SHA-1.
    let files: Vec<_> = policy.user_files.iter().chain(&policy.global_files).cloned().collect();
    let mut order: Vec<Algorithm> = Vec::new();
    for algorithm in known_hosts::recorded_algorithms(&files, &policy.name) {
        let wanted = match algorithm {
            Algorithm::Rsa { .. } => vec![
                Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
                Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
            ],
            other => vec![other],
        };
        for a in wanted {
            if preferred.key.contains(&a) && !order.contains(&a) {
                order.push(a);
            }
        }
    }
    if !order.is_empty() {
        for a in preferred.key.iter() {
            if !order.contains(a) {
                order.push(a.clone());
            }
        }
        preferred.key = Cow::Owned(order);
    }
    if opts.compression {
        preferred.compression = Cow::Owned(vec![
            russh::compression::ZLIB_LEGACY,
            russh::compression::ZLIB,
            russh::compression::NONE,
        ]);
    }
    Config {
        client_id: SshId::Standard(Cow::Owned(format!("SSH-2.0-podssh_{}", env!("CARGO_PKG_VERSION")))),
        keepalive_interval: opts.keepalive_interval,
        keepalive_max: opts.keepalive_max,
        inactivity_timeout: None,
        window_size: WINDOW,
        nodelay: true,
        preferred,
        ..Config::default()
    }
}

/// `host`, or `host:port` when the port is not 22.
fn display(hop: &Hop) -> String {
    if hop.port == 22 {
        hop.host.clone()
    } else {
        format!("{}:{}", hop.host, hop.port)
    }
}

/// russh's errors, in words a user can act on.
pub fn describe(e: &russh::Error) -> String {
    use russh::Error;
    match e {
        Error::Disconnect | Error::HUP | Error::RecvError | Error::SendError => {
            "the connection closed unexpectedly".into()
        }
        Error::IO(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => "the connection closed unexpectedly".into(),
        Error::Version => "the server did not answer with an SSH version line (is this an SSH server?)".into(),
        Error::NoCommonAlgo { kind, ours, theirs } => format!(
            "no {kind:?} algorithm in common with the server (podssh offers {}; the server offers {})",
            ours.join(","),
            theirs.join(",")
        ),
        Error::KeepaliveTimeout => "the server stopped answering keepalives".into(),
        Error::ConnectionTimeout | Error::InactivityTimeout => "the connection timed out".into(),
        Error::StrictKeyExchangeViolation { .. } => {
            format!("{e} (the connection was tampered with, or the server is broken)")
        }
        other => other.to_string(),
    }
}
