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
use crate::relay_stream::{RelayEnd, RelayStatus};
use crate::{auth, forward, session};

/// podssh's own failures, as OpenSSH's: connection, host key, authentication,
/// and a session that ends without an exit status.
pub const EXIT_FAILURE: i32 = 255;

/// The SSH window advertised to the server. On the forward path the relay
/// closes a session when 2 MiB wait for a slow receiver (`1013 client receive
/// backlog`); a window of 512 KiB keeps the server from ever having that much
/// in flight (russh's default is 2 MiB).
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
            let first = opts.jump.first().unwrap_or(&opts.destination);
            let target = podssh_ws::dial::authority(&first.host, first.port);
            for line in failure_lines(&message, relay.and_then(|r| r.get()).as_ref(), &target) {
                log.error(&line);
            }
            EXIT_FAILURE
        }
    }
}

/// The lines of a failed run. When the relay ended the session abnormally,
/// that is the cause, whatever the SSH client saw after it: the first line
/// names the hop that broke and keeps the relay's code and reason as they
/// are, and a second line says what may help. Else the message, and the
/// relay's own words when it closed with a reason.
pub fn failure_lines(message: &str, relay: Option<&RelayEnd>, target: &str) -> Vec<String> {
    let label = message.split_once(": ").map_or(message, |(label, _)| label);
    let (leg, why) = match relay {
        Some(RelayEnd::Closed { code: Some(code), reason }) if *code != 1000 => {
            (podssh_ws::session::forward_close(Some(*code), reason), format!("relay close {code}: {reason}"))
        }
        Some(RelayEnd::Failed(why)) => (podssh_ws::session::ForwardClose::Client, why.to_string()),
        _ => {
            let mut lines = vec![message.to_string()];
            lines.extend(relay.and_then(RelayEnd::explain));
            return lines;
        }
    };
    let mut lines = vec![format!("{label}: {} ({why})", leg.what(target))];
    let reason = match relay {
        Some(RelayEnd::Closed { reason, .. }) => reason.as_str(),
        _ => "",
    };
    lines.extend(leg.remedy(reason).map(str::to_string));
    lines
}

/// Why a hop could not be reached or logged in to: a command that maps
/// failures to exit codes (`cp`) reads which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HopError {
    /// The connection, the forward to the hop, or the handshake failed, or
    /// the login broke before an answer.
    Unreachable(String),
    /// podssh did not accept the host key.
    HostKey(String),
    /// The server refused each way of logging in.
    Auth(String),
    /// The destination refused a forward of `-R`, with `ExitOnForwardFailure`.
    Forward(String),
}

impl std::fmt::Display for HopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HopError::Unreachable(m) | HopError::HostKey(m) | HopError::Auth(m) | HopError::Forward(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl std::error::Error for HopError {}

/// The SSH connection to each `-J` hop in turn, the destination last, each
/// authenticated: for a session (`ssh`) and for SFTP (`cp`). Every handle
/// stays alive until the end, since each hop's channel runs inside the
/// previous hop's connection.
pub async fn connect_hops<S>(stream: S, opts: &Options, log: &Arc<Log>) -> Result<Vec<Handle<Client>>, HopError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hops: Vec<&Hop> = opts.jump.iter().chain(std::iter::once(&opts.destination)).collect();
    let last = hops.len() - 1;
    let mut handles: Vec<Handle<Client>> = vec![connect(stream, hops[0], last == 0, opts, log).await?];
    for (i, hop) in hops.iter().enumerate().skip(1) {
        let previous = handles.last().expect("one handle per hop so far");
        let channel = forward::open(previous, &hop.host, hop.port).await.map_err(HopError::Unreachable)?;
        handles.push(connect(channel, hop, i == last, opts, log).await?);
    }
    Ok(handles)
}

/// Close each connection, the destination first.
pub async fn disconnect_all(handles: &[Handle<Client>]) {
    for handle in handles.iter().rev() {
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

async fn run_inner<S>(stream: S, opts: &Options, log: &Arc<Log>) -> Result<i32, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut handles = connect_hops(stream, opts, log).await.map_err(|e| e.to_string())?;
    let host = display(&opts.destination);
    let result = match &opts.request {
        Request::StdioForward { host, port } => {
            Ok(forward::stdio(handles.last().expect("the destination"), host, *port, log).await)
        }
        Request::Nothing => {
            let mut handle = handles.pop().expect("the destination");
            let ended = (&mut handle).await;
            handles.push(handle);
            // -N ends only when the server or the network ends it, never
            // as a success: OpenSSH says so too, with 255 (T-026).
            match ended {
                Ok(()) => {
                    let said = crate::handler::take_last_disconnect().map(|s| format!(": {s}")).unwrap_or_default();
                    log.error(&format!("the server ended the connection to {host}{said}"));
                    Ok(EXIT_FAILURE)
                }
                Err(e) => Err(format!("connection to {host} lost: {}", describe(&e))),
            }
        }
        _ => session::run(handles.last().expect("the destination"), opts, &host, log).await,
    };
    disconnect_all(&handles).await;
    result
}

/// The SSH handshake and login for one hop.
pub(crate) async fn connect<S>(
    stream: S,
    hop: &Hop,
    is_destination: bool,
    opts: &Options,
    log: &Arc<Log>,
) -> Result<Handle<Client>, HopError>
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
        pin: if is_destination { opts.host_key_pin.clone() } else { None },
    };
    let config = Arc::new(client_config(opts, &policy));
    let client = Client::new(policy, log.clone());
    let refusal = client.refusal();
    let disconnect = client.disconnect();
    let forwards = client.forwards();
    let label = display(hop);
    log.verbose(&format!("SSH handshake with {label}"));
    let handshake = russh::client::connect_stream(config, stream, client);
    let mut handle = match tokio::time::timeout(opts.connect_timeout, handshake).await {
        Err(_) => {
            return Err(HopError::Unreachable(format!(
                "{label}: the SSH handshake did not finish within {} s",
                opts.connect_timeout.as_secs()
            )))
        }
        Ok(Err(russh::Error::UnknownKey)) => {
            let why = refusal.lock().unwrap_or_else(|e| e.into_inner()).take();
            return Err(HopError::HostKey(why.unwrap_or_else(|| "host key verification failed.".into())));
        }
        Ok(Err(e)) => {
            // The server's own words, when it sent a disconnect, name the
            // cause better than the closed stream does.
            let said = disconnect.lock().unwrap_or_else(|e| e.into_inner()).take();
            return Err(HopError::Unreachable(match said {
                Some(said) => format!("{label}: the server ended the connection: {said}"),
                None => format!("{label}: {}", describe(&e)),
            }));
        }
        Ok(Ok(handle)) => handle,
    };
    auth::authenticate(&mut handle, &user, &hop.host, opts, log).await.map_err(|e| match e {
        auth::AuthError::Refused(m) => HopError::Auth(m),
        auth::AuthError::Broke(m) => HopError::Unreachable(m),
    })?;
    log.verbose(&format!("authenticated to {label} as {user}"));
    // The forwards of `-R` are the destination's; asked again after each new
    // connection of a run (`--persist`).
    if is_destination && !opts.remote_forwards.is_empty() {
        crate::remote::request(&handle, &forwards, opts, log).await.map_err(HopError::Forward)?;
    }
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
            Algorithm::Rsa { .. } => {
                vec![Algorithm::Rsa { hash: Some(HashAlg::Sha512) }, Algorithm::Rsa { hash: Some(HashAlg::Sha256) }]
            }
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
        preferred.compression =
            Cow::Owned(vec![russh::compression::ZLIB_LEGACY, russh::compression::ZLIB, russh::compression::NONE]);
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

/// `host`, or `host:port` when the port is not 22 (`[v6]:port` for an
/// IPv6 address).
pub(crate) fn display(hop: &Hop) -> String {
    if hop.port == 22 {
        hop.host.clone()
    } else {
        podssh_ws::dial::authority(&hop.host, hop.port)
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

#[cfg(test)]
mod tests {
    use super::*;

    const DROP: &str = "railway.new: the connection closed unexpectedly";

    /// The first line from each kind of relay end, from a server disconnect
    /// and from a bare error (GitHub #17).
    #[test]
    fn first_line_names_the_hop_that_broke() {
        let lost = RelayEnd::Closed { code: Some(1011), reason: "write failed: Network connection lost.".into() };
        let lines = failure_lines(DROP, Some(&lost), "railway.new:22");
        assert_eq!(
            lines[0],
            "railway.new: the relay lost its connection to railway.new:22 (relay close 1011: write failed: Network connection lost.)"
        );
        assert!(lines[1].contains("--relay-host"), "{lines:?}");
        let cap = RelayEnd::Closed { code: Some(1009), reason: "session byte cap".into() };
        let lines = failure_lines(DROP, Some(&cap), "railway.new:22");
        assert!(lines[0].contains("at one of its limits (relay close 1009: session byte cap)"), "{lines:?}");
        assert!(lines[1].contains("64 MiB"), "{lines:?}");
        let gone = RelayEnd::Failed(podssh_ws::SessionError::Idle("the relay sent nothing for 40 s".into()));
        let lines = failure_lines(DROP, Some(&gone), "railway.new:22");
        assert!(lines[0].starts_with("railway.new: the connection between podssh and the relay broke"), "{lines:?}");
        // A normal close of the relay: the message, then the relay's words.
        let done = RelayEnd::Closed { code: Some(1000), reason: "target closed".into() };
        let server = "railway.new: the server ended the connection: too many sessions (TooManyConnections)";
        let lines = failure_lines(server, Some(&done), "railway.new:22");
        assert_eq!(lines[0], server);
        assert!(lines[1].contains("target closed"), "{lines:?}");
        // No relay (--direct): the message as it is.
        assert_eq!(failure_lines(DROP, None, "railway.new:22"), vec![DROP.to_string()]);
    }
}
