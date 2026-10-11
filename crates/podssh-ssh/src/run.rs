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
use crate::options::{Agent, Hop, Options, Request};
use crate::relay_stream::{RelayEnd, RelayStatus};
use crate::retry::{Phase, Retry};
use crate::{auth, forward, retry, session};

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
    let outcome = run_outcome(stream, opts, relay, log.clone()).await;
    for line in &outcome.lines {
        log.error(line);
    }
    outcome.code
}

/// How a run ended: its exit code, whether a new connection may try it
/// again (T-025), and the lines of a failure, not yet said, as a try says
/// them in its own words.
#[derive(Debug)]
pub struct Outcome {
    pub code: i32,
    pub retry: Option<Retry>,
    pub lines: Vec<String>,
}

/// [`run`], with its outcome given back instead of said.
pub async fn run_outcome<S>(stream: S, opts: &Options, relay: Option<RelayStatus>, log: Arc<Log>) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    retry::begin();
    match run_inner(stream, opts, &log).await {
        Ok(code) => Outcome { code, retry: None, lines: Vec::new() },
        Err(message) => {
            let first = opts.jump.first().unwrap_or(&opts.destination);
            let target = podssh_ws::dial::authority(&first.host, first.port);
            let end = relay.and_then(|r| r.get());
            let lines = failure_lines(&message, end.as_ref(), &target);
            Outcome { code: EXIT_FAILURE, retry: retry::retry_phase(retry::phase(), end.as_ref()), lines }
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
    let hops: Vec<(&Hop, Cow<'_, Options>)> = opts
        .jump
        .iter()
        .enumerate()
        .map(|(i, hop)| (hop, hop_options(opts, i)))
        .chain(std::iter::once((&opts.destination, Cow::Borrowed(opts))))
        .collect();
    let last = hops.len() - 1;
    let mut handles: Vec<Handle<Client>> = vec![connect(stream, hops[0].0, last == 0, &hops[0].1, log).await?];
    for (i, (hop, hop_opts)) in hops.iter().enumerate().skip(1) {
        let previous = handles.last().expect("one handle per hop so far");
        let channel = forward::open(previous, &hop.host, hop.port).await.map_err(HopError::Unreachable)?;
        handles.push(connect(channel, hop, i == last, hop_opts, log).await?);
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
        Request::StdioForward(target) => {
            retry::reached(Phase::Requested);
            let handle = handles.last().expect("the destination");
            with_master(handle, opts, log, async { Ok(forward::stdio(handle, target, log).await) }, Ok(0)).await
        }
        Request::Nothing => {
            // The wait of -N is its request: a drop after it is no failure
            // to try again.
            retry::reached(Phase::Requested);
            let mut handle = handles.pop().expect("the destination");
            // -L, -D and a control master serve while -N waits for the end
            // (T-038, T-039); a master may end the run itself.
            if !opts.local_forwards.is_empty() || masters(opts) {
                let wait = crate::local::alongside(&handle, &opts.local_forwards, log, crate::local::closed(&handle));
                let closed = with_master(
                    &handle,
                    opts,
                    log,
                    async {
                        wait.await;
                        true
                    },
                    false,
                )
                .await;
                if !closed {
                    handles.push(handle);
                    disconnect_all(&handles).await;
                    return Ok(0);
                }
            }
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
                Err(e) => Err(format!(
                    "connection to {host} lost: {}",
                    crate::handler::take_last_error().unwrap_or_else(|| describe(&e))
                )),
            }
        }
        _ => {
            let handle = handles.last().expect("the destination");
            let session =
                crate::local::alongside(handle, &opts.local_forwards, log, session::run(handle, opts, &host, log));
            with_master(handle, opts, log, session, Ok(0)).await
        }
    };
    // What each forward carried (T-041), with -v.
    for line in crate::tally::lines() {
        log.verbose(&line);
    }
    disconnect_all(&handles).await;
    result
}

/// Whether this run serves a control socket (T-039).
fn masters(opts: &Options) -> bool {
    #[cfg(unix)]
    return opts.control.is_some();
    #[cfg(not(unix))]
    {
        let _ = opts;
        false
    }
}

/// `work` on `handle`, with the run's control master served meanwhile
/// (T-039); `ended` when a client said `-O exit`, or the master was idle
/// for its `ControlPersist`.
async fn with_master<T>(
    handle: &Handle<Client>,
    opts: &Options,
    log: &Arc<Log>,
    work: impl std::future::Future<Output = T>,
    ended: T,
) -> T {
    #[cfg(unix)]
    {
        let control = opts.control.as_ref().and_then(crate::mux::ControlSlot::take);
        match crate::mux::alongside(handle, control, log, work).await {
            crate::mux::Mastered::Done(out) => out,
            crate::mux::Mastered::Ended(why) => {
                log.verbose(&format!("the control master ended the run: {why:?}"));
                ended
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (handle, opts, log, ended);
        work.await
    }
}

/// The options of hop `i` of `-J`: its own, when the caller resolved them
/// (T-290), with the run's memory of its logins, which each hop shares as
/// it did before; else the connection's.
fn hop_options(opts: &Options, i: usize) -> Cow<'_, Options> {
    match opts.jump_options.get(i) {
        Some(own) => {
            let mut own = own.clone();
            own.remembered = opts.remembered.clone();
            Cow::Owned(own)
        }
        None => Cow::Borrowed(opts),
    }
}

/// The name that `known_hosts` files the key of `hop` under (T-030): `host`,
/// or `[host]:port` off port 22, each hop its own; `HostKeyAlias` as it is,
/// with no port, as OpenSSH files it, when `opts` are the hop's own: the
/// destination's, or a jump hop's from its own blocks (T-290). A jump hop
/// never takes the destination's alias: its key is another server's.
pub(crate) fn hop_key_name(hop: &Hop, is_destination: bool, opts: &Options) -> String {
    match &opts.host_key_alias {
        Some(alias) if is_destination || opts.destination == *hop => alias.clone(),
        _ => known_hosts::host_name(&hop.host, hop.port),
    }
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
    let policy = Policy {
        name: hop_key_name(hop, is_destination, opts),
        strict: opts.strict_host_key_checking,
        user_files: opts.user_known_hosts.clone(),
        no_user_file: opts.no_user_known_hosts,
        global_files: opts.global_known_hosts.clone(),
        batch_mode: opts.batch_mode,
        pin: if is_destination { opts.host_key_pin.clone() } else { None },
        fingerprints: if is_destination { opts.host_key_fingerprints.clone() } else { Vec::new() },
    };
    let config = Arc::new(client_config(opts, &policy));
    // Only the destination may use the agent (-A) and the display (-X),
    // never a jump hop.
    let forwarded = if is_destination { opts.forward_agent.clone() } else { Agent::Off };
    let x11 = if is_destination { opts.forward_x11.clone() } else { None };
    let client = Client::new(policy, log.clone()).forwarding_agent(forwarded).forwarding_x11(x11);
    let refusal = client.refusal();
    let disconnect = client.disconnect();
    let forwards = client.forwards();
    if is_destination {
        crate::remote::set_destination(forwards.clone());
    }
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
    retry::reached(Phase::Auth);
    auth::authenticate(&mut handle, &user, &hop.host, hop.port, opts, log).await.map_err(|e| match e {
        auth::AuthError::Refused(m) => HopError::Auth(m),
        auth::AuthError::Broke(m) => HopError::Unreachable(m),
    })?;
    log.verbose(&format!("authenticated to {label} as {user}"));
    if is_destination {
        retry::reached(Phase::Ready);
    }
    // The forwards of `-R` are the destination's; asked again after each new
    // connection of a run (`--persist`).
    if is_destination && !opts.remote_forwards.is_empty() {
        retry::reached(Phase::Requested);
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
    // A host that a `@cert-authority` line names is asked for a certificate
    // first, of each algorithm it may sign with but SHA-1 RSA (T-027).
    if crate::hostcert::trusted_for(&files, &policy.name) {
        let certs: Vec<Algorithm> = preferred
            .key
            .iter()
            .filter(|a| !matches!(a, Algorithm::Rsa { hash: None } | Algorithm::Dsa | Algorithm::Other(_)))
            .cloned()
            .collect();
        preferred.host_key_certificates = Cow::Owned(certs);
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
#[path = "run_tests.rs"]
mod tests;
