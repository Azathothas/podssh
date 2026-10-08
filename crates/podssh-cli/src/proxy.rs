//! `podssh proxy HOST PORT`: a byte pipe between stdin/stdout and HOST:PORT,
//! through the relay. It is made to be OpenSSH's `ProxyCommand`:
//!
//! ```text
//! ssh -o ProxyCommand='podssh proxy %h %p' -o ServerAliveInterval=60 user@host
//! ```
//!
//! stdout carries the target's bytes and nothing else; diagnostics go to
//! stderr. End of stdin stops sending but keeps receiving (as `nc` does without
//! `-N`): a WebSocket Close is not a TCP half-close, and sending one would cut
//! off a reply that is still on its way.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::dial::DialError;
use podssh_ws::frame;
use podssh_ws::session::close_code_and_reason;
use podssh_ws::{connect, ConnectError, Endpoint, ProxyChoice, RelaySession, Trust, WsClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::relay::{self, Relay};
use crate::relay_token::{self, MintContext, Origin, TokenError};

/// Bound on reaching the relay: proxy, TCP, TLS, upgrade, and minting.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// What `podssh proxy` was asked to do.
#[derive(Debug, Clone, Default)]
pub struct ProxyArgs {
    /// `HOST`, or `HOST:PORT` when no separate port is given.
    pub target: Option<String>,
    pub port: Option<String>,
    /// `--relay-host`.
    pub relay_host: Option<String>,
    /// `--ca-file`.
    pub ca_file: Option<String>,
}

/// Run the verb; returns the process exit code.
pub fn run_proxy(args: &ProxyArgs, err: &mut dyn Write) -> i32 {
    let (host, port) = match parse_target(args.target.as_deref(), args.port.as_deref()) {
        Ok(t) => t,
        Err(why) => {
            let _ = writeln!(err, "podssh proxy: {why}");
            let _ = writeln!(err, "usage: podssh proxy HOST PORT   (as an OpenSSH ProxyCommand: podssh proxy %h %p)");
            return EXIT_USAGE;
        }
    };
    let relay = match relay::select_relay(args.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok()) {
        Ok(r) => r,
        Err(why) => {
            let _ = writeln!(err, "podssh proxy: {why}");
            return EXIT_USAGE;
        }
    };
    let path = match relay::forward_path(&host, port) {
        Ok(p) => p,
        Err(why) => {
            let _ = writeln!(err, "podssh proxy: {why}");
            return EXIT_USAGE;
        }
    };
    let ca_file = args.ca_file.clone().or_else(|| std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty()));
    let trust = match ca_file {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh proxy: could not start the async runtime: {e}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    let code = runtime.block_on(session(&relay, &path, &trust, &format!("{host}:{port}"), err));
    // A read on stdin may still be blocked in a helper thread; do not wait
    // for it, or podssh would hang after the session has ended.
    runtime.shutdown_background();
    code
}

/// `HOST PORT`, or `HOST:PORT` alone.
pub fn parse_target(target: Option<&str>, port: Option<&str>) -> Result<(String, u16), String> {
    let target = target.ok_or("missing HOST and PORT")?;
    let (host, port_text) = match port {
        Some(p) => (target, p),
        None => target.rsplit_once(':').ok_or("missing PORT")?,
    };
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("{port_text:?} is not a port"))?;
    relay::check_host(host)?;
    Ok((host.to_string(), port))
}

async fn session(relay: &Relay, path: &str, trust: &Trust, target: &str, err: &mut dyn Write) -> i32 {
    let proxy = ProxyChoice::FromEnvironment;
    let ctx = MintContext { relay, trust, proxy: &proxy, timeout: CONNECT_TIMEOUT };
    let mut token = match relay_token::obtain(&ctx, false).await {
        Ok(t) => t,
        Err(e) => return token_failure(&e, err),
    };
    if let Some(why) = token.cache_warning.take() {
        let _ = writeln!(err, "podssh: the relay token could not be cached, so one is minted per run: {why}");
    }
    let config = WsClientConfig {
        endpoint: Endpoint { host: relay.host.clone(), port: relay.port, path: path.to_string() },
        trust: trust.clone(),
        server_name: relay.host.clone(),
        timeout: CONNECT_TIMEOUT,
        idle_timeout: Some(podssh_ws::DEFAULT_IDLE_TIMEOUT),
        proxy: proxy.clone(),
    };
    let mut result = connect(&config, token.secret()).await;
    // A cached token the relay no longer accepts: forget it and mint once.
    // Not for a policy refusal, which a new token cannot fix.
    if let Err(ConnectError::Refused { status: 403, body }) = &result {
        if token.origin == Origin::Cache && !is_policy_refusal(body) {
            crate::token_cache::remove(&relay.host);
            token = match relay_token::obtain(&ctx, true).await {
                Ok(t) => t,
                Err(e) => return token_failure(&e, err),
            };
            result = connect(&config, token.secret()).await;
        }
    }
    let origin = token.origin;
    drop(token);
    match result {
        Ok(session) => pump(session, err).await,
        Err(e) => connect_failure(&e, origin, target, err),
    }
}

/// The relay's wording for a policy refusal (spec: "not in the ALLOW list").
fn is_policy_refusal(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    body.contains("allow list") || body.contains("not allowed") || body.contains("blocked")
}

fn token_failure(e: &TokenError, err: &mut dyn Write) -> i32 {
    let _ = writeln!(err, "podssh: {e}");
    match e {
        TokenError::BadEnvironment => EX_CONFIG,
        TokenError::Connect(c) => exit_for(c),
        _ => EX_UNAVAILABLE,
    }
}

fn connect_failure(e: &ConnectError, origin: Origin, target: &str, err: &mut dyn Write) -> i32 {
    let _ = writeln!(err, "podssh: {e}");
    let hint = match e {
        ConnectError::Refused { status: 400 | 403, body } if is_policy_refusal(body) => {
            Some(format!("the relay's policy does not allow {target}"))
        }
        ConnectError::Refused { status: 403, .. } if origin == Origin::Environment => {
            Some(format!("the token in {} was rejected", relay_token::TOKEN_ENV))
        }
        ConnectError::Refused { status: 502, .. } => Some(format!("the relay could not reach {target}")),
        ConnectError::Dial(DialError::ProxyRefused { .. }) => {
            Some("the HTTP proxy does not allow connections to the relay".to_string())
        }
        _ => None,
    };
    if let Some(hint) = hint {
        let _ = writeln!(err, "podssh: {hint}");
    }
    exit_for(e)
}

/// The exit code for a connection failure (sysexits).
fn exit_for(e: &ConnectError) -> i32 {
    match e {
        ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_)) => EX_CONFIG,
        ConnectError::Refused { status: 401 | 403, .. } => EX_NOPERM,
        // The relay answers 400 for a target in a blocked address range.
        ConnectError::Refused { status: 400, body } if is_policy_refusal(body) => EX_NOPERM,
        ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

/// How the relay-to-stdout direction ended.
enum Ended {
    Closed { code: Option<u16>, reason: String },
    /// stdout went away (the consumer, e.g. ssh, exited).
    OutputGone,
}

/// Copy both directions until the relay ends the session.
async fn pump(session: RelaySession, err: &mut dyn Write) -> i32 {
    let session = Arc::new(session);
    let upstream = stdin_to_relay(session.clone());
    let downstream = relay_to_stdout(session.clone());
    tokio::pin!(upstream);
    tokio::pin!(downstream);
    let mut sending = true;
    loop {
        tokio::select! {
            sent = &mut upstream, if sending => match sent {
                Ok(()) => sending = false,
                Err(e) => {
                    let _ = writeln!(err, "podssh: {e}");
                    return EX_UNAVAILABLE;
                }
            },
            ended = &mut downstream => return finish(ended, &session, err).await,
        }
    }
}

async fn stdin_to_relay(session: Arc<RelaySession>) -> Result<(), String> {
    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        // A stdin that fails to read is treated like one that ended.
        let n = stdin.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            return Ok(());
        }
        session
            .send_binary(&buf[..n])
            .await
            .map_err(|e| format!("sending to the relay failed: {e}"))?;
    }
}

async fn relay_to_stdout(session: Arc<RelaySession>) -> Result<Ended, String> {
    let mut stdout = tokio::io::stdout();
    loop {
        let f = session.read_frame().await?;
        match f.opcode {
            frame::OPCODE_BINARY if f.payload.is_empty() => {} // the relay's keepalive
            frame::OPCODE_BINARY => {
                if stdout.write_all(&f.payload).await.is_err() || stdout.flush().await.is_err() {
                    return Ok(Ended::OutputGone);
                }
            }
            frame::OPCODE_CLOSE => {
                let (code, reason) = close_code_and_reason(&f.payload);
                return Ok(Ended::Closed { code, reason });
            }
            frame::OPCODE_TEXT => return Err("the relay sent a text frame on the forward path".into()),
            other => return Err(format!("the relay sent an unexpected frame (opcode {other:#x})")),
        }
    }
}

async fn finish(ended: Result<Ended, String>, session: &RelaySession, err: &mut dyn Write) -> i32 {
    match ended {
        Ok(Ended::Closed { code: None | Some(1000) | Some(1001), .. }) => 0,
        Ok(Ended::Closed { code: Some(code), reason }) => {
            let _ = writeln!(err, "podssh: the relay closed the session: {code} {reason}");
            EX_UNAVAILABLE
        }
        Ok(Ended::OutputGone) => {
            let _ = session.send_close(1000, "").await;
            0
        }
        Err(e) => {
            let _ = writeln!(err, "podssh: {e}");
            EX_UNAVAILABLE
        }
    }
}
