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

use podssh_ws::frame;
use podssh_ws::session::close_code_and_reason;
use podssh_ws::{RelaySession, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use podssh_relay::open::{OpenError, Request};
use podssh_relay::relay::{self, RelayList};
use podssh_relay::token::TokenError;
use podssh_ws::dial::DialError;
use podssh_ws::ConnectError;

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};

/// What `podssh proxy` was asked to do.
#[derive(Debug, Clone, Default)]
pub struct ProxyArgs {
    /// `HOST`, or `HOST:PORT` when no separate port is given.
    pub target: Option<String>,
    pub port: Option<String>,
    /// `--relay-host`.
    pub relay_host: Option<String>,
    /// `--relay-addr`.
    pub relay_addr: Option<String>,
    /// `--ca-file`.
    pub ca_file: Option<String>,
}

/// Run the verb; returns the process exit code.
pub fn run_proxy(args: &ProxyArgs, err: &mut dyn Write) -> i32 {
    let (host, port) = match parse_target(args.target.as_deref(), args.port.as_deref()) {
        Ok(t) => t,
        Err(why) => {
            let _ = writeln!(err, "podssh proxy: {why}");
            // `--relay-host=-x 22` takes the HOST for its value: say how a
            // HOST that starts with - gets through.
            let flags = args.relay_host.is_some() || args.relay_addr.is_some() || args.ca_file.is_some();
            if flags && (args.target.is_none() || args.port.is_none()) {
                let _ = writeln!(err, "podssh proxy: a HOST that starts with - is read as a flag; put -- before it");
            }
            let _ = writeln!(
                err,
                "usage: podssh proxy [OPTIONS] [--] HOST PORT   (as an OpenSSH ProxyCommand: podssh proxy %h %p)"
            );
            return EXIT_USAGE;
        }
    };
    if let Err(refusal) = crate::pins::apply(args.relay_addr.as_deref()) {
        return refusal.report("proxy", err);
    }
    let relays = match crate::relay_settings::relays(args.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok()) {
        Ok(r) => r,
        Err(refusal) => return refusal.report("proxy", err),
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
    let v6 = relay::is_ipv6_literal(&host);
    let target = podssh_ws::dial::authority(&host, port);
    let code = runtime.block_on(session(&relays, &path, &trust, &target, v6, err));
    // A read on stdin may still be blocked in a helper thread; do not wait
    // for it, or podssh would hang after the session has ended.
    runtime.shutdown_background();
    code
}

/// `HOST PORT`, or one word: `HOST:PORT` or `[IPV6]:PORT`. HOST may be a
/// bare IPv6 address (OpenSSH gives `%h` so) or one in brackets.
pub fn parse_target(target: Option<&str>, port: Option<&str>) -> Result<(String, u16), String> {
    let target = target.ok_or("missing HOST and PORT")?;
    let (host, port_text) = match port {
        Some(p) => (unbracket(target)?, p.to_string()),
        None => one_word(target)?,
    };
    let port =
        port_text.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{port_text:?} is not a port"))?;
    relay::check_target(&host)?;
    Ok((host, port))
}

/// `[IPV6]` to the address; a name or a bare address as it is.
fn unbracket(host: &str) -> Result<String, String> {
    let Some(rest) = host.strip_prefix('[') else { return Ok(host.to_string()) };
    match rest.strip_suffix(']') {
        Some(inner) if relay::is_ipv6_literal(inner) => Ok(inner.to_string()),
        Some(_) => Err(format!("{host:?}: brackets hold an IPv6 address, as in [2001:db8::1]")),
        None => Err(format!("{host:?}: '[' is not closed")),
    }
}

/// One word, by the rule of `podssh_ws::dial`'s proxy URLs: `[IPV6]:PORT`,
/// or `HOST:PORT` with one `:`. More than one `:` with no brackets is
/// refused: in `2001:db8::1:22`, the `:22` is a part of the address.
fn one_word(target: &str) -> Result<(String, String), String> {
    if let Some(rest) = target.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or_else(|| format!("{target:?}: '[' is not closed"))?;
        let port = after.strip_prefix(':').ok_or_else(|| format!("missing PORT: {target:?} needs :PORT after ']'"))?;
        return Ok((unbracket(&format!("[{inner}]"))?, port.to_string()));
    }
    if target.matches(':').count() > 1 {
        return Err(format!(
            "{target:?}: an IPv6 address with a port needs brackets, as in [2001:db8::1]:22; or give the port as a second word"
        ));
    }
    let (host, port) = target.rsplit_once(':').ok_or("missing PORT")?;
    Ok((host.to_string(), port.to_string()))
}

async fn session(relays: &RelayList, path: &str, trust: &Trust, target: &str, v6: bool, err: &mut dyn Write) -> i32 {
    let request = Request { relays, path, trust, target, rounds: 1 };
    let opened = podssh_relay::open(&request, &mut |note: &str| {
        let _ = writeln!(err, "podssh: {note}");
    })
    .await;
    match opened {
        Ok(opened) => pump(opened.session, target, v6, err).await,
        Err(failure) => {
            for line in failure.lines(target) {
                let _ = writeln!(err, "podssh: {line}");
            }
            sysexit(failure.last())
        }
    }
}

/// The sysexits code `podssh proxy` exits with when no session opened.
pub fn sysexit(e: &OpenError) -> i32 {
    match e {
        OpenError::Token(TokenError::BadEnvironment) => EX_CONFIG,
        OpenError::Token(TokenError::Connect(c)) | OpenError::Connect { error: c, .. } => match c {
            ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_)) => EX_CONFIG,
            ConnectError::Refused { status: 401 | 403, .. } => EX_NOPERM,
            // The relay answers 400 for a target in a blocked address range.
            ConnectError::Refused { status: 400, body } if podssh_relay::open::is_policy_refusal(body) => EX_NOPERM,
            ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
            _ => EX_UNAVAILABLE,
        },
        _ => EX_UNAVAILABLE,
    }
}

/// How the relay-to-stdout direction ended.
enum Ended {
    Closed {
        code: Option<u16>,
        reason: String,
    },
    /// stdout went away (the consumer, e.g. ssh, exited).
    OutputGone,
}

/// Copy both directions until the relay ends the session.
/// `target` (`host:port`) and `v6` (an IPv6 address) are for the note on how
/// its session ended.
async fn pump(session: RelaySession, target: &str, v6: bool, err: &mut dyn Write) -> i32 {
    let session = Arc::new(session);
    let upstream = stdin_to_relay(session.clone());
    let downstream = relay_to_stdout(session.clone());
    // A link that dies without a word is found by pinging, in about 30 s
    // instead of at the 90 s idle read limit.
    let liveness = session.watch_liveness(podssh_ws::LIVENESS_EVERY, podssh_ws::LIVENESS_ALLOWED);
    tokio::pin!(upstream);
    tokio::pin!(downstream);
    tokio::pin!(liveness);
    let mut sending = true;
    loop {
        tokio::select! {
            reason = &mut liveness => {
                let _ = writeln!(err, "podssh: {reason}");
                return EX_UNAVAILABLE;
            }
            sent = &mut upstream, if sending => match sent {
                Ok(()) => sending = false,
                Err(e) => {
                    let _ = writeln!(err, "podssh: {e}");
                    return EX_UNAVAILABLE;
                }
            },
            ended = &mut downstream => return finish(ended, &session, target, v6, err).await,
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
        session.send_binary(&buf[..n]).await.map_err(|e| format!("sending to the relay failed: {e}"))?;
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

async fn finish(
    ended: Result<Ended, String>,
    session: &RelaySession,
    target: &str,
    v6: bool,
    err: &mut dyn Write,
) -> i32 {
    match ended {
        // 1000 is a normal end (the target closed). The relay uses 1001 for its
        // own limits ("idle timeout", "session time cap"), which are not.
        Ok(Ended::Closed { code: None | Some(1000), .. }) => 0,
        Ok(Ended::Closed { code: Some(code), reason }) => {
            // The hop first; `CODE REASON` stays as the relay wrote it.
            let leg = podssh_ws::session::forward_close(Some(code), &reason);
            let _ = writeln!(err, "podssh: {}: {code} {reason}", leg.what(target));
            if let Some(remedy) = leg.remedy(&reason) {
                let _ = writeln!(err, "podssh: {remedy}");
            }
            if let Some(note) = relay::ipv6_note(v6, &reason) {
                let _ = writeln!(err, "podssh: {note}");
            }
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
