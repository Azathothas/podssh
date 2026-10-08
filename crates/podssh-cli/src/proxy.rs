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

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::relay::{self, Relay};

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
    let mut notes = Vec::new();
    let opened = crate::relay_open::open(relay, path, trust, target, &mut |note: &str| notes.push(note.to_string())).await;
    for note in notes {
        let _ = writeln!(err, "podssh: {note}");
    }
    match opened {
        Ok(session) => pump(session, err).await,
        Err(e) => {
            for line in e.lines() {
                let _ = writeln!(err, "podssh: {line}");
            }
            e.sysexit()
        }
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
        // 1000 is a normal end (the target closed). The relay uses 1001 for its
        // own limits ("idle timeout", "session time cap"), which are not.
        Ok(Ended::Closed { code: None | Some(1000), .. }) => 0,
        Ok(Ended::Closed { code: Some(code), reason }) => {
            let _ = writeln!(err, "podssh: the relay closed the session: {code} {reason}");
            if reason.contains("idle") {
                let _ = writeln!(
                    err,
                    "podssh: the relay closes a session after 180 s without traffic; set ServerAliveInterval below 180"
                );
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
