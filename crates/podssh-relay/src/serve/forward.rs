//! `GET /connect/<host>/<port>`, served (T-169): the token, the policy, the
//! dial before the upgrade, then binary frames both ways with the contract's
//! limits and close codes (`docs/relay.md`, "Errors and close codes"). Each
//! write waits for the reader on the other side, so no queue grows without a
//! bound: a slow client slows the target's reads, as TCP would (T-336). The
//! dial goes through the host's proxy when one is set (T-457, `egress`).
//! The road with the resumable layer (T-173, `layer`) dials and pumps each
//! of its links with the same functions. The client's Close shuts the
//! target's writing side, and the target's bytes still go to the client
//! until it closes or is silent for 15 s, as the contract says (T-671); a
//! link of the layer ends at its client's Close, as its session outlives it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::frame;
use podssh_ws::http::request::{self, Request};
use podssh_ws::server;
use podssh_ws::session::RelaySession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::egress::{self, Missed, Plan};
use super::policy::shown;
use super::{answer, Config};

/// The longest wait of `?precheck` for the target's first bytes, as the
/// default relay clamps it (measured 2026-10-01).
const PRECHECK_CAP: Duration = Duration::from_millis(400);
/// How often the limits are looked at.
const TICK: Duration = Duration::from_millis(500);

/// What `/connect/` was asked: the target and its options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub host: String,
    pub port: u16,
    pub family: Option<u8>,
    pub lazy: bool,
    pub precheck: Duration,
}

/// The target and options of a request-target `/connect/<host>/<port>?...`;
/// an IPv6 literal comes bare or in brackets.
pub fn asked(target: &str) -> Option<Asked> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let rest = path.strip_prefix("/connect/")?;
    let (host, port) = rest.rsplit_once('/')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    if host.is_empty() || host.contains('/') {
        return None;
    }
    let mut asked = Asked { host: host.to_string(), port, family: None, lazy: false, precheck: Duration::ZERO };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "family" => asked.family = value.parse().ok().filter(|f| *f == 4 || *f == 6),
            "dial" => asked.lazy = value == "lazy",
            // A value that is not a number is 0, as the default relay reads it.
            "precheck" => asked.precheck = Duration::from_millis(value.parse().unwrap_or(0)).min(PRECHECK_CAP),
            _ => {}
        }
    }
    Some(asked)
}

/// Serve one `/connect/` request on `stream`, `pending` the bytes that came
/// after its head.
pub async fn connect<S>(mut stream: S, head: Request, pending: Vec<u8>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // A token of one session is spent here, whatever the upgrade's end, so
    // that a hop that read it in cleartext has no second use (T-326).
    let token_ok = head.header("x-relay-token").is_some_and(|t| cfg.tokens.take(t, super::tokens::now_ms()));
    if !token_ok {
        return answer(&mut stream, request::refusal(403, "forward: missing or wrong token", &[])).await;
    }
    let key = match server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => return answer(&mut stream, refused.answer()).await,
    };
    let Some(asked) = asked(&head.target) else {
        let why = format!("{}: the path is /connect/HOST/PORT", head.target);
        return answer(&mut stream, request::refusal(400, &why, &[])).await;
    };
    let target = shown(&asked.host, asked.port);
    let plan = match cfg.policy.plan(&asked.host, asked.port, asked.family, &cfg.egress).await {
        Ok(plan) => plan,
        Err(refused) => {
            if let Some(line) = refused.logged() {
                cfg.event(&line);
            }
            return answer(&mut stream, request::refusal(refused.status(), &refused.answer(), &[])).await;
        }
    };
    let mut early = Vec::new();
    let dialed = if asked.lazy {
        None
    } else {
        match dial(&asked.host, &plan, &cfg).await {
            Ok(mut tcp) => {
                if !asked.precheck.is_zero() {
                    let mut buf = vec![0u8; 16 * 1024];
                    if let Ok(Ok(n)) = tokio::time::timeout(asked.precheck, tcp.read(&mut buf)).await {
                        early.extend_from_slice(&buf[..n]);
                    }
                }
                Some(tcp)
            }
            // A proxy's refusal too: the role's 502, with the proxy's status.
            Err(why) => {
                let why = format!("relay: cannot reach {target}: {why}");
                return answer(&mut stream, request::refusal(502, &why, &[])).await;
            }
        }
    };
    if stream.write_all(&server::switching(&key)).await.is_err() {
        return;
    }
    cfg.event("upgrade");
    // The client's Close is answered once the target's bytes are over.
    let session = Arc::new(server::session(stream, pending, None).holding_close_answer());
    let tcp = match dialed {
        Some(tcp) => tcp,
        // `?dial=lazy`: the target is dialed once the client's first bytes come.
        None => match first_then_dial(&session, &asked.host, &plan, &cfg).await {
            Ok((tcp, first)) => {
                let mut tcp = tcp;
                if tcp.write_all(&first).await.is_err() {
                    let _ = session.send_close(1011, "write failed: the target took no bytes").await;
                    return;
                }
                tcp
            }
            Err(Some(why)) => {
                let _ = session.send_close(1011, &format!("connect failed: {why}")).await;
                return;
            }
            Err(None) => return,
        },
    };
    let after = AfterClose::Drains(cfg.limits.half_closed);
    pump(session, tcp.into_split(), early, cfg, after).await;
}

/// The target `host` by `plan`, within the dial's limit in all; `Err` holds
/// the client's words. The owner hears a proxy's fault, with where the
/// proxy is, on the role's line.
pub(super) async fn dial(host: &str, plan: &Plan, cfg: &Config) -> Result<TcpStream, String> {
    match egress::dial(host, plan, &cfg.egress, &cfg.policy.ipv6, cfg.limits.connect).await {
        Ok((tcp, _)) => {
            // A slow target's unsent bytes, as a slow client's (T-336).
            super::sockets::bound_unsent(&tcp);
            Ok(tcp)
        }
        Err(Missed { said, line }) => {
            if let Some(line) = line {
                cfg.event(&format!("proxy: {line}"));
            }
            Err(said)
        }
    }
}

/// `?dial=lazy`: wait for the client's first payload, then dial. `Err(None)`
/// when the client went first.
async fn first_then_dial<S>(
    session: &RelaySession<S>,
    host: &str,
    plan: &Plan,
    cfg: &Config,
) -> Result<(TcpStream, Vec<u8>), Option<String>>
where
    S: AsyncRead + AsyncWrite,
{
    loop {
        let f = session.read_frame().await.map_err(|_| None)?;
        match f.opcode {
            frame::OPCODE_BINARY | frame::OPCODE_CONTINUATION if !f.payload.is_empty() => {
                return dial(host, plan, cfg).await.map(|tcp| (tcp, f.payload)).map_err(Some);
            }
            frame::OPCODE_CLOSE => {
                let _ = session.send_close(1000, "client closed before the target was dialed").await;
                return Err(None);
            }
            _ => {}
        }
    }
}

/// How a session ended, and the Close that says so.
enum End {
    /// The client's Close: the target's writing side is shut.
    Client,
    /// Nothing more can be said to the client.
    Gone,
    Close(u16, String),
}

/// What the client's Close does to the target's way to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AfterClose {
    /// It ends the session, answered by the reader: a link of the layer,
    /// whose session goes on without it.
    Ends,
    /// The target's bytes go on until it closes, or is silent this long
    /// after its last byte or the Close; the session's Close is the answer
    /// (`docs/relay.md`, "The forward path", T-671). Its session holds the
    /// answer ([`RelaySession::holding_close_answer`]).
    Drains(Duration),
}

/// The words of a Close after the client's, when the target was silent for
/// `idle`: the contract's, `client half-closed, target idle for 15s`.
pub(super) fn half_closed(idle: Duration) -> String {
    format!("client half-closed, target idle for {}s", idle.as_secs())
}

/// Bytes both ways between the client and the target's two halves until one
/// side ends or a limit is met. The target is a TCP connection, or a link's
/// end of the resumable layer (T-173); `after`, what the client's Close does.
pub(super) async fn pump<S, R, W>(
    session: Arc<RelaySession<S>>,
    (mut from_target, mut to_target): (R, W),
    early: Vec<u8>,
    cfg: Arc<Config>,
    after: AfterClose,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let started = Instant::now();
    let moved = Arc::new(AtomicU64::new(0));
    // The time of the last payload, in ms after the start: keepalives and
    // pings do not count, as on the default relay.
    let heard = Arc::new(AtomicU64::new(0));
    let limits = cfg.limits.clone();
    let stamp = |heard: &AtomicU64| heard.store(started.elapsed().as_millis() as u64, Ordering::SeqCst);

    let up = {
        let (session, moved, heard) = (session.clone(), moved.clone(), heard.clone());
        async move {
            loop {
                let f = match session.read_frame().await {
                    Ok(f) => f,
                    Err(_) => return End::Gone,
                };
                match f.opcode {
                    frame::OPCODE_BINARY | frame::OPCODE_CONTINUATION => {
                        if f.payload.is_empty() {
                            continue;
                        }
                        if let Err(e) = to_target.write_all(&f.payload).await {
                            return End::Close(1011, format!("write failed: {e}"));
                        }
                        moved.fetch_add(f.payload.len() as u64, Ordering::SeqCst);
                        stamp(&heard);
                    }
                    frame::OPCODE_CLOSE => {
                        cfg.event(&format!("close {}", close_code(&f.payload)));
                        let _ = to_target.shutdown().await;
                        return End::Client;
                    }
                    _ => return End::Close(1003, "text frames are not accepted".into()),
                }
            }
        }
    };
    let down = {
        let (session, moved, heard) = (session.clone(), moved.clone(), heard.clone());
        async move {
            if !early.is_empty() {
                if session.send_binary(&early).await.is_err() {
                    return End::Gone;
                }
                moved.fetch_add(early.len() as u64, Ordering::SeqCst);
                stamp(&heard);
            }
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match from_target.read(&mut buf).await {
                    Ok(0) => return End::Close(1000, "target closed".into()),
                    Ok(n) => n,
                    Err(e) => return End::Close(1011, format!("target read failed: {e}")),
                };
                if session.send_binary(&buf[..n]).await.is_err() {
                    return End::Gone;
                }
                moved.fetch_add(n as u64, Ordering::SeqCst);
                stamp(&heard);
            }
        }
    };
    let limit = {
        let (session, moved, heard) = (session.clone(), moved.clone(), heard.clone());
        async move {
            let mut kept = Instant::now();
            loop {
                tokio::time::sleep(TICK).await;
                let idle = started.elapsed().saturating_sub(Duration::from_millis(heard.load(Ordering::SeqCst)));
                if idle >= limits.idle {
                    return End::Close(1001, "idle timeout".into());
                }
                if started.elapsed() >= limits.session {
                    return End::Close(1001, "session time cap".into());
                }
                if moved.load(Ordering::SeqCst) >= limits.bytes {
                    return End::Close(1009, "session byte cap".into());
                }
                if kept.elapsed() >= limits.keepalive {
                    // An empty binary frame, which the client skips.
                    let _ = session.send_binary(&[]).await;
                    kept = Instant::now();
                }
            }
        }
    };
    // The way down and the limits outlive the client's Close.
    tokio::pin!(down, limit);
    let end = tokio::select! {
        end = up => end,
        end = &mut down => end,
        end = &mut limit => end,
    };
    let end = match (end, after) {
        // The target's writing side is shut; its answer still comes.
        (End::Client, AfterClose::Drains(idle)) => {
            let quiet = until_quiet(started, started.elapsed(), &heard, idle);
            tokio::select! {
                end = &mut down => end,
                end = &mut limit => end,
                end = quiet => end,
            }
        }
        (end, _) => end,
    };
    if let End::Close(code, why) = end {
        let _ = session.send_close(code, &why).await;
    }
}

/// Until the target was silent for `idle` since its last byte, or since the
/// client's Close at `closed_at`, each counted from `started`: the
/// contract's end of a half-closed session (15.4 s after a Close that
/// GitHub answered 0.4 s after it, measured 2026-10-09).
async fn until_quiet(started: Instant, closed_at: Duration, heard: &AtomicU64, idle: Duration) -> End {
    loop {
        // After the Close, only the target's bytes move `heard`.
        let last = Duration::from_millis(heard.load(Ordering::SeqCst)).max(closed_at);
        let due = started + last + idle;
        if Instant::now() >= due {
            return End::Close(1000, half_closed(idle));
        }
        tokio::time::sleep_until(due).await;
    }
}

/// The code of a Close's payload, 1005 for none.
fn close_code(payload: &[u8]) -> u16 {
    if payload.len() >= 2 {
        u16::from_be_bytes([payload[0], payload[1]])
    } else {
        1005
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_and_options_of_a_connect_path_are_read() {
        let a = asked("/connect/github.com/22").unwrap();
        assert_eq!((a.host.as_str(), a.port, a.lazy, a.family), ("github.com", 22, false, None));
        let b = asked("/connect/2001:db8::1/22?family=6&dial=lazy&precheck=9999").unwrap();
        assert_eq!((b.host.as_str(), b.family, b.lazy, b.precheck), ("2001:db8::1", Some(6), true, PRECHECK_CAP));
        assert_eq!(asked("/connect/[::1]/443").unwrap().host, "::1");
        assert_eq!(asked("/connect/h/22?precheck=soon").unwrap().precheck, Duration::ZERO);
        for bad in ["/connect/h", "/connect//22", "/connect/h/0", "/connect/h/x", "/health", "/connect/a/b/22"] {
            assert!(asked(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_half_closed_session_ends_in_the_contracts_words() {
        let idle = super::super::Limits::default().half_closed;
        assert_eq!(half_closed(idle), "client half-closed, target idle for 15s");
    }
}
