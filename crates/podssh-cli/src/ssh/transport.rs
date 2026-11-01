//! The stream to the first hop: through the relay, with failover, or over
//! TCP with `--direct`. `ssh` runs a session on it, and `cp` an SFTP session.
//! When the user named no relay and each relay host failed, the direct road
//! once, as the road table gives it (T-363): the dial of `--direct`, then
//! the server's version line, which goes to the SSH client first.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_relay::open::{OpenError, Request};
use podssh_ssh::{Hop, Log, RelayStatus};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::resolve::{Resolved, Transport};
use crate::exitmap::sysexits;

/// A stream of either transport.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// The first hop, reached.
pub struct Reached {
    /// The bytes to and from the first hop.
    pub stream: Box<dyn Duplex>,
    /// The relay leg's status, when the relay carries the stream.
    pub relay: Option<RelayStatus>,
    /// The proxy of a `--direct` connection, when one carries it.
    pub direct_proxy: Option<DirectProxy>,
    /// The task that carries the session in the resumable layer, when the
    /// road runs one (a podssh node behind a `cf://` name, T-300): it ends
    /// once its `CLOSE` went out and its last line was said. The layer's
    /// heartbeat finds a dead link, so SSH's keepalives by default would
    /// only end a session that it carries onto a new one (T-154).
    pub layer: Option<Carriage>,
}

/// The end of a task that carries a session in the layer.
pub type Carriage = tokio::sync::oneshot::Receiver<()>;

/// How long a Ping of the forward road waits for the relay before the
/// relay counts as silent: the layer's wait (T-302), as the notice is one
/// on each road.
pub const SILENCE_WAIT: std::time::Duration = podssh_relay::session::hearing::WAIT;

/// How long a run waits, after SSH, for the layer's task to end: its
/// `CLOSE`, and the line of a failure.
pub const CARRIAGE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Wait for the layer's task of a road, if it runs one, within
/// [`CARRIAGE_WAIT`]: else the node keeps the session for a resume until
/// its deadline, and the line of a failure may never be said.
pub async fn settle(layer: Option<Carriage>) {
    if let Some(layer) = layer {
        let _ = tokio::time::timeout(CARRIAGE_WAIT, layer).await;
    }
}

/// The layer's tasks of the roads whose connection a command hands on
/// (T-331): each waits here until the command's end, in [`settled`].
static KEPT: std::sync::Mutex<Vec<Carriage>> = std::sync::Mutex::new(Vec::new());

/// Keep the layer's task of a road, if it runs one, for [`settled`].
pub fn keep(layer: Option<Carriage>) {
    if let Some(layer) = layer {
        let mut kept = KEPT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        running(&mut kept);
        kept.push(layer);
    }
}

/// Only the tasks that still run: a listener that keeps listening hands on
/// a road for each client, and the list would grow with each.
fn running(kept: &mut Vec<Carriage>) {
    kept.retain_mut(|layer| matches!(layer.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)));
}

/// Run `work`, a command's whole run, then wait for each task of the layer
/// that it kept, within [`CARRIAGE_WAIT`] in all: inside the runtime, as
/// a task spawned there runs only while the runtime does.
pub async fn settled<T>(work: impl std::future::Future<Output = T>) -> T {
    let out = work.await;
    let kept = std::mem::take(&mut *KEPT.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
    let deadline = tokio::time::Instant::now() + CARRIAGE_WAIT;
    for layer in kept {
        let _ = tokio::time::timeout_at(deadline, layer).await;
    }
    out
}

/// The proxy that carries a `--direct` connection, and whether any byte came
/// back through it. A `200` to CONNECT proves that the proxy took the
/// request, not that the tunnel carries bytes as they are: a proxy that
/// intercepts TLS waits for a ClientHello, then sends nothing or resets
/// (T-317), and a failure with nothing heard names it.
#[derive(Clone)]
pub struct DirectProxy {
    proxy: String,
    heard: Arc<AtomicBool>,
}

impl DirectProxy {
    /// The line that names the proxy as the cause, when no byte came back.
    pub fn cause(&self, target: &str) -> Option<String> {
        (!self.heard.load(Ordering::Relaxed)).then(|| {
            format!(
                "{target}: the proxy {} took the CONNECT, and no byte of an SSH server came back: it may expect \
                 TLS and carry no SSH. Without --direct, the relay carries SSH over HTTPS",
                self.proxy
            )
        })
    }
}

/// A stream that marks the first byte that it reads.
struct Heard<S> {
    inner: S,
    heard: Arc<AtomicBool>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Heard<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.heard.store(true, Ordering::Relaxed);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Heard<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Why the first hop was not reached: the lines that say so, and the
/// sysexits code of a command that uses them (`ssh` exits 255 instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotReached {
    /// Each line, for the log; empty when each attempt was logged already.
    pub lines: Vec<String>,
    /// 64 for a target that the relay cannot carry, else as `proxy` exits.
    pub code: i32,
}

/// Reach the first `-J` hop, or the destination, as `resolved` says. A
/// `node://` destination is not reached here: its road has its own runner.
pub async fn reach(resolved: &Resolved, log: &Arc<Log>) -> Result<Reached, NotReached> {
    reach_skipping(resolved, 0, log).await
}

/// [`reach`], with the first `skip` relay hosts tried last: a try after a
/// drop of the link to a host goes to the next one (T-025).
pub async fn reach_skipping(resolved: &Resolved, skip: usize, log: &Arc<Log>) -> Result<Reached, NotReached> {
    let opts = &resolved.options;
    let first = opts.jump.first().unwrap_or(&opts.destination);
    let target = podssh_ws::dial::authority(&first.host, first.port);
    match &resolved.transport {
        Transport::Relay { relays, trust, family, failover, then_direct } => {
            let turned;
            let relays = if skip == 0 {
                relays
            } else {
                let mut hosts = relays.hosts.clone();
                let n = hosts.len().max(1);
                hosts.rotate_left(skip % n);
                turned = podssh_relay::relay::RelayList { hosts, explicit: relays.explicit };
                &turned
            };
            let mut path = podssh_relay::relay::forward_path(&first.host, first.port)
                .map_err(|why| NotReached { lines: vec![why], code: sysexits::EX_USAGE })?;
            if let Some(f) = family {
                path.push_str(&format!("?family={f}"));
            }
            let hosts: Vec<&str> = relays.hosts.iter().map(|r| r.host.as_str()).collect();
            log.verbose(&format!("connecting to {target} through the relay ({})", hosts.join(", ")));
            let request = Request {
                relays,
                path: &path,
                trust,
                target: &target,
                rounds: resolved.connection_attempts,
                failover: *failover,
            };
            let note_log = log.clone();
            let started = tokio::time::Instant::now();
            match podssh_relay::open(&request, &mut |note: &str| note_log.info(note)).await {
                Ok(opened) => {
                    log.verbose(&format!("the relay host {} opened the session", opened.relay.host));
                    podssh_ssh::outcome::relay_host(&opened.relay.host);
                    let (stream, status) = podssh_ssh::relay_stream::spawn(opened.session);
                    // The relay's silence, for the notice (T-307).
                    let heard = status.clone();
                    opts.silence.attach(move || heard.silent(tokio::time::Instant::now(), SILENCE_WAIT));
                    Ok(Reached { stream: Box::new(stream), relay: Some(status), direct_proxy: None, layer: None })
                }
                Err(failure) => {
                    let not = NotReached { lines: failure.lines(&target), code: crate::proxy::sysexit(failure.last()) };
                    // Offline, the direct road may not connect either.
                    if !*then_direct || matches!(failure.last(), OpenError::Offline) {
                        return Err(not);
                    }
                    Box::pin(after_relay(first, &target, not, started.elapsed(), log)).await
                }
            }
        }
        Transport::Node { .. } => Err(NotReached {
            lines: vec!["a node:// destination is reached through its pair, not here".into()],
            code: sysexits::EX_USAGE,
        }),
        Transport::Iroh { .. } => Err(NotReached {
            lines: vec!["an iroh: destination is reached over the iroh road, not here".into()],
            code: sysexits::EX_USAGE,
        }),
        Transport::Derp { .. } => Err(NotReached {
            lines: vec!["a derp: destination is reached over the DERP road, not here".into()],
            code: sysexits::EX_USAGE,
        }),
        Transport::Cloudflare { host, trust, channel } => {
            super::cloudflare::reach(host, trust, channel, opts, log).await
        }
        Transport::Cloud { road, trust } => super::cloud::reach(road, trust, log).await,
        Transport::Direct => {
            if podssh_relay::open::offline() {
                return Err(NotReached {
                    lines: vec![format!(
                        "{} is set, so podssh does not connect anywhere",
                        podssh_relay::open::OFFLINE_ENV
                    )],
                    code: sysexits::EX_UNAVAILABLE,
                });
            }
            let multipath = multipath_asked(std::env::var(MPTCP_ENV).ok().as_deref())
                .map_err(|why| NotReached { lines: vec![why], code: sysexits::EX_CONFIG })?;
            let rounds = resolved.connection_attempts.max(1);
            for round in 1..=rounds {
                if round > 1 {
                    let wait = podssh_relay::open::backoff(round - 1);
                    log.info(&format!("retrying in {:.1} s (attempt {round} of {rounds})", wait.as_secs_f32()));
                    tokio::time::sleep(wait).await;
                }
                log.verbose(&format!("connecting to {target} directly"));
                let dialled = direct(&first.host, first.port, multipath, &target, log).await;
                match dialled {
                    Ok(tcp) => {
                        let _ = tcp.set_nodelay(true);
                        // A write that makes no progress fails as on the
                        // relay leg, never a wait for ever (T-227).
                        let stream = podssh_ws::write_limit::WriteLimit::new(tcp, podssh_ws::client::WRITE_TIMEOUT);
                        let Some(proxy) = podssh_ws::dial::proxy_from_env(&first.host).ok().flatten() else {
                            return Ok(Reached {
                                stream: Box::new(stream),
                                relay: None,
                                direct_proxy: None,
                                layer: None,
                            });
                        };
                        let heard = Arc::new(AtomicBool::new(false));
                        let watched = Heard { inner: stream, heard: heard.clone() };
                        let direct_proxy = Some(DirectProxy { proxy: proxy.to_string(), heard });
                        return Ok(Reached { stream: Box::new(watched), relay: None, direct_proxy, layer: None });
                    }
                    Err(e) => log.error(&format!("could not connect to {target}: {e}")),
                }
            }
            Err(NotReached { lines: Vec::new(), code: sysexits::EX_UNAVAILABLE })
        }
    }
}

/// The variable that asks for Multipath TCP on the direct road (T-172).
pub const MPTCP_ENV: &str = "PODSSH_MPTCP";

/// `PODSSH_MPTCP`: yes asks for Multipath TCP; no, empty or unset asks for
/// nothing; another value is a setting that cannot be used.
fn multipath_asked(value: Option<&str>) -> Result<bool, String> {
    let Some(value) = value else { return Ok(false) };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "no" | "off" | "false" | "0" => Ok(false),
        "yes" | "on" | "true" | "1" => Ok(true),
        _ => Err(format!("{MPTCP_ENV}={value}: yes or no")),
    }
}

/// One dial of `--direct`, through `HTTPS_PROXY` when it is set; with
/// `multipath`, Multipath TCP where the road and the host allow it, and `-v`
/// says which the connection got.
async fn direct(
    host: &str,
    port: u16,
    multipath: bool,
    target: &str,
    log: &Log,
) -> Result<tokio::net::TcpStream, podssh_ws::DialError> {
    let (proxy, limit) = (ProxyChoice::FromEnvironment, podssh_relay::open::CONNECT_TIMEOUT);
    if !multipath {
        return podssh_ws::dial::dial(host, port, &proxy, limit).await;
    }
    let (tcp, how) = podssh_ws::dial::dial_multipath(host, port, &proxy, limit).await?;
    log.verbose(&format!("{target}: {how}"));
    Ok(tcp)
}

/// How long the direct road after the relay hosts waits for the server's
/// version line (T-363): an SSH server sends it at once, and a proxy that
/// takes the CONNECT and carries no SSH sends nothing.
pub const VERSION_WAIT: Duration = Duration::from_secs(10);

/// The direct road once each relay host failed (T-363): one dial of
/// `first`, as `--direct` makes it, then the server's version line within
/// [`VERSION_WAIT`], whose bytes go to the SSH client first. When it fails
/// too, the relay's lines, then one that names both roads with their times;
/// the exit stays the relay's.
async fn after_relay(
    first: &Hop,
    target: &str,
    relay: NotReached,
    relay_took: Duration,
    log: &Log,
) -> Result<Reached, NotReached> {
    let proxy = podssh_ws::dial::proxy_from_env(&first.host).ok().flatten().map(|p| p.to_string());
    log.info(&announce(relay_took, target, proxy.as_deref()));
    for line in &relay.lines {
        log.verbose(line);
    }
    let started = tokio::time::Instant::now();
    let failed = |why: String| {
        let mut lines = relay.lines.clone();
        lines.push(both_failed(relay_took, target, started.elapsed(), &why));
        NotReached { lines, code: relay.code }
    };
    // A bad PODSSH_MPTCP asks for nothing here: the one dial is a plain one.
    let multipath = multipath_asked(std::env::var(MPTCP_ENV).ok().as_deref()).unwrap_or(false);
    let tcp = match direct(&first.host, first.port, multipath, target, log).await {
        Ok(tcp) => tcp,
        Err(e) => return Err(failed(e.to_string())),
    };
    let _ = tcp.set_nodelay(true);
    let mut stream = podssh_ws::write_limit::WriteLimit::new(tcp, podssh_ws::client::WRITE_TIMEOUT);
    match super::banner::read(&mut stream, VERSION_WAIT).await {
        Ok(read) => {
            log.verbose(&format!("the direct road carried the session to {target}"));
            let stream = Box::new(super::banner::Prefixed::new(read, stream));
            Ok(Reached { stream, relay: None, direct_proxy: None, layer: None })
        }
        // A proxy that takes the CONNECT and carries no SSH is no road (T-317).
        Err(why) => Err(failed(match &proxy {
            Some(proxy) => format!(
                "the proxy {proxy} took the CONNECT, then {why}: no byte of an SSH server came back, as from a \
                 proxy that expects TLS and carries no SSH"
            ),
            None => format!("the connection opened, then {why}"),
        })),
    }
}

/// The line before the direct road's dial: through a proxy, its CONNECT
/// names the target, which the relay's does not.
fn announce(relay_took: Duration, target: &str, proxy: Option<&str>) -> String {
    let via = proxy.map(|p| format!(", through the proxy {p}, whose CONNECT names it")).unwrap_or_default();
    format!(
        "each relay host failed, after {:.1} s; podssh tries {target} directly{via} (PODSSH_DIRECT=no turns this \
         off; -v gives the relay's lines)",
        relay_took.as_secs_f32()
    )
}

/// The line of both roads, each with its time, when both failed.
fn both_failed(relay_took: Duration, target: &str, direct_took: Duration, why: &str) -> String {
    format!(
        "the relay road failed after {:.1} s, and the direct road to {target} after {:.1} s: {why}",
        relay_took.as_secs_f32(),
        direct_took.as_secs_f32()
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{announce, both_failed, keep, multipath_asked, running, settled, CARRIAGE_WAIT, VERSION_WAIT};
    use crate::ssh::banner::{self, Prefixed};

    /// The line before the direct road names the target and the proxy, and
    /// the switch; the line of a double failure names both roads and their
    /// times (T-363).
    #[test]
    fn the_lines_of_the_direct_road_name_the_target_the_proxy_and_both_times() {
        let said = announce(Duration::from_millis(2300), "ssh.example:22", Some("127.0.0.1:3128"));
        let starts = "each relay host failed, after 2.3 s; podssh tries ssh.example:22 directly";
        assert!(said.starts_with(starts), "{said}");
        assert!(said.contains("through the proxy 127.0.0.1:3128") && said.contains("PODSSH_DIRECT=no"), "{said}");
        assert!(!announce(Duration::ZERO, "h:22", None).contains("proxy"), "no proxy, none named");
        let both = both_failed(Duration::from_millis(1500), "h:2222", Duration::from_millis(40), "refused");
        assert_eq!(both, "the relay road failed after 1.5 s, and the direct road to h:2222 after 0.0 s: refused");
    }

    /// The version line is read, and given back to the client first; a
    /// silent server and one that is no SSH server are named (T-363).
    #[tokio::test(start_paused = true)]
    async fn the_version_line_is_given_back_and_a_silence_is_named_at_its_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut ours, mut theirs) = tokio::io::duplex(1024);
        theirs.write_all(b"a line first\r\nSSH-2.0-test\r\n").await.unwrap();
        let read = banner::read(&mut ours, VERSION_WAIT).await.expect("a version line");
        let mut again = Prefixed::new(read, ours);
        theirs.write_all(b"more").await.unwrap();
        drop(theirs);
        let mut all = Vec::new();
        again.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"a line first\r\nSSH-2.0-test\r\nmore");
        let (mut silent, _held) = tokio::io::duplex(1024);
        let started = tokio::time::Instant::now();
        let why = banner::read(&mut silent, VERSION_WAIT).await.unwrap_err();
        assert_eq!(started.elapsed(), VERSION_WAIT);
        assert_eq!(why, "nothing came in 10 s");
        let (mut tls, mut proxy) = tokio::io::duplex(1024);
        proxy.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x50]).await.unwrap();
        assert_eq!(banner::read(&mut tls, VERSION_WAIT).await.unwrap_err(), "what came was not an SSH banner");
    }

    /// A command that hands its connection on waits, at its end, for the
    /// layer's task that it kept: its `CLOSE` and its last line (T-331);
    /// a task that never ends holds it no longer than the wait.
    #[tokio::test(start_paused = true)]
    async fn a_command_waits_for_the_layer_s_task_that_it_kept_and_no_longer_than_the_wait() {
        let (ended, done) = tokio::sync::oneshot::channel();
        let started = tokio::time::Instant::now();
        let out = settled(async {
            keep(Some(done));
            keep(None);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _ = ended.send(());
            });
            7
        })
        .await;
        assert_eq!(out, 7);
        assert_eq!(started.elapsed(), Duration::from_secs(2), "until the task's end");
        let (never, done) = tokio::sync::oneshot::channel::<()>();
        let started = tokio::time::Instant::now();
        settled(async { keep(Some(done)) }).await;
        assert_eq!(started.elapsed(), CARRIAGE_WAIT, "a task that never ends");
        drop(never);
        let started = tokio::time::Instant::now();
        settled(async {}).await;
        assert_eq!(started.elapsed(), Duration::ZERO, "nothing kept, no wait");
    }

    /// The tasks that ended leave the list as the next one comes: those of
    /// the clients that a listener served before.
    #[test]
    fn a_kept_task_that_ended_leaves_the_list() {
        let (sent, ended) = tokio::sync::oneshot::channel::<()>();
        let _ = sent.send(());
        let (gone, dropped) = tokio::sync::oneshot::channel::<()>();
        drop(gone);
        let (_runs, running_one) = tokio::sync::oneshot::channel::<()>();
        let mut kept = vec![ended, dropped, running_one];
        running(&mut kept);
        assert_eq!(kept.len(), 1, "the one that still runs");
    }

    #[test]
    fn podssh_mptcp_asks_with_yes_and_refuses_another_word() {
        assert_eq!(multipath_asked(None), Ok(false));
        for no in ["", "no", "OFF", "0", "false"] {
            assert_eq!(multipath_asked(Some(no)), Ok(false), "{no}");
        }
        for yes in ["yes", "On", "1", "true"] {
            assert_eq!(multipath_asked(Some(yes)), Ok(true), "{yes}");
        }
        assert!(multipath_asked(Some("maybe")).unwrap_err().contains("PODSSH_MPTCP=maybe"));
    }
}
