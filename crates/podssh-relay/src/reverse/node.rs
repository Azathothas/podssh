//! The node of a pair: one WebSocket to `/v1/node/<name>`, kept up, and the
//! actions for each way it can end (`docs/reverse.md`, "Node").

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::client::{ConnectError, Endpoint, WsClientConfig};
use podssh_ws::{DialError, ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use super::closes::RelayClose;
use super::framing::SessionId;
use super::serve::{serve, End, Settings};
use super::wire::{self, Socket, Wire};
use crate::pair::Pair;

/// The local side of a session, as a handler opens it.
pub type Opening<S> = Pin<Box<dyn Future<Output = Result<S, String>> + Send>>;

/// Lets a session's client in, and says whether the node has room for it:
/// the resumable layer's admission (T-300).
pub type Admit = Box<dyn FnOnce() -> bool + Send>;

/// Why a client that the node would let in is not: the budget is full.
pub const NO_ROOM: &str = "this node keeps as many sessions as its budget allows";

/// What a node does with each session that the relay opens: a byte stream to
/// carry, or a reason to refuse it. The node carries bytes only; what they
/// mean is the handler's (`docs/architecture.md`).
pub trait Handler: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    fn open(&self, id: SessionId) -> Opening<Self::Stream>;

    /// [`Handler::open`] under the resumable layer, which keeps the session
    /// for a resume once `admit` let its client in. A handler that checks
    /// no client lets it in at once; one that checks a key, once the key is
    /// let in.
    fn open_admitted(&self, id: SessionId, admit: Admit) -> Opening<Self::Stream> {
        if admit() {
            self.open(id)
        } else {
            Box::pin(async { Err(NO_ROOM.to_string()) })
        }
    }

    /// The bytes that may wait for a session's local side before the node
    /// takes it for stalled and ends the session. A handler with its own
    /// flow control holds its window, so that a slow local side is not
    /// taken for a stopped one.
    fn queue_bytes(&self) -> usize {
        QUEUE_BYTES
    }

    /// The node's socket, whose role registers tokens of one leg (T-615), or
    /// `None` once it ended; each socket says so at its `hello`. Only the
    /// resumable layer passes it on ([`Handler::registers`]), as a session
    /// with no layer has no later leg.
    fn attach(&self, _frames: Option<crate::e2e::legs::Frames>) {}

    /// Where the tokens of one leg of the sessions that this handler lets
    /// in go: a handler of the end-to-end channel above the layer registers
    /// them there.
    fn registers(&self, _frames: Option<crate::e2e::legs::Frames>) {}

    /// The role took the token of one leg of `digest` (hex) for an
    /// operator's upgrade: the handler that registered it registers the next.
    fn spent(&self, _digest: &str) {}
}

/// The bytes that may wait for a local side with no flow control of its own:
/// the relay has none for one session, so a stalled one ends.
pub const QUEUE_BYTES: usize = 1 << 20;

/// Asked when the pair expires; a new pair to go on with, or `None` to stop.
pub type RepairHook = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Option<Pair>> + Send>> + Send + Sync>;

/// What a node runs with.
pub struct NodeConfig<'a> {
    pub pair: Pair,
    /// The label that the pair is stored under, deleted when the relay says
    /// that the pair was stopped, while it holds that pair.
    pub label: Option<String>,
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// Bound on connecting.
    pub timeout: Duration,
    pub settings: Settings,
    /// Asked at the expiry for the next pair; none, and an expired pair
    /// ends the node.
    pub repair: Option<RepairHook>,
    /// TLS, except in the tests of an embedder.
    pub wire: Wire,
    /// Lines for the user: each `409` after a loss, with the time left.
    pub say: Option<&'a (dyn Fn(String) + Send + Sync)>,
}

/// Why a node ended. Each is final: a failure that a reconnection repairs is
/// handled inside [`run`].
#[derive(Debug)]
pub enum Exit {
    /// The caller stopped it: each session got `close`, the socket a Close 1000.
    Stopped,
    /// `409`: another node holds the name, at the first registration; or
    /// the relay held the old socket longer than `Settings::rejoin` after a
    /// loss (T-261).
    NameInUse,
    /// `1001 operator stopped reverse relay`: the pair is over, and its stored
    /// copy is deleted.
    PairStopped,
    /// `1001 pair expired`, or a `403` after the expiry, with no new pair.
    PairExpired,
    /// A `403` before the expiry: a stopped pair or a wrong token.
    Forbidden,
    /// The node cannot connect as it is set up: an unusable proxy setting or
    /// trust store, or a host that plain `ws://` refuses. A reconnection would
    /// repeat it.
    Unusable(String),
}

/// What to do after a socket ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    Reconnect,
    Repair,
    Exit(&'static str),
}

/// The action for a Close of the relay (`docs/reverse.md`, "Exit codes", 3):
/// by the code and the reason, never the code alone.
pub fn after_close(close: &RelayClose) -> Next {
    let reason = close.reason.trim().to_ascii_lowercase();
    match close.code {
        1001 if reason == "operator stopped reverse relay" => Next::Exit("stopped"),
        1001 if reason == "pair expired" => Next::Repair,
        1003 | 1009 => Next::Exit("fault"),
        _ => Next::Reconnect,
    }
}

/// A relay's Close of a planned restart (RFC 6455's "Service Restart"), which
/// podssh's relay role sends before it stops (T-255).
pub const RESTART: u16 = 1012;

/// A node connects again at once this often at most: a relay that takes each
/// socket and drops it at once meets the backoff from the second time.
pub const AT_ONCE_EVERY: Duration = Duration::from_secs(10);

/// Whether a node whose socket ended connects again at once (T-255, T-421):
/// after a socket that served, as a restart (`1012`), a drop with no Close
/// and a fault of one frame are no overload; and once each [`AT_ONCE_EVERY`]
/// at most, `last` being when it last went at once.
pub fn again_at_once(served: bool, last: Option<Instant>, now: Instant) -> bool {
    served && last.is_none_or(|at| now.saturating_duration_since(at) >= AT_ONCE_EVERY)
}

/// How a socket that served ended, in the words of the node's line: the
/// relay's restart, a fault of this node's bytes, another Close, or a link
/// that ended with no Close. `None` for a stop of the caller's.
pub fn ended_words(end: &End) -> Option<String> {
    let reason = |text: &str| match podssh_ws::text::one_line(text) {
        shown if shown.is_empty() => "no reason".to_string(),
        shown => shown,
    };
    Some(match end {
        End::Stopped => return None,
        End::Closed(close) if close.code == RESTART => {
            format!("the relay is restarting (relay close {RESTART}: {})", reason(&close.reason))
        }
        End::Closed(close) if matches!(after_close(close), Next::Exit("fault")) => {
            format!("the relay closed the node for a fault of this node: {} {}", close.code, reason(&close.reason))
        }
        End::Closed(close) => {
            format!("the relay closed the node's socket (relay close {}: {})", close.code, reason(&close.reason))
        }
        End::Failed(e) => format!("the link to the relay ended with no Close ({})", reason(&e.to_string())),
    })
}

/// Run the node until it ends; reconnect after a broken socket, at once the
/// first time after a socket that served ([`again_at_once`]), else with the
/// jittered backoff of the forward opener, with a line that says how the
/// socket ended. `config.pair` is then the pair that the node ended with: a
/// new one after a re-pair.
///
/// A `409` at the first registration means that another node has the name,
/// or that the relay still holds the socket of the node that ran just before
/// this one: the node connects again for `Settings::first_conflict`, then
/// exits (T-416). After a loss it means that the relay still holds the old
/// socket: the node connects again until `Settings::rejoin` after the loss,
/// as the sessions that the resumable layer keeps wait that long (T-261;
/// rule 6 of `docs/reverse.md`).
pub async fn run<H, F>(config: &mut NodeConfig<'_>, handler: Arc<H>, stop: F) -> Exit
where
    H: Handler,
    F: Future<Output = ()>,
{
    let mut stop = Box::pin(stop);
    let mut retry: u32 = 0;
    // When the node last lost a socket that it held.
    let mut lost: Option<Instant> = None;
    // When the relay first answered `409` to a node that had held no socket.
    let mut first_conflict: Option<Instant> = None;
    // When the node last connected again at once (T-255).
    let mut at_once: Option<Instant> = None;
    loop {
        // How the socket ended, when one served this time: the words of the
        // next try's line.
        let mut ended: Option<String> = None;
        let path = match crate::relay::node_path(&config.pair.name) {
            Ok(path) => path,
            Err(_) => return Exit::Forbidden,
        };
        let ws = WsClientConfig {
            endpoint: Endpoint { host: config.pair.relay.host.clone(), port: config.pair.relay.port, path },
            trust: config.trust.clone(),
            server_name: config.pair.relay.host.clone(),
            timeout: config.timeout,
            // A node socket can be quiet for long; pings find a dead one.
            idle_timeout: None,
            proxy: config.proxy.clone(),
        };
        let connected = tokio::select! {
            connected = wire::open(config.wire, &ws, config.pair.node_token()) => connected,
            () = &mut stop => return Exit::Stopped,
        };
        let next = match connected {
            Ok(socket) => {
                retry = 0;
                // Only now can an operator reach the node: a user, and a
                // test, wait for this line, not for the start.
                if let Some(say) = config.say {
                    let again = if lost.is_some() { " again" } else { "" };
                    say(format!("online{again}: the relay takes this pair's sessions"));
                }
                let end = match socket {
                    Socket::Tls(session) => serve(session, handler.clone(), config.settings, &mut stop).await,
                    #[cfg(feature = "plain-ws")]
                    Socket::Plain(session) => serve(session, handler.clone(), config.settings, &mut stop).await,
                    // A carrier's role takes no node's path (T-595): never
                    // here, but a socket is a socket.
                    #[cfg(feature = "serve")]
                    Socket::Carrier(session) => serve(session, handler.clone(), config.settings, &mut stop).await,
                };
                lost = Some(Instant::now());
                ended = ended_words(&end);
                match end {
                    End::Stopped => return Exit::Stopped,
                    End::Failed(_) => Next::Reconnect,
                    End::Closed(close) => match after_close(&close) {
                        Next::Exit("stopped") => {
                            // This node's pair only: one stored under the
                            // label since is the next pair (T-395).
                            if let Some(label) = &config.label {
                                if matches!(crate::pair::load(label), Ok(Some(kept)) if kept.name == config.pair.name) {
                                    let _ = crate::pair::remove(label);
                                }
                            }
                            return Exit::PairStopped;
                        }
                        // A fault of this node's bytes (1003, 1009) ends the
                        // sessions of this socket, not the node: a server
                        // that only this node reaches must not be locked out
                        // by one frame, and the layer resumes its sessions on
                        // the next socket (T-409). The line says so.
                        Next::Exit(_) => Next::Reconnect,
                        next => next,
                    },
                }
            }
            Err(
                ConnectError::Config(why)
                | ConnectError::Dial(DialError::BadProxy(why) | DialError::InvalidTarget(why)),
            ) => return Exit::Unusable(why),
            Err(ConnectError::Refused { status: 409, .. }) => {
                let (left, why) = match lost {
                    Some(at) => (config.settings.rejoin.saturating_sub(at.elapsed()), "the node's lost socket"),
                    None => {
                        let since = *first_conflict.get_or_insert_with(Instant::now);
                        (
                            config.settings.first_conflict.saturating_sub(since.elapsed()),
                            "another node's socket, or the socket of the node that ran before this one",
                        )
                    }
                };
                if left.is_zero() {
                    return Exit::NameInUse;
                }
                if let Some(say) = config.say {
                    say(format!("the relay still holds {why} (409); connecting again, for {} s more", left.as_secs()));
                }
                Next::Reconnect
            }
            Err(ConnectError::Refused { status: 403, .. }) if expired(&config.pair) => Next::Repair,
            Err(ConnectError::Refused { status: 403, .. }) => return Exit::Forbidden,
            Err(_) => Next::Reconnect,
        };
        match next {
            Next::Repair => {
                let Some(hook) = config.repair.clone() else { return Exit::PairExpired };
                let Some(pair) = hook().await else { return Exit::PairExpired };
                config.pair = pair;
            }
            Next::Reconnect => {
                // The first try after a socket that served goes at once: its
                // sessions wait on the layer meanwhile (T-255, T-421).
                let now = Instant::now();
                if again_at_once(ended.is_some(), at_once, now) {
                    at_once = Some(now);
                    if let (Some(say), Some(ended)) = (config.say, &ended) {
                        say(format!("{ended}; connecting again at once"));
                    }
                    continue;
                }
                retry = retry.saturating_add(1);
                let wait = crate::open::backoff(retry);
                if let (Some(say), Some(ended)) = (config.say, &ended) {
                    say(format!("{ended}; connecting again in {:.1} s", wait.as_secs_f64()));
                }
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = &mut stop => return Exit::Stopped,
                }
            }
            Next::Exit(_) => return Exit::Forbidden,
        }
    }
}

fn expired(pair: &Pair) -> bool {
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    pair.expires_ms <= now
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_ws::SessionError;

    fn closed(code: u16, reason: &str) -> End {
        End::Closed(RelayClose { code, reason: reason.into(), clean: true })
    }

    #[test]
    fn a_socket_that_served_is_taken_again_at_once_once_each_10_s() {
        let now = Instant::now();
        assert!(again_at_once(true, None, now), "the first time after a socket that served");
        assert!(!again_at_once(false, None, now), "a try that never had a socket backs off");
        assert!(!again_at_once(true, Some(now), now + Duration::from_secs(3)), "twice within 10 s");
        assert!(again_at_once(true, Some(now), now + AT_ONCE_EVERY), "10 s after the last time");
    }

    #[test]
    fn the_words_of_an_end_name_a_restart_a_fault_a_close_and_a_drop() {
        assert_eq!(
            ended_words(&closed(1012, "relay restarting")).as_deref(),
            Some("the relay is restarting (relay close 1012: relay restarting)")
        );
        assert_eq!(
            ended_words(&closed(1003, "unknown session id")).as_deref(),
            Some("the relay closed the node for a fault of this node: 1003 unknown session id")
        );
        assert_eq!(
            ended_words(&closed(1011, "")).as_deref(),
            Some("the relay closed the node's socket (relay close 1011: no reason)")
        );
        let dropped = ended_words(&End::Failed(SessionError::ClosedWithoutClose("the peer went".into())));
        let words = dropped.as_deref().unwrap_or_default();
        assert!(words.starts_with("the link to the relay ended with no Close ("), "{words}");
        assert_eq!(ended_words(&End::Stopped), None, "a stop of the caller's is said by the caller");
    }
}
