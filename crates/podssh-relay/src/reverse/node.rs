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

/// What a node does with each session that the relay opens: a byte stream to
/// carry, or a reason to refuse it. The node carries bytes only; what they
/// mean is the handler's (`docs/architecture.md`).
pub trait Handler: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    fn open(&self, id: SessionId) -> Opening<Self::Stream>;

    /// The bytes that may wait for a session's local side before the node
    /// takes it for stalled and ends the session. A handler with its own
    /// flow control holds its window, so that a slow local side is not
    /// taken for a stopped one.
    fn queue_bytes(&self) -> usize {
        QUEUE_BYTES
    }
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
    /// that the pair was stopped.
    pub label: Option<String>,
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// Bound on connecting.
    pub timeout: Duration,
    pub settings: Settings,
    /// Off by default: an expired pair ends the node.
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
    /// `1003` or `1009`: a fault of this node that a reconnection would repeat.
    Fault(RelayClose),
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

/// Run the node until it ends; reconnect after a broken socket, with the
/// jittered backoff of the forward opener. `config.pair` is then the pair that
/// the node ended with: a new one after a re-pair.
///
/// A `409` at the first registration means that another node has the name,
/// and the node exits. After a loss it means that the relay still holds the
/// old socket: the node connects again until `Settings::rejoin` after the
/// loss, as the sessions that the resumable layer keeps wait that long
/// (T-261; rule 6 of `docs/reverse.md`).
pub async fn run<H, F>(config: &mut NodeConfig<'_>, handler: Arc<H>, stop: F) -> Exit
where
    H: Handler,
    F: Future<Output = ()>,
{
    let mut stop = Box::pin(stop);
    let mut retry: u32 = 0;
    // When the node last lost a socket that it held.
    let mut lost: Option<Instant> = None;
    loop {
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
                };
                lost = Some(Instant::now());
                match end {
                    End::Stopped => return Exit::Stopped,
                    End::Failed(_) => Next::Reconnect,
                    End::Closed(close) => match after_close(&close) {
                        Next::Exit("stopped") => {
                            if let Some(label) = &config.label {
                                let _ = crate::pair::remove(label);
                            }
                            return Exit::PairStopped;
                        }
                        Next::Exit(_) => return Exit::Fault(close),
                        next => next,
                    },
                }
            }
            Err(
                ConnectError::Config(why)
                | ConnectError::Dial(DialError::BadProxy(why) | DialError::InvalidTarget(why)),
            ) => return Exit::Unusable(why),
            Err(ConnectError::Refused { status: 409, .. }) => {
                let left = lost.map(|at| config.settings.rejoin.saturating_sub(at.elapsed()));
                match left {
                    Some(left) if !left.is_zero() => {
                        if let Some(say) = config.say {
                            say(format!(
                                "the relay still holds the node's lost socket (409); connecting again, for {} s more",
                                left.as_secs()
                            ));
                        }
                        Next::Reconnect
                    }
                    _ => return Exit::NameInUse,
                }
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
                retry = retry.saturating_add(1);
                tokio::select! {
                    () = tokio::time::sleep(crate::open::backoff(retry)) => {}
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
