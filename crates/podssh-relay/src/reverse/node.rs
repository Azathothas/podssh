//! The node of a pair: one WebSocket to `/v1/node/<name>`, kept up, and the
//! actions for each way it can end (`docs/reverse.md`, "Node").

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_transport::closes::RelayClose;
use podssh_transport::{LegTarget, SessionId};
use podssh_ws::client::{connect, ConnectError, Endpoint, WsClientConfig};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};

use super::serve::{serve, End, Settings};
use crate::pair::Pair;

/// The local side of a session, as a handler opens it.
pub type Opening<S> = Pin<Box<dyn Future<Output = Result<S, String>> + Send>>;

/// What a node does with each session that the relay opens: a byte stream to
/// carry, or a reason to refuse it. The node carries bytes only; what they
/// mean is the handler's (`docs/architecture.md`).
pub trait Handler: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    fn open(&self, id: SessionId) -> Opening<Self::Stream>;
}

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
}

/// Why a node ended. Each is final: a failure that a reconnection repairs is
/// handled inside [`run`].
#[derive(Debug)]
pub enum Exit {
    /// The caller stopped it: each session got `close`, the socket a Close 1000.
    Stopped,
    /// `409`: another node holds the name. Not retried.
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
}

/// What to do after a socket ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    Reconnect,
    Repair,
    Exit(&'static str),
}

/// The action for a Close of the relay (`docs/reverse.md`, "Operator", 3):
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
/// jittered backoff of the forward opener.
pub async fn run<H, F>(mut config: NodeConfig<'_>, handler: Arc<H>, stop: F) -> Exit
where
    H: Handler,
    F: Future<Output = ()>,
{
    let mut stop = Box::pin(stop);
    let mut retry: u32 = 0;
    loop {
        let path = match (LegTarget::ReverseNode { name: config.pair.name.clone() }).path() {
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
            connected = connect(&ws, config.pair.node_token()) => connected,
            () = &mut stop => return Exit::Stopped,
        };
        let next = match connected {
            Ok(session) => {
                retry = 0;
                match serve(session, handler.clone(), config.settings, &mut stop).await {
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
            Err(ConnectError::Refused { status: 409, .. }) => return Exit::NameInUse,
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    pair.expires_ms <= now
}
