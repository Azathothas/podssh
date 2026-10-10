//! A synchronous facade over this crate, for a caller with no async runtime
//! (podbox, T-081; `docs/design.md`, section 3). A [`Client`] owns one tokio
//! runtime on the current thread and blocks on it in each call; no tokio type
//! is in this API.
//!
//! - [`Client::pair`], [`Client::status`] and [`Client::stop`]: the pairs of
//!   the reverse road;
//! - [`Client::run_node`]: a node, whose sessions a [`BlockingHandler`] opens
//!   as a reader and a writer ([`Local`]);
//! - [`Client::run_operator`]: one operator session over a reader and a
//!   writer, such as standard input and output;
//! - [`Client::open_forward`]: a forward session, as a [`Forward`] stream.
//!
//! A node's and an operator's sessions run the end-to-end channel of T-088
//! by default, as podssh's own ends do ([`NodeChannel`], [`OperatorChannel`]).
//!
//! No call runs on a thread that runs a tokio runtime (an async task, or
//! `spawn_blocking`): blocking there would stall that runtime, so the call
//! returns [`Error::InsideRuntime`], and nothing panics. Use the async
//! functions of this crate there.

mod bridge;
mod channel;
mod forward;

pub use bridge::{BlockingHandler, Local};
pub use channel::{NodeChannel, OperatorChannel};
pub use forward::{Closed, Forward};

use std::future::Future;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::client::ConnectError;
use podssh_ws::{ProxyChoice, Trust};
use tokio::runtime::Runtime;
use tokio::sync::Notify;

use crate::open::{Failure, Request};
use crate::pair::{self, Pair, PairContext, PairError, Presence, Stopped};
use crate::relay::{forward_path, Relay, RelayList};
use crate::reverse::{self, Exit, NodeConfig, OperatorConfig, OperatorLimits, Outcome, RepairHook, Settings, Wire};

/// The bound on each connection when the caller sets none.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// What a [`Client`] connects with.
#[derive(Debug, Clone)]
pub struct Config {
    /// podssh's own roots and TLS provider by default; `Trust::caller` takes
    /// the caller's rustls configuration (T-066).
    pub trust: Trust,
    /// `HTTPS_PROXY` and `NO_PROXY` from the environment by default.
    pub proxy: ProxyChoice,
    /// Bound on each connection: the dial, the proxy, TLS and the upgrade.
    pub timeout: Duration,
    /// TLS, except in the tests of an embedder.
    pub wire: Wire,
}

impl Default for Config {
    fn default() -> Self {
        Config { trust: Trust::Default, proxy: ProxyChoice::FromEnvironment, timeout: DEFAULT_TIMEOUT, wire: Wire::Tls }
    }
}

/// Why a call failed. No variant holds a token.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The call came from a thread that runs a tokio runtime, where blocking
    /// would stall it.
    InsideRuntime,
    /// The runtime, or a thread for a session, could not start.
    Start(String),
    /// A target that the relay cannot take as a host and a port.
    BadTarget(String),
    /// A pair could not be made, asked about or stopped.
    Pair(PairError),
    /// The socket of an operator could not open.
    Connect(ConnectError),
    /// No relay host opened the forward session to `target`: each attempt,
    /// in order.
    Open { target: String, failure: Failure },
    /// The key of the end-to-end channel could not be read or made.
    Key(String),
    /// The end-to-end channel failed: a refused key, a changed node key, a
    /// message that failed its check (T-088).
    Channel(crate::e2e::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InsideRuntime => write!(
                f,
                "a blocking call of podssh-relay came from a thread that runs a tokio runtime; use the async functions there"
            ),
            Error::Start(why) | Error::BadTarget(why) => write!(f, "{why}"),
            Error::Pair(e) => write!(f, "{e}"),
            Error::Connect(e) => write!(f, "{e}"),
            Error::Open { target, failure } => write!(f, "{}", failure.lines(target).join("; ")),
            Error::Key(why) => write!(f, "the end-to-end channel's key: {why}"),
            Error::Channel(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Stops a node from another thread: a signal handler, a supervisor. A stop
/// that comes before the node runs stops it as it starts.
#[derive(Debug, Clone, Default)]
pub struct Stopper(Arc<StopState>);

#[derive(Debug, Default)]
struct StopState {
    stopped: AtomicBool,
    notify: Notify,
}

impl Stopper {
    pub fn new() -> Stopper {
        Stopper::default()
    }

    /// Stop the node: each session gets `close`, and the socket a Close 1000.
    pub fn stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn is_stopped(&self) -> bool {
        self.0.stopped.load(Ordering::SeqCst)
    }

    async fn stopped(&self) {
        loop {
            // Registered before the flag is read, so no stop is missed.
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_stopped() {
                return;
            }
            notified.await;
        }
    }
}

/// How a node runs, beyond its pair and its handler.
#[derive(Clone, Default)]
pub struct NodeOptions {
    /// The label that the pair is stored under, deleted when the relay says
    /// that the pair was stopped.
    pub label: Option<String>,
    pub settings: Settings,
    /// Asked, on a thread of its own, when the pair expires: a new pair to go
    /// on with, or `None` to end the node. It may call the client
    /// ([`Client::pair`]).
    pub repair: Option<Arc<dyn Fn() -> Option<Pair> + Send + Sync>>,
    /// The end-to-end channel of each session; on by default.
    pub channel: NodeChannel,
}

impl std::fmt::Debug for NodeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeOptions")
            .field("label", &self.label)
            .field("settings", &self.settings)
            .field("repair", &self.repair.is_some())
            .field("channel", &self.channel)
            .finish()
    }
}

/// Where an operator session goes: a node's name on a relay, with the pair's
/// connect token.
#[derive(Clone)]
pub struct Operator<'a> {
    pub relay: &'a Relay,
    pub name: &'a str,
    pub connect_token: &'a str,
    pub limits: OperatorLimits,
    /// The end-to-end channel of the session; on by default.
    pub channel: OperatorChannel,
}

impl<'a> Operator<'a> {
    pub fn new(relay: &'a Relay, name: &'a str, connect_token: &'a str) -> Operator<'a> {
        Operator { relay, name, connect_token, limits: OperatorLimits::default(), channel: OperatorChannel::default() }
    }

    /// The same, with this channel.
    pub fn with_channel(mut self, channel: OperatorChannel) -> Operator<'a> {
        self.channel = channel;
        self
    }

    /// The operator's side of `pair`.
    pub fn of(pair: &'a Pair) -> Operator<'a> {
        Operator::new(&pair.relay, &pair.name, pair.connect_token())
    }
}

impl std::fmt::Debug for Operator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operator")
            .field("relay", self.relay)
            .field("name", &self.name)
            .field("connect_token", &"<redacted>")
            .field("limits", &self.limits)
            .field("channel", &self.channel)
            .finish()
    }
}

/// A blocking client of the relay. Several threads may call one client at
/// once: they share its runtime.
pub struct Client {
    /// `Some` until the drop.
    runtime: Option<Runtime>,
    config: Config,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Client {
    /// A client with its own runtime. It may be made, and dropped, anywhere;
    /// its calls refuse to run inside a tokio runtime.
    pub fn new(config: Config) -> Result<Client, Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Start(format!("the async runtime could not start: {e}")))?;
        Ok(Client { runtime: Some(runtime), config })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn runtime(&self) -> Result<&Runtime, Error> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Error::InsideRuntime);
        }
        self.runtime.as_ref().ok_or_else(|| Error::Start("the client's runtime has ended".into()))
    }

    /// Block on `future`, unless this thread runs a tokio runtime, where
    /// `Runtime::block_on` would panic.
    fn block_on<F: Future>(&self, future: F) -> Result<F::Output, Error> {
        Ok(self.runtime()?.block_on(future))
    }

    fn pair_context<'a>(&'a self, relay: &'a Relay) -> PairContext<'a> {
        PairContext { relay, trust: &self.config.trust, proxy: &self.config.proxy, timeout: self.config.timeout }
    }

    /// A new pair, from `relay`'s control host (`POST /v1/pair`).
    pub fn pair(&self, relay: &Relay) -> Result<Pair, Error> {
        self.block_on(pair::create(&self.pair_context(relay)))?.map_err(Error::Pair)
    }

    /// Whether `pair`'s node is online, and its sessions.
    pub fn status(&self, pair: &Pair) -> Result<Presence, Error> {
        self.block_on(pair::status(&self.pair_context(&pair.relay), pair))?.map_err(Error::Pair)
    }

    /// End `pair` on the relay; its tokens end whatever the answer.
    pub fn stop(&self, pair: &Pair) -> Result<Stopped, Error> {
        self.block_on(pair::stop(&self.pair_context(&pair.relay), pair))?.map_err(Error::Pair)
    }

    /// Run a node for `pair` until `stopper` stops it or the relay ends it for
    /// good; then `pair` is the pair that it ended with (a new one after a
    /// re-pair). The handler opens each session on a thread of its own, and
    /// two threads carry it: one reads its reader, one writes its writer. A
    /// node has at most 64 sessions (the relay's `maxSessions`), so at most
    /// 128 such threads.
    pub fn run_node<H: BlockingHandler>(
        &self,
        pair: &mut Pair,
        handler: H,
        options: &NodeOptions,
        stopper: &Stopper,
    ) -> Result<Exit, Error> {
        let runtime = self.runtime()?;
        let mut config = NodeConfig {
            pair: pair.duplicate(),
            label: options.label.clone(),
            trust: &self.config.trust,
            proxy: &self.config.proxy,
            timeout: self.config.timeout,
            settings: options.settings,
            repair: options.repair.clone().map(blocking_repair),
            wire: self.config.wire,
            say: None,
        };
        let channel = options.channel.end(options.label.as_deref(), &pair.name).map_err(Error::Key)?;
        let handler = bridge::Bridged(Arc::new(handler));
        let exit = match channel {
            Some(node) => {
                let handler = Arc::new(reverse::E2e::new(handler, node));
                runtime.block_on(reverse::run(&mut config, handler, stopper.stopped()))
            }
            None => runtime.block_on(reverse::run(&mut config, Arc::new(handler), stopper.stopped())),
        };
        *pair = config.pair;
        Ok(exit)
    }

    /// One operator session to `to`: what `reader` gives goes to the node's
    /// local side, and what comes back goes to `writer`, flushed, before the
    /// outcome is returned. Up to 1 MiB of input is kept until the node is
    /// ready; the session ends at the end of `reader`. The thread that reads
    /// `reader` may outlive the call: it ends when `reader` ends, or when the
    /// client is dropped.
    pub fn run_operator<R, W>(&self, to: &Operator<'_>, reader: R, writer: W) -> Result<Outcome, Error>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let runtime = self.runtime()?;
        let bridged = bridge::bridge(Local::new(reader, writer), runtime.handle().clone()).map_err(Error::Start)?;
        let config = OperatorConfig {
            relay: to.relay,
            name: to.name,
            connect_token: to.connect_token,
            trust: &self.config.trust,
            proxy: &self.config.proxy,
            timeout: self.config.timeout,
            limits: to.limits,
            wire: self.config.wire,
        };
        let outcome = match to.channel.end(to.name).map_err(Error::Key)? {
            Some((identity, check)) => {
                let (cipher, session) = crate::e2e::ends::operator(bridged.stream, identity, check);
                let (outcome, ended) =
                    runtime.block_on(async { tokio::join!(reverse::operator::run(&config, cipher), session) });
                // A cut, or a failed stream, is the leg's to tell.
                if let Err(e) = ended {
                    if !matches!(e, crate::e2e::Error::Cut | crate::e2e::Error::Io(_)) {
                        bridged.output_done.wait(to.limits.close_limit);
                        return Err(Error::Channel(e));
                    }
                }
                outcome
            }
            None => runtime.block_on(reverse::operator::run(&config, bridged.stream)),
        };
        bridged.output_done.wait(to.limits.close_limit);
        outcome.map_err(Error::Connect)
    }

    /// A forward session to `host:port`, failing over across `relays`, as
    /// `podssh ssh` opens one: the token comes from the environment, the cache
    /// or a mint, and the proxy from the environment. It is TLS whatever
    /// `Config::wire` says; the plain form for tests is `forward_on_loopback`.
    pub fn open_forward(&self, relays: &RelayList, host: &str, port: u16) -> Result<Forward<'_>, Error> {
        let path = forward_path(host, port).map_err(Error::BadTarget)?;
        let target = podssh_ws::dial::authority(host, port);
        let request = Request { relays, path: &path, trust: &self.config.trust, target: &target, rounds: 1 };
        let mut notes = Vec::new();
        let opened = self.block_on(crate::open::open(&request, &mut |note: &str| notes.push(note.to_string())))?;
        let opened = opened.map_err(|failure| Error::Open { target, failure })?;
        Ok(Forward::new(self, reverse::wire::Socket::Tls(opened.session), opened.relay, notes))
    }

    /// A forward session through a stand-in relay on the loopback, over plain
    /// `ws://` with `token`, for the tests of an embedder: no failover, and no
    /// token of the cache.
    #[cfg(feature = "plain-ws")]
    pub fn forward_on_loopback(&self, relay: &Relay, host: &str, port: u16, token: &str) -> Result<Forward<'_>, Error> {
        use podssh_ws::client::{Endpoint, WsClientConfig};
        let path = forward_path(host, port).map_err(Error::BadTarget)?;
        let config = WsClientConfig {
            endpoint: Endpoint { host: relay.host.clone(), port: relay.port, path },
            trust: self.config.trust.clone(),
            server_name: relay.host.clone(),
            timeout: self.config.timeout,
            idle_timeout: Some(podssh_ws::client::DEFAULT_IDLE_TIMEOUT),
            proxy: ProxyChoice::Direct,
        };
        let socket =
            self.block_on(reverse::wire::open(Wire::PlainLoopback, &config, token))?.map_err(Error::Connect)?;
        Ok(Forward::new(self, socket, relay.clone(), Vec::new()))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // With no wait: a thread may still block on a reader; and this does
        // not panic inside an async context, as a plain drop would.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// A blocking re-pair hook as the node's async one: it runs on a thread of
/// its own, with no runtime, so it may call the client.
fn blocking_repair(hook: Arc<dyn Fn() -> Option<Pair> + Send + Sync>) -> RepairHook {
    Arc::new(move || {
        let hook = hook.clone();
        Box::pin(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let spawned = std::thread::Builder::new().name("podssh-relay repair".into()).spawn(move || {
                let _ = tx.send(hook());
            });
            match spawned {
                Ok(_) => rx.await.ok().flatten(),
                Err(_) => None,
            }
        })
    })
}
