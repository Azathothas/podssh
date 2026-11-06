//! A carrier (T-595): the node's socket of the reverse road on a byte stream
//! that exists already, such as the client's stdio, a descriptor, or a
//! program that the client started (an exec channel of a platform's own
//! SSH, for a host whose every road out is closed). The stream carries the
//! socket's WebSocket frames with no HTTP before them. The client's end runs
//! the relay role's side of that socket in its own process, for this one
//! node, and each operator's leg is a pipe in the process to it ([`Door`],
//! a wire of the leg); so the node, the layer, the end-to-end channel and
//! the routes are the pair's road's, and no protocol is new.
//!
//! No relay, no pair and no token: the stream is the door, as whoever holds
//! it reached the node through what carries it. The relay's limits (64 MiB a
//! session, a pair's 72 h) do not hold; the layer's and the stream's do.
//! The role speaks first (`hello`), as the relay does; the node's first
//! frame, a Ping ([`greet`]), says that it reads, and only then does a leg
//! open, so that a node that is slow to start meets no `1013` of the role.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use podssh_ws::client::{ConnectError, WRITE_TIMEOUT};
use podssh_ws::dial::DialError;
use podssh_ws::server;
use podssh_ws::session::RelaySession;
use podssh_ws::SessionError;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::pairs::{Pair, Pairs};
use super::{node, operator};
use crate::serve::{tokens::Tokens, Config, Events, Limits, Mint};

/// The name of the carrier's one pair, in the path of each leg.
pub const NAME: &str = "carrier";
/// Each direction of the pipe of an operator's leg.
const LEG_PIPE: usize = 256 * 1024;
/// How often a wait for the node looks again.
const LOOK: Duration = Duration::from_millis(20);
/// The payload of the node's first Ping.
const GREETING: &[u8] = b"podssh carrier";

/// A byte stream that carries the node's socket.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// The stream, as the role holds it.
pub type Link = Box<dyn Stream>;

/// Starts the stream again, for the end that started it (`exec:`): the new
/// link of a resume. An end that was given its stream has none.
pub type Again = Box<dyn Fn() -> Result<Link, String> + Send + Sync>;

/// The role's side of the stream that carries the node's socket now, and the
/// task that serves it.
type Held = Option<(Arc<RelaySession<Link>>, JoinHandle<()>)>;

/// The relay role's side of one node's socket, in the client's process.
pub struct Role {
    cfg: Arc<Config>,
    pair: Arc<Pair>,
    again: Option<Again>,
    link: Mutex<Held>,
    /// The stream in the words of the user, for the lines: `exec:CMD`.
    shown: String,
}

impl Role {
    /// A role with no node yet; `shown` names the stream, `again` starts it
    /// anew, and `events` hears each step as the role says it.
    pub fn new(shown: &str, again: Option<Again>, events: Option<Events>) -> Result<Role, String> {
        let cfg = Config {
            version: format!("carrier {}", env!("CARGO_PKG_VERSION")),
            // No request reaches this role: it mints nothing.
            mint: Mint::Nobody,
            tokens: Tokens::random()?,
            policy: Default::default(),
            egress: Default::default(),
            limits: Limits::default(),
            pairs: Pairs::default(),
            resumes: Default::default(),
            answered: Default::default(),
            brake: Default::default(),
            usage: Default::default(),
            events,
        };
        let pair = Arc::new(Pair::carried(NAME));
        Ok(Role { cfg: Arc::new(cfg), pair, again, link: Mutex::new(None), shown: shown.to_string() })
    }

    /// Serve the node's socket on `link`, the stream's first. Inside a tokio
    /// runtime.
    pub fn attach(&self, link: Link) -> Result<(), String> {
        let mut held = lock(&self.link);
        self.attach_held(&mut held, link)
    }

    fn attach_held(&self, held: &mut Held, link: Link) -> Result<(), String> {
        let session = Arc::new(server::session(link, Vec::new(), None).naming("the carrier's node"));
        let task = node::carried(session.clone(), self.pair.clone(), self.cfg.clone())?;
        *held = Some((session, task));
        Ok(())
    }

    /// An operator's leg at `path`, once the node reads the stream, within
    /// `limit`: the near end of a pipe whose far end the role carries, as
    /// it carries an operator's socket.
    pub async fn open(&self, path: &str, limit: Duration) -> Result<RelaySession<DuplexStream>, ConnectError> {
        let ours = crate::relay::operator_path(NAME).map_err(ConnectError::Config)?;
        if path != ours {
            return Err(ConnectError::Config(format!("{path}: a carrier's role takes its operators' legs alone")));
        }
        self.ready(limit).await?;
        let (near, far) = tokio::io::duplex(LEG_PIPE);
        tokio::spawn(operator::leg(
            Arc::new(server::session(far, Vec::new(), None)),
            self.pair.clone(),
            self.cfg.clone(),
        ));
        Ok(RelaySession::new(near, Vec::new(), None, WRITE_TIMEOUT).naming("the carrier"))
    }

    /// Until the node's socket is up and the node spoke on it; a stream that
    /// ended is started again by the end that started it, once for each
    /// wait, so that a program that ends at once is not started in a loop:
    /// the layer's own wait comes between two legs.
    async fn ready(&self, limit: Duration) -> Result<(), ConnectError> {
        let deadline = Instant::now() + limit;
        let mut started = false;
        loop {
            match self.up() {
                (true, true) => return Ok(()),
                (false, _) if started => {
                    let (target, detail) = (format!("the carrier {}", self.shown), "it ended before a node read it");
                    return Err(ConnectError::Dial(DialError::Connect {
                        target,
                        detail: detail.into(),
                        cut: None,
                        kind: None,
                    }));
                }
                (false, _) => {
                    self.start_again()?;
                    started = true;
                }
                (true, false) => {}
            }
            if Instant::now() >= deadline {
                return Err(ConnectError::Timeout { step: "the carrier's node, to read the stream,", after: limit });
            }
            tokio::time::sleep(LOOK).await;
        }
    }

    /// Whether a node's socket is joined now: false once its stream ended
    /// and none took its place, so that a client of a stream with one life
    /// can end with it (T-596).
    pub fn joined(&self) -> bool {
        self.up().0
    }

    /// Whether a node's socket is joined, and whether its node spoke.
    fn up(&self) -> (bool, bool) {
        let joined = self.pair.lock().node_outbox().is_some();
        let spoke = lock(&self.link).as_ref().is_some_and(|(session, _)| session.frames_received() > 0);
        (joined, spoke)
    }

    /// A new stream in place of one that ended. A stream that this end was
    /// given has one life: the end is final (410), as a new leg would meet it
    /// again.
    fn start_again(&self) -> Result<(), ConnectError> {
        let mut held = lock(&self.link);
        // Another leg started it meanwhile.
        if self.pair.lock().node_outbox().is_some() {
            return Ok(());
        }
        let Some(again) = &self.again else {
            let body =
                format!("the carrier {} ended, and a stream that this end did not start has one life", self.shown);
            return Err(ConnectError::Refused { status: 410, body });
        };
        let target = format!("the carrier {}", self.shown);
        let link = again()
            .map_err(|detail| ConnectError::Dial(DialError::Connect { target, detail, cut: None, kind: None }))?;
        self.attach_held(&mut held, link).map_err(ConnectError::Config)
    }

    /// The end of the client: the node hears a Close 1000 after what waits
    /// for it, and the Close is waited for `limit` at most, so that the node
    /// exits 0.
    pub async fn close(&self, limit: Duration) {
        let node = self.pair.lock().node_outbox();
        if let Some(node) = node {
            node.close(1000, "the carrier's client ended");
            let _ = tokio::time::timeout(limit, node.ended()).await;
        }
    }
}

/// A carrier's role as the wire of an operator's leg
/// ([`crate::reverse::Wire::Carrier`]): `Copy`, as each wire is, so the role
/// lives as long as the process, which runs one carrier.
#[derive(Clone, Copy)]
pub struct Door(&'static Role);

impl Door {
    pub fn of(role: Role) -> Door {
        Door(Box::leak(Box::new(role)))
    }

    pub fn role(self) -> &'static Role {
        self.0
    }
}

impl PartialEq for Door {
    fn eq(&self, other: &Door) -> bool {
        std::ptr::eq(self.0, other.0)
    }
}

impl Eq for Door {}

impl std::fmt::Debug for Door {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Door({})", self.0.shown)
    }
}

/// The node's end of a carrier: its socket on `stream`, the client's side of
/// the WebSocket as on the relay's socket, with no upgrade.
pub fn node_socket<S: AsyncRead + AsyncWrite>(stream: S) -> RelaySession<S> {
    RelaySession::new(stream, Vec::new(), None, WRITE_TIMEOUT).naming("the carrier")
}

/// The node's first frame: a Ping, which says that it reads the stream.
pub async fn greet<S: AsyncRead + AsyncWrite>(session: &RelaySession<S>) -> Result<(), SessionError> {
    session.send_ping(GREETING).await
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
