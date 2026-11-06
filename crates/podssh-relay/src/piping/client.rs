//! The client of the road: a link to the node of a pair, by a hello at the
//! node's door. The hello is a whole POST, which ends once the node's GET
//! took it, so a node that is not there is told within [`DOOR_LIMIT`]; a
//! door that another client holds for a moment is knocked at again. A link
//! is streamed until a streamed one does not flow; from then on, this
//! client's links are numbered. The end-to-end channel above the layer
//! checks the node's identity, as the paths prove only the pair's secret.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite};

use super::dial::Proto;
use super::exchange::{delivered_whole, Http};
use super::flow::{self, Link, Opening};
use super::numbered;
use super::paths::{Ends, LinkId, Mode, Secret};
use super::server::Server;
use super::Say;
use crate::session::client::{self, Outcome};
use crate::session::resume::{self, Next, Note};
use crate::session::{Ask, Ended, Hearing, OsEntropy, Settings};

/// How long a hello waits for the node at its door.
pub const DOOR_LIMIT: Duration = Duration::from_secs(20);
/// How many times a busy door is knocked at.
const KNOCKS: u32 = 6;

/// One server of a client: its HTTP client, and whether its links go in
/// numbered pieces.
struct Door {
    http: Arc<Http>,
    /// A streamed link did not flow, or pod-services says that the server
    /// holds a body to its end: the links are numbered.
    numbered: AtomicBool,
}

/// Why no link came through one server.
enum Missed {
    /// No node took the hello there, or the server failed: the node may
    /// wait at the next server.
    Elsewhere(String),
    /// The node is there, and its link failed, or its door stayed busy.
    Here(String),
}

/// The links of one client to the node of one pair, through the first of
/// its servers where the node waits (T-497).
pub struct Dialer {
    secret: Arc<Secret>,
    doors: Vec<Door>,
    /// The server where the node was met last: the next link tries it first.
    at: AtomicUsize,
    say: Say,
}

impl Dialer {
    pub fn new(secret: Secret, http: Http, say: Say) -> Dialer {
        Dialer::with_servers(secret, vec![http], say)
    }

    /// A dialer of each server of `https`, in their order: a server is tried
    /// once no node took the hello at the one before, never two at once.
    /// `https` holds one server at least.
    pub fn with_servers(secret: Secret, https: Vec<Http>, say: Say) -> Dialer {
        let doors = https
            .into_iter()
            .map(|http| Door { numbered: AtomicBool::new(http.server().holds_bodies()), http: Arc::new(http) })
            .collect();
        Dialer { secret: Arc::new(secret), doors, at: AtomicUsize::new(0), say }
    }

    fn door(&self) -> &Door {
        &self.doors[self.at.load(Ordering::SeqCst).min(self.doors.len() - 1)]
    }

    /// The server where the node was met last, or the first.
    pub fn server(&self) -> &Server {
        self.door().http.server()
    }

    /// The protocol of the last connection to that server, once one was made.
    pub fn proto(&self) -> Option<Proto> {
        self.door().http.proto()
    }

    /// Whether this client's links to that server are numbered.
    pub fn numbered(&self) -> bool {
        self.door().numbered.load(Ordering::SeqCst)
    }

    /// A new link to the node, whose mark came; else why none. The server
    /// where the node was met last is tried first, then each other in order.
    pub async fn link(&self) -> Result<Link, String> {
        let (count, first) = (self.doors.len(), self.at.load(Ordering::SeqCst));
        let mut missed = Vec::new();
        for step in 0..count {
            let at = (first + step) % count;
            match self.link_at(&self.doors[at]).await {
                Ok(link) => {
                    if at != first {
                        (self.say)(format!(
                            "the node waits at {}: this client's links go there",
                            self.doors[at].http.server()
                        ));
                        self.at.store(at, Ordering::SeqCst);
                    }
                    return Ok(link);
                }
                Err(Missed::Here(why)) => return Err(why),
                Err(Missed::Elsewhere(why)) => missed.push(why),
            }
        }
        Err(missed.join("; then "))
    }

    async fn link_at(&self, door: &Door) -> Result<Link, Missed> {
        if !door.numbered.load(Ordering::SeqCst) {
            let id = self.knock(door, Mode::Streamed).await?;
            match self.open(door, Mode::Streamed, &id).await {
                Ok(link) => return Ok(link),
                Err(Opening::Held(why)) => {
                    (self.say)(format!("{why}; this client's links go in numbered pieces from now on"));
                    door.numbered.store(true, Ordering::SeqCst);
                }
                Err(Opening::Failed(why)) => return Err(Missed::Here(why)),
            }
        }
        let id = self.knock(door, Mode::Numbered).await?;
        self.open(door, Mode::Numbered, &id).await.map_err(|opening| Missed::Here(opening.to_string()))
    }

    async fn open(&self, door: &Door, mode: Mode, id: &LinkId) -> Result<Link, Opening> {
        let ends = Ends::client(&self.secret, id);
        match mode {
            Mode::Streamed => flow::streamed(door.http.clone(), &ends).await,
            Mode::Numbered => numbered::open(door.http.clone(), &ends).await,
        }
    }

    /// The hello of a new link at the node's door of `door`, taken by the
    /// node: the link's id.
    async fn knock(&self, door: &Door, mode: Mode) -> Result<LinkId, Missed> {
        let id = LinkId::random(&mut OsEntropy).map_err(|e| Missed::Here(e.to_string()))?;
        let (http, path) = (&door.http, door.http.server().path(&self.secret.door()));
        let hello = self.secret.hello(mode, &id);
        let (mut last, mut busy) = (String::new(), false);
        for knock in 1..=KNOCKS {
            match http.post(&path, hello.as_bytes(), DOOR_LIMIT).await {
                // A hello that did not arrive whole opens no link, which the
                // layer retries; the node opens a link's id once, however
                // often it comes.
                Ok(text) => match delivered_whole(&text) {
                    Ok(()) => return Ok(id),
                    // The node's GET went away as the hello came: it asks again.
                    Err(why) => (last, busy) = (why, true),
                },
                Err(failed) if failed.waited => {
                    return Err(Missed::Elsewhere(format!(
                        "no node took the hello at {} within {} s: the node is offline, or serves no Piping Server \
                         road",
                        http.server(),
                        DOOR_LIMIT.as_secs()
                    )))
                }
                // Another client's hello holds the door for a moment (400),
                // or the way lost the connection: the same door again.
                Err(failed) if failed.again() => (last, busy) = (failed.to_string(), failed.status == Some(400)),
                // The server answered no Piping Server's page: the node
                // waits at another, or nowhere.
                Err(failed) => return Err(Missed::Elsewhere(format!("{}: {failed}", http.server()))),
            }
            if knock < KNOCKS {
                let pause = rand::rng().random_range(100..600u64) * u64::from(knock);
                tokio::time::sleep(Duration::from_millis(pause)).await;
            }
        }
        let how = if busy { "stayed busy" } else { "kept failing" };
        let why = format!("the door at {} {how}: {last}", http.server());
        // A door that a node's other client held: the node is here. A
        // server that kept failing: the node may wait at the next.
        Err(if busy { Missed::Here(why) } else { Missed::Elsewhere(why) })
    }
    /// End the connections to each server.
    pub async fn close(&self) {
        for door in &self.doors {
            door.http.close().await;
        }
    }
}

/// Carry `app` to the node of `dialer`: the first link and the layer's
/// handshake on it, then a new link after each lost one, until the session
/// ends. `note` hears each step of the session across links.
pub async fn carry<A, N>(dialer: &Dialer, app: A, settings: Settings, note: N) -> Result<Outcome, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    carry_heard(dialer, app, settings, note, Arc::default()).await
}

/// [`carry`], with the session's `hearing`, which a notice of the far end's
/// silence reads.
pub async fn carry_heard<A, N>(
    dialer: &Dialer,
    app: A,
    settings: Settings,
    note: N,
    hearing: Arc<Hearing>,
) -> Result<Outcome, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    let first = dialer.link().await?;
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await.map_err(|e| e.to_string())?;
    let client = client.with_hearing(hearing);
    let connect = |_: &Ended| async move {
        match dialer.link().await {
            Ok(link) => Next::Link(link),
            Err(why) => Next::Retry(why),
        }
    };
    // On the heap: the layer's future is larger than a small thread's stack
    // in a debug build.
    Ok(Box::pin(resume::run(client, app, connect, note, &mut OsEntropy)).await)
}
