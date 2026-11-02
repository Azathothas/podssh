//! The client of the road: a link to the node of a pair, by a hello at the
//! node's door. The hello is a whole POST, which ends once the node's GET
//! took it, so a node that is not there is told within [`DOOR_LIMIT`]; a
//! door that another client holds for a moment is knocked at again. A link
//! is streamed until a streamed one does not flow; from then on, this
//! client's links are numbered. The end-to-end channel above the layer
//! checks the node's identity, as the paths prove only the pair's secret.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite};

use super::dial::Proto;
use super::exchange::{delivered, Http};
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

/// The links of one client to the node of one pair.
pub struct Dialer {
    secret: Arc<Secret>,
    http: Arc<Http>,
    say: Say,
    /// A streamed link did not flow: the links are numbered.
    numbered: AtomicBool,
}

impl Dialer {
    pub fn new(secret: Secret, http: Http, say: Say) -> Dialer {
        Dialer { secret: Arc::new(secret), http: Arc::new(http), say, numbered: AtomicBool::new(false) }
    }

    pub fn server(&self) -> &Server {
        self.http.server()
    }

    /// The protocol of the last connection to the server, once one was made.
    pub fn proto(&self) -> Option<Proto> {
        self.http.proto()
    }

    /// Whether this client's links are numbered.
    pub fn numbered(&self) -> bool {
        self.numbered.load(Ordering::SeqCst)
    }

    /// A new link to the node, whose mark came; else why none.
    pub async fn link(&self) -> Result<Link, String> {
        if !self.numbered() {
            match self.open(Mode::Streamed).await {
                Ok(link) => return Ok(link),
                Err(Opening::Held(why)) => {
                    (self.say)(format!("{why}; this client's links go in numbered pieces from now on"));
                    self.numbered.store(true, Ordering::SeqCst);
                }
                Err(Opening::Failed(why)) => return Err(why),
            }
        }
        self.open(Mode::Numbered).await.map_err(|opening| opening.to_string())
    }

    async fn open(&self, mode: Mode) -> Result<Link, Opening> {
        let id = LinkId::random(&mut OsEntropy).map_err(|e| Opening::Failed(e.to_string()))?;
        self.knock(mode, &id).await.map_err(Opening::Failed)?;
        let ends = Ends::client(&self.secret, &id);
        match mode {
            Mode::Streamed => flow::streamed(self.http.clone(), &ends).await,
            Mode::Numbered => numbered::open(self.http.clone(), &ends).await,
        }
    }

    /// The hello of link `id` at the node's door, taken by the node.
    async fn knock(&self, mode: Mode, id: &LinkId) -> Result<(), String> {
        let door = self.http.server().path(&self.secret.door());
        let hello = self.secret.hello(mode, id);
        let mut last = String::new();
        for knock in 1..=KNOCKS {
            match self.http.post(&door, hello.as_bytes(), DOOR_LIMIT).await {
                // piping-server-rust 0.18.0 says "halfway disconnected" to a
                // sender whose receiver took the whole body and closed: for a
                // hello of a few bytes that is a delivery, and a hello that
                // did not arrive whole opens no link, which the layer retries;
                // the node opens a link's id once, however often it comes.
                Ok(text) if text.contains("halfway") && !text.contains("[ERROR]") => return Ok(()),
                Ok(text) => match delivered(&text) {
                    Ok(()) => return Ok(()),
                    // The node's GET went away as the hello came: it asks again.
                    Err(why) => last = why,
                },
                Err(failed) if failed.waited => {
                    return Err(format!(
                        "no node took the hello at {} within {} s: the node is offline, or serves no Piping Server \
                         road",
                        self.http.server(),
                        DOOR_LIMIT.as_secs()
                    ))
                }
                // Another client's hello holds the door for a moment.
                Err(failed) if failed.again() => last = failed.to_string(),
                Err(failed) => return Err(format!("{}: {failed}", self.http.server())),
            }
            if knock < KNOCKS {
                let pause = rand::rng().random_range(100..600u64) * u64::from(knock);
                tokio::time::sleep(Duration::from_millis(pause)).await;
            }
        }
        Err(format!("the door at {} stayed busy: {last}", self.http.server()))
    }

    /// End the connections to the server.
    pub async fn close(&self) {
        self.http.close().await;
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
