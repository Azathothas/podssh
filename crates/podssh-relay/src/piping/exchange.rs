//! A Piping Server's client: the GETs and POSTs of the road, on [`dial`]'s
//! connections. Over HTTP/2 each request is a stream of one connection, kept
//! while it lives, so that a node's door and each of its links share it.
//! Over HTTP/1.1 a streamed request has a connection of its own for as long
//! as its way lasts, and a whole one takes a connection that an earlier one
//! left, kept a little less than Node's 5 s of keep-alive; a request on a
//! kept connection that the server closed meanwhile goes once more on a new
//! one, as nothing of it reached the server.
//!
//! [`dial`]: super::dial

use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use tokio::io::{AsyncRead, AsyncWriteExt, WriteHalf};
use tokio::task::AbortHandle;

use super::dial::{BoxIo, Dial, Proto};
use super::http1::{self, Length, Reader};
use super::http2;
use super::server::Server;

/// How long a connection of HTTP/1.1 waits for the next request.
const IDLE_FOR: Duration = Duration::from_secs(4);
/// The idle connections kept, at most.
const IDLE_MAX: usize = 2;
/// The most of a server's words read, for a line or a check.
const TEXT_CAP: usize = 16 * 1024;

/// Why a request failed: the server's status and words, or none when no
/// answer came; `waited` when none came within the request's wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub status: Option<u16>,
    pub why: String,
    pub waited: bool,
}

impl Failed {
    pub fn lost(why: impl Into<String>) -> Failed {
        Failed { status: None, why: why.into(), waited: false }
    }

    pub fn status(status: u16, text: String) -> Failed {
        Failed { status: Some(status), why: shown(&text), waited: false }
    }

    pub fn waited(wait: Duration) -> Failed {
        Failed { status: None, why: format!("no answer within {} s", wait.as_secs()), waited: true }
    }

    /// Whether the same request may work again soon: no answer came, a
    /// proxy's gateway failed, or the server refused a second sender or
    /// receiver on a path (400), which ends when the other one leaves.
    pub fn again(&self) -> bool {
        !self.waited && matches!(self.status, None | Some(400 | 502 | 503 | 504))
    }
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(status) if self.why.is_empty() => write!(f, "HTTP {status}"),
            Some(status) => write!(f, "HTTP {status}: {}", self.why),
            None => f.write_str(&self.why),
        }
    }
}

impl std::error::Error for Failed {}

/// Whether a sender's answer says that its receiver took the whole body. A
/// Piping Server says so in words: a receiver that went away halfway, or a
/// refusal, has its own.
pub fn delivered(text: &str) -> Result<(), String> {
    if ["[ERROR]", "aborted", "halfway"].iter().any(|word| text.contains(word)) {
        let last = text.lines().rev().find(|line| !line.trim().is_empty()).unwrap_or(text);
        return Err(format!("the server said: {}", shown(last)));
    }
    Ok(())
}

/// A server's words for a line: one line, 200 characters at most.
fn shown(text: &str) -> String {
    podssh_ws::text::one_line(text.trim()).chars().take(200).collect()
}

/// A body, read as it comes.
pub enum Body {
    H1(Reader<BoxIo>),
    H2(h2::RecvStream),
}

impl Body {
    /// Its next bytes; `None` at its end.
    pub async fn next(&mut self) -> Result<Option<Bytes>, String> {
        match self {
            Body::H1(reader) => Ok(reader.next().await?.map(Bytes::from)),
            Body::H2(body) => http2::next(body).await,
        }
    }
}

/// The body of a streamed POST, sent as it comes; the server's words are
/// read meanwhile, and dropped.
pub struct Upload {
    way: Way,
    drain: AbortHandle,
}

enum Way {
    H1(WriteHalf<BoxIo>),
    H2(h2::SendStream<Bytes>),
}

impl Upload {
    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        // An empty chunk would end the body.
        if bytes.is_empty() {
            return Ok(());
        }
        match &mut self.way {
            Way::H1(write) => {
                write.write_all(&http1::chunk(bytes)).await.map_err(|e| e.to_string())?;
                write.flush().await.map_err(|e| e.to_string())
            }
            Way::H2(stream) => http2::send_all(stream, bytes).await,
        }
    }

    /// The end of the body.
    pub async fn finish(&mut self) -> Result<(), String> {
        match &mut self.way {
            Way::H1(write) => {
                write.write_all(http1::LAST_CHUNK).await.map_err(|e| e.to_string())?;
                write.flush().await.map_err(|e| e.to_string())
            }
            Way::H2(stream) => stream.send_data(Bytes::new(), true).map_err(|e| e.to_string()),
        }
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        self.drain.abort();
    }
}

/// A connection of HTTP/1.1 between requests, with the bytes read past the
/// last answer.
struct Kept {
    io: BoxIo,
    buf: Vec<u8>,
}

/// The connection for one request.
enum Conn {
    H1 { kept: Kept, reused: bool },
    H2(SendRequest<Bytes>),
}

/// A failed request of HTTP/1.1, and whether it failed before any byte of its
/// answer: on a kept connection, the server closed it, and it may go again.
struct Tried {
    failed: Failed,
    stale: bool,
}

impl Tried {
    fn stale(e: std::io::Error) -> Tried {
        Tried { failed: Failed::lost(e.to_string()), stale: true }
    }

    fn other(failed: Failed) -> Tried {
        Tried { failed, stale: false }
    }
}

/// The client of one Piping Server.
pub struct Http {
    server: Server,
    dial: Dial,
    h2: tokio::sync::Mutex<Option<http2::Conn>>,
    idle: Mutex<Vec<(Instant, Kept)>>,
    proto: Mutex<Option<Proto>>,
}

impl Http {
    pub fn new(server: Server, dial: Dial) -> Http {
        Http { server, dial, h2: tokio::sync::Mutex::new(None), idle: Mutex::new(Vec::new()), proto: Mutex::new(None) }
    }

    pub fn server(&self) -> &Server {
        &self.server
    }

    /// The protocol of the last connection, once one was made.
    pub fn proto(&self) -> Option<Proto> {
        *lock(&self.proto)
    }

    /// The live connection of HTTP/2; else, with `reuse`, an idle one of
    /// HTTP/1.1; else a new one, of the protocol that the server took.
    async fn conn(&self, reuse: bool) -> Result<Conn, Failed> {
        let mut slot = self.h2.lock().await;
        if let Some(conn) = slot.as_ref().filter(|conn| conn.alive()) {
            return Ok(Conn::H2(conn.send.clone()));
        }
        *slot = None;
        if reuse {
            if let Some(kept) = self.take_idle() {
                return Ok(Conn::H1 { kept, reused: true });
            }
        } else {
            // A new connection for a streamed way ends each idle one first:
            // over HTTP/1.1 an end holds two connections at most, its two
            // ways, as the operator's ruling Q44 allows (T-437).
            lock(&self.idle).clear();
        }
        let (io, proto) = (self.dial)(&self.server).await.map_err(Failed::lost)?;
        *lock(&self.proto) = Some(proto);
        match proto {
            Proto::H2 => {
                let conn = http2::Conn::start(io).await.map_err(Failed::lost)?;
                let send = conn.send.clone();
                *slot = Some(conn);
                Ok(Conn::H2(send))
            }
            Proto::H1 => Ok(Conn::H1 { kept: Kept { io, buf: Vec::new() }, reused: false }),
        }
    }

    fn take_idle(&self) -> Option<Kept> {
        let mut idle = lock(&self.idle);
        while let Some((at, kept)) = idle.pop() {
            if at.elapsed() < IDLE_FOR {
                return Some(kept);
            }
        }
        None
    }

    fn keep(&self, kept: Kept) {
        let mut idle = lock(&self.idle);
        if idle.len() < IDLE_MAX {
            idle.push((Instant::now(), kept));
        }
    }

    /// A GET of `path` whose answer's head came within `wait`, or with no
    /// bound: its body, read as it comes. A receiver's head comes when its
    /// sender does.
    pub async fn get(&self, path: &str, wait: Option<Duration>) -> Result<Body, Failed> {
        match self.conn(false).await? {
            Conn::H2(send) => Ok(Body::H2(http2::get(send, &self.server, path, wait).await?)),
            Conn::H1 { kept, .. } => {
                let Kept { mut io, mut buf } = kept;
                let head = http1::request("GET", &self.server.authority(), path, Length::None);
                send_head(&mut io, &head).await.map_err(|e| Failed::lost(e.to_string()))?;
                let answer = read_answer(&mut io, &mut buf, wait).await.map_err(|tried| tried.failed)?;
                let mut reader = Reader::new(io, buf, answer.framing);
                if answer.status != 200 {
                    return Err(Failed::status(answer.status, text_of(&mut reader).await));
                }
                Ok(Body::H1(reader))
            }
        }
    }

    /// The whole body of a GET of `path`, at most `cap` bytes, whose head came
    /// within `wait`.
    pub async fn get_all(&self, path: &str, wait: Option<Duration>, cap: usize) -> Result<Vec<u8>, Failed> {
        let mut reuse = true;
        loop {
            match self.conn(reuse).await? {
                Conn::H2(send) => {
                    let mut body = Body::H2(http2::get(send, &self.server, path, wait).await?);
                    return all(&mut body, cap).await.map_err(Failed::lost);
                }
                Conn::H1 { kept, reused } => match self.h1_get_all(kept, path, wait, cap).await {
                    Err(tried) if reused && tried.stale => reuse = false,
                    done => return done.map_err(|tried| tried.failed),
                },
            }
        }
    }

    async fn h1_get_all(&self, kept: Kept, path: &str, wait: Option<Duration>, cap: usize) -> Result<Vec<u8>, Tried> {
        let Kept { mut io, mut buf } = kept;
        let head = http1::request("GET", &self.server.authority(), path, Length::None);
        send_head(&mut io, &head).await.map_err(Tried::stale)?;
        let answer = read_answer(&mut io, &mut buf, wait).await?;
        let mut reader = Reader::new(io, buf, answer.framing);
        let body = reader.all(cap).await.map_err(|why| Tried::other(Failed::lost(why)))?;
        if answer.status != 200 {
            return Err(Tried::other(Failed::status(answer.status, String::from_utf8_lossy(&body).into_owned())));
        }
        if answer.keep && reader.finished() {
            let (io, buf) = reader.into_parts();
            self.keep(Kept { io, buf });
        }
        Ok(body)
    }

    /// A POST of `body` to `path`, and the whole text of the server's answer,
    /// within `wait`: a Piping Server ends it once its receiver took the
    /// body, or went away.
    pub async fn post(&self, path: &str, body: &[u8], wait: Duration) -> Result<String, Failed> {
        let work = async {
            let mut reuse = true;
            loop {
                match self.conn(reuse).await? {
                    Conn::H2(send) => return http2::post(send, &self.server, path, body, wait).await,
                    Conn::H1 { kept, reused } => match self.h1_post(kept, path, body).await {
                        Err(tried) if reused && tried.stale => reuse = false,
                        done => return done.map_err(|tried| tried.failed),
                    },
                }
            }
        };
        tokio::time::timeout(wait, work).await.map_err(|_| Failed::waited(wait))?
    }

    async fn h1_post(&self, kept: Kept, path: &str, body: &[u8]) -> Result<String, Tried> {
        let Kept { io, buf } = kept;
        let (mut read, mut write) = tokio::io::split(io);
        let head = http1::request("POST", &self.server.authority(), path, Length::Fixed(body.len()));
        // The body and the answer at once: the server answers a sender before
        // it reads the body, and reads it only once its receiver came.
        let sending = async {
            send_head(&mut write, &head).await?;
            write.write_all(body).await?;
            write.flush().await
        };
        let answering = async {
            let mut buf = buf;
            let answer = read_answer(&mut read, &mut buf, None).await?;
            let mut reader = Reader::new(&mut read, buf, answer.framing);
            let text = reader.all(TEXT_CAP).await.map_err(|why| Tried::other(Failed::lost(why)))?;
            let finished = reader.finished();
            Ok::<_, Tried>((answer, text, finished))
        };
        let (sent, answered) = tokio::join!(sending, answering);
        let (answer, text, finished) = match (answered, &sent) {
            (Ok(done), _) => done,
            (Err(tried), Err(e)) => return Err(Tried { failed: Failed::lost(e.to_string()), stale: tried.stale }),
            (Err(tried), Ok(())) => return Err(tried),
        };
        let text = String::from_utf8_lossy(&text).into_owned();
        if answer.status != 200 {
            return Err(Tried::other(Failed::status(answer.status, text)));
        }
        // A body that did not all go would begin the next request.
        if answer.keep && finished && sent.is_ok() {
            self.keep(Kept { io: read.unsplit(write), buf: Vec::new() });
        }
        Ok(text)
    }

    /// A POST of `path` whose body begins with `first`, sent with the request's
    /// head, and goes on as [`Upload::send`] gives it, once the server's head
    /// came within `wait`. With no head, a proxy on the way may hold the body
    /// until its end ([`Failed::waited`]). The first bytes go before the head
    /// is awaited, as nwtgck's server (ppng.io's) answers a sender, and its
    /// receiver, only once a byte of the body came.
    pub async fn post_stream(&self, path: &str, wait: Duration, first: &[u8]) -> Result<Upload, Failed> {
        match self.conn(false).await? {
            Conn::H2(send) => {
                let (stream, drain) = http2::post_stream(send, &self.server, path, wait, first).await?;
                Ok(Upload { way: Way::H2(stream), drain })
            }
            Conn::H1 { kept, .. } => {
                let Kept { io, mut buf } = kept;
                let (mut read, mut write) = tokio::io::split(io);
                let head = http1::request("POST", &self.server.authority(), path, Length::Chunked);
                send_head(&mut write, &head).await.map_err(|e| Failed::lost(e.to_string()))?;
                if !first.is_empty() {
                    let sent = async {
                        write.write_all(&http1::chunk(first)).await?;
                        write.flush().await
                    };
                    sent.await.map_err(|e| Failed::lost(e.to_string()))?;
                }
                let answer = read_answer(&mut read, &mut buf, Some(wait)).await.map_err(|tried| tried.failed)?;
                let mut reader = Reader::new(read, buf, answer.framing);
                if answer.status != 200 {
                    return Err(Failed::status(answer.status, text_of(&mut reader).await));
                }
                let drain = tokio::spawn(async move { while let Ok(Some(_)) = reader.next().await {} });
                Ok(Upload { way: Way::H1(write), drain: drain.abort_handle() })
            }
        }
    }

    /// Drop each connection.
    pub async fn close(&self) {
        self.h2.lock().await.take();
        lock(&self.idle).clear();
    }
}

/// The whole of `body`, at most `cap` bytes.
pub async fn all(body: &mut Body, cap: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(bytes) = body.next().await? {
        if out.len() + bytes.len() > cap {
            return Err(format!("a body of more than {cap} bytes"));
        }
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

async fn send_head<W: tokio::io::AsyncWrite + Unpin>(io: &mut W, head: &[u8]) -> std::io::Result<()> {
    io.write_all(head).await?;
    io.flush().await
}

/// An answer's head within `wait`, or with no bound; a connection that ended
/// before any byte of it is stale.
async fn read_answer<R: AsyncRead + Unpin>(
    io: &mut R,
    buf: &mut Vec<u8>,
    wait: Option<Duration>,
) -> Result<http1::Answer, Tried> {
    let read = match wait {
        Some(wait) => match tokio::time::timeout(wait, http1::read_head(io, buf)).await {
            Ok(read) => read,
            Err(_) => return Err(Tried::other(Failed::waited(wait))),
        },
        None => http1::read_head(io, buf).await,
    };
    read.map_err(|why| Tried { failed: Failed::lost(why), stale: buf.is_empty() })
}

/// The text of a refusal, for its line.
async fn text_of<R: AsyncRead + Unpin>(reader: &mut Reader<R>) -> String {
    let bytes = reader.all(TEXT_CAP).await.unwrap_or_default();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
