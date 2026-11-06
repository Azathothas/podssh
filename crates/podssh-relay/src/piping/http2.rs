//! HTTP/2 to a Piping Server: one connection, each request a stream of it,
//! and a PING when it is quiet, as a proxy may drop a quiet connection with
//! no word and a node's door waits for hours. Node's server takes a
//! request's head and answers a sender before its body comes, and streams a
//! receiver's body as the sender's DATA comes (its `http2` compatibility
//! layer), so a stream is a way of a link.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use tokio::task::AbortHandle;

use super::dial::BoxIo;
use super::exchange::Failed;
use super::server::Server;

/// The windows that this end grants: a few round trips of a fast link.
pub const STREAM_WINDOW: u32 = 1 << 20;
pub const CONNECTION_WINDOW: u32 = 4 << 20;
/// A PING of a quiet connection, and how long its answer may take.
const PING_EVERY: Duration = Duration::from_secs(25);
const PING_WAIT: Duration = Duration::from_secs(20);
/// The bound of HTTP/2's handshake.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(20);
/// The most of an answer's text that is kept, for a line.
pub const TEXT_CAP: usize = 4096;

/// A connection of HTTP/2, while it lives.
pub struct Conn {
    pub send: SendRequest<Bytes>,
    ended: Arc<AtomicBool>,
    tasks: Vec<AbortHandle>,
}

impl Conn {
    /// HTTP/2 over `io`, driven and pinged by tasks of its own.
    pub async fn start(io: BoxIo) -> Result<Conn, String> {
        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(STREAM_WINDOW).initial_connection_window_size(CONNECTION_WINDOW);
        let (send, mut connection) = tokio::time::timeout(HANDSHAKE_LIMIT, builder.handshake::<_, Bytes>(io))
            .await
            .map_err(|_| format!("no HTTP/2 within {} s", HANDSHAKE_LIMIT.as_secs()))?
            .map_err(|e| format!("HTTP/2: {e}"))?;
        let ended = Arc::new(AtomicBool::new(false));
        let pings = connection.ping_pong();
        let driver = {
            let ended = ended.clone();
            tokio::spawn(async move {
                let _ = connection.await;
                ended.store(true, Ordering::SeqCst);
            })
        };
        let pinger = tokio::spawn(keep_alive(pings, ended.clone(), driver.abort_handle()));
        Ok(Conn { send, ended, tasks: vec![driver.abort_handle(), pinger.abort_handle()] })
    }

    /// Whether the connection may carry another request.
    pub fn alive(&self) -> bool {
        !self.ended.load(Ordering::SeqCst)
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.ended.store(true, Ordering::SeqCst);
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// A PING each [`PING_EVERY`]; a connection whose PING gets no answer within
/// [`PING_WAIT`] is ended, so that each of its streams fails and is asked
/// again on a new one.
async fn keep_alive(pings: Option<h2::PingPong>, ended: Arc<AtomicBool>, driver: AbortHandle) {
    let Some(mut pings) = pings else { return };
    loop {
        tokio::time::sleep(PING_EVERY).await;
        if !matches!(tokio::time::timeout(PING_WAIT, pings.ping(h2::Ping::opaque())).await, Ok(Ok(_))) {
            ended.store(true, Ordering::SeqCst);
            driver.abort();
            return;
        }
    }
}

/// A request of HTTP/2 for `path` on `server`; a POST of a known length
/// says it.
fn request(
    server: &Server,
    method: http::Method,
    path: &str,
    length: Option<usize>,
) -> Result<http::Request<()>, Failed> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("https://{}{path}", server.authority()))
        .version(http::Version::HTTP_2)
        .header("user-agent", super::USER_AGENT);
    if let Some(length) = length {
        builder =
            builder.header("content-type", "application/octet-stream").header("content-length", length.to_string());
    }
    builder.body(()).map_err(|e| Failed::lost(format!("the request: {e}")))
}

/// A GET of `path` whose answer's head came within `wait`, or with no bound:
/// its status, and its body. A refusal's text is read.
pub async fn get(
    send: SendRequest<Bytes>,
    server: &Server,
    path: &str,
    wait: Option<Duration>,
) -> Result<RecvStream, Failed> {
    get_sized(send, server, path, wait).await.map(|(body, _)| body)
}

/// [`get`], and the length that the answer's `Content-Length` gives, which
/// a whole body must have: a front that cuts a transfer can end the stream
/// cleanly, short (T-497, `piping.onrender.com`).
pub async fn get_sized(
    send: SendRequest<Bytes>,
    server: &Server,
    path: &str,
    wait: Option<Duration>,
) -> Result<(RecvStream, Option<u64>), Failed> {
    let request = request(server, http::Method::GET, path, None)?;
    let mut send = send.ready().await.map_err(lost)?;
    let (answer, _) = send.send_request(request, true).map_err(lost)?;
    let answer = match wait {
        Some(wait) => tokio::time::timeout(wait, answer).await.map_err(|_| Failed::waited(wait))?,
        None => answer.await,
    }
    .map_err(lost)?;
    let status = answer.status().as_u16();
    let length = answer.headers().get(http::header::CONTENT_LENGTH);
    let length = length.and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
    let body = answer.into_body();
    if status != 200 {
        return Err(Failed::status(status, text(body).await));
    }
    Ok((body, length))
}

/// A POST of `body` to `path`, and the whole text of its answer, both within
/// `wait`.
pub async fn post(
    send: SendRequest<Bytes>,
    server: &Server,
    path: &str,
    body: &[u8],
    wait: Duration,
) -> Result<String, Failed> {
    let request = request(server, http::Method::POST, path, Some(body.len()))?;
    let work = async {
        let mut send = send.ready().await.map_err(lost)?;
        let (answer, mut stream) = send.send_request(request, false).map_err(lost)?;
        // The body and the answer at once: a server answers a sender before
        // it takes the body, and takes it only once its receiver came.
        let sending = async {
            send_all(&mut stream, body).await?;
            stream.send_data(Bytes::new(), true).map_err(|e| e.to_string())
        };
        let answering = async {
            let answer = answer.await.map_err(lost)?;
            let status = answer.status().as_u16();
            let text = text(answer.into_body()).await;
            if status != 200 {
                return Err(Failed::status(status, text));
            }
            Ok(text)
        };
        let (sent, answered) = tokio::join!(sending, answering);
        let text = answered?;
        sent.map_err(Failed::lost)?;
        Ok(text)
    };
    tokio::time::timeout(wait, work).await.map_err(|_| Failed::waited(wait))?
}

/// A POST of `path` whose body goes as it comes, once the server's head came
/// within `wait`: its stream, and the task that reads the server's words.
pub async fn post_stream(
    send: SendRequest<Bytes>,
    server: &Server,
    path: &str,
    wait: Duration,
    first: &[u8],
) -> Result<(SendStream<Bytes>, AbortHandle), Failed> {
    let request = request(server, http::Method::POST, path, None)?;
    let mut send = send.ready().await.map_err(lost)?;
    let (answer, mut stream) = send.send_request(request, false).map_err(lost)?;
    // The first bytes before the answer: nwtgck's server answers a sender
    // only once its first byte came.
    send_all(&mut stream, first).await.map_err(Failed::lost)?;
    // No head within the wait: a proxy on the way may hold the body to its end.
    let answer = tokio::time::timeout(wait, answer).await.map_err(|_| Failed::waited(wait))?.map_err(lost)?;
    let status = answer.status().as_u16();
    if status != 200 {
        return Err(Failed::status(status, text(answer.into_body()).await));
    }
    let drain = tokio::spawn(async move {
        let _ = text(answer.into_body()).await;
    });
    Ok((stream, drain.abort_handle()))
}

/// The next bytes of `body`, its window given back; `None` at its end.
pub async fn next(body: &mut RecvStream) -> Result<Option<Bytes>, String> {
    match body.data().await {
        None => Ok(None),
        Some(Err(e)) => Err(e.to_string()),
        Some(Ok(bytes)) => {
            let _ = body.flow_control().release_capacity(bytes.len());
            Ok(Some(bytes))
        }
    }
}

/// Send `bytes` on `stream` as the server's window lets them go.
pub async fn send_all(stream: &mut SendStream<Bytes>, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len());
        let room = match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(Ok(room)) => room,
            Some(Err(e)) => return Err(e.to_string()),
            None => return Err("the stream was reset".into()),
        };
        let take = room.min(bytes.len());
        if take == 0 {
            continue;
        }
        stream.send_data(Bytes::copy_from_slice(&bytes[..take]), false).map_err(|e| e.to_string())?;
        bytes = &bytes[take..];
    }
    Ok(())
}

/// The text of an answer, at most [`TEXT_CAP`] bytes of it kept, read to its
/// end: a Piping Server ends a sender's answer once its receiver took the
/// body.
async fn text(mut body: RecvStream) -> String {
    let mut kept = Vec::new();
    while let Ok(Some(bytes)) = next(&mut body).await {
        let room = TEXT_CAP.saturating_sub(kept.len());
        kept.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }
    String::from_utf8_lossy(&kept).into_owned()
}

fn lost(e: h2::Error) -> Failed {
    Failed::lost(format!("HTTP/2: {e}"))
}
