//! A request of the edge for the node's origin, over QUIC (T-428): as over
//! HTTP/2 ([`super::origin_h2`]), but the request is the edge's
//! `ConnectRequest`, whose metadata holds the method, the Host and each
//! header, and the answer is the node's `ConnectResponse`, its status and
//! each header in its metadata, as cloudflared's `httpResponseAdapter`
//! writes them (`connection/quic_connection.go` at 2026.10.6), a 101 kept as
//! it is; then the body, or the WebSocket's frames, as the rest of the
//! stream. Over any stream that reads and writes, so that a test needs no
//! QUIC.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

use super::connect::{self, ConnectRequest, Kind};
use super::origin::{self, Asked, Origin};

/// The metadata's keys of a request's method and Host.
pub const METHOD: &str = "HttpMethod";
pub const HOST: &str = "HttpHost";

/// Serve `request` of the edge with `server`: the bytes after the request
/// come on `from_edge`, and the answer goes on `to_edge`.
pub async fn serve<R, W>(server: Arc<dyn Origin>, request: &ConnectRequest, mut from_edge: R, mut to_edge: W)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let asked = asked(request);
    let body = match asked.websocket {
        true => Vec::new(),
        false => match tokio::time::timeout(origin::BODY_WAIT, read_body(request, &mut from_edge)).await {
            Ok(Ok(body)) => body,
            Ok(Err(status)) => return refuse(&mut to_edge, status).await,
            Err(_) => return refuse(&mut to_edge, 408).await,
        },
    };
    let Ok(head) = asked.head(body.len()) else { return refuse(&mut to_edge, 400).await };
    let mut conn = server.connect();
    let answered = async {
        conn.write_all(&head).await.map_err(|e| e.to_string())?;
        conn.write_all(&body).await.map_err(|e| e.to_string())?;
        origin::read_answer(&mut conn).await
    };
    let Ok(Ok((answer, rest))) = tokio::time::timeout(origin::ANSWER_WAIT, answered).await else {
        return refuse(&mut to_edge, 502).await;
    };
    let passed = answer.passed();
    let status = answer.status.to_string();
    let keys: Vec<String> = passed.iter().map(|(name, _)| format!("{}{name}", connect::HEADER)).collect();
    let mut metadata = vec![(connect::STATUS, status.as_str())];
    metadata.extend(keys.iter().zip(&passed).map(|(key, (_, value))| (key.as_str(), *value)));
    let answered = [connect::preamble().to_vec(), connect::response("", &metadata)].concat();
    if to_edge.write_all(&answered).await.is_err() {
        return;
    }
    let (from_origin, to_origin) = tokio::io::split(conn);
    if answer.switched() {
        both_ways(from_edge, to_edge, rest, from_origin, to_origin).await;
    } else {
        drop(from_edge);
        body_to_edge(to_edge, rest, from_origin).await;
    }
}

/// The request as the origin takes it: its target from the visitor's URL,
/// its Host and method from the metadata, and each `HttpHeader:NAME`.
fn asked(request: &ConnectRequest) -> Asked {
    let meta = |key: &str| request.metadata.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    let host = meta(HOST).map_or_else(|| authority_of(&request.dest), str::to_string);
    let fields = request.metadata.iter().filter_map(|(key, value)| {
        let name = key.strip_prefix(connect::HEADER)?;
        Some((name.to_string(), value.clone()))
    });
    Asked {
        method: meta(METHOD).unwrap_or("GET").to_string(),
        target: target_of(&request.dest),
        host,
        headers: fields.collect(),
        websocket: request.kind == Kind::WebSocket,
    }
}

/// The path and the query of the visitor's URL, `https://HOST/PATH?QUERY`,
/// with no fragment; `/` for none.
pub fn target_of(dest: &str) -> String {
    let rest = dest.split_once("://").map_or(dest, |(_, rest)| rest);
    let rest = rest.split('#').next().unwrap_or_default();
    match rest.find(['/', '?']) {
        Some(at) if rest[at..].starts_with('/') => rest[at..].to_string(),
        Some(at) => format!("/{}", &rest[at..]),
        None => "/".to_string(),
    }
}

/// The authority of the visitor's URL, for a request whose metadata names
/// no Host.
fn authority_of(dest: &str) -> String {
    let rest = dest.split_once("://").map_or(dest, |(_, rest)| rest);
    rest.split(['/', '?', '#']).next().unwrap_or_default().to_string()
}

/// The body of a request that is no upgrade, as cloudflared reads one over
/// QUIC: its `Content-Length`, or with chunks the rest of the stream, else
/// none; [`origin::BODY_MAX`] at most. `Err` holds the status that refuses it.
async fn read_body<R: AsyncRead + Unpin>(request: &ConnectRequest, from_edge: &mut R) -> Result<Vec<u8>, u16> {
    let length = match request.header("content-length") {
        Some(text) => Some(text.trim().parse::<usize>().map_err(|_| 400u16)?),
        None if request.header("transfer-encoding").is_some() => None,
        None => return Ok(Vec::new()),
    };
    if length.is_some_and(|n| n > origin::BODY_MAX) {
        return Err(413);
    }
    let (mut body, mut chunk) = (Vec::new(), vec![0u8; 16 * 1024]);
    while !matches!(length, Some(n) if body.len() >= n) {
        let n = from_edge.read(&mut chunk).await.map_err(|_| 400u16)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > origin::BODY_MAX {
            return Err(413);
        }
    }
    match length {
        Some(n) if body.len() < n => Err(400),
        Some(n) => Ok(body[..n].to_vec()),
        None => Ok(body),
    }
}

/// The node's own answer `status`, with why, as cloudflared answers a
/// request that its origin did not take.
async fn refuse<W: AsyncWrite + Unpin>(to_edge: &mut W, status: u16) {
    let status = status.to_string();
    let why = "podssh's origin did not take the request";
    let answer = [connect::preamble().to_vec(), connect::response(why, &[(connect::STATUS, status.as_str())])];
    let _ = to_edge.write_all(&answer.concat()).await;
    let _ = to_edge.shutdown().await;
}

/// The origin's body to the edge, until the origin closes; an origin that
/// stalls past [`origin::ANSWER_WAIT`] ends the stream there.
async fn body_to_edge<W: AsyncWrite + Unpin>(mut to_edge: W, rest: Vec<u8>, mut from_origin: ReadHalf<DuplexStream>) {
    if to_edge.write_all(&rest).await.is_err() {
        return;
    }
    let mut buf = vec![0u8; origin::PIPE];
    loop {
        match tokio::time::timeout(origin::ANSWER_WAIT, from_origin.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                if to_edge.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
    let _ = to_edge.shutdown().await;
}

/// After a 101: the visitor's frames to the origin, and the origin's to the
/// visitor, until the origin ends; once the visitor's side ended, the
/// origin's last frames have [`origin::END_WAIT`].
async fn both_ways<R, W>(
    mut from_edge: R,
    mut to_edge: W,
    rest: Vec<u8>,
    mut from_origin: ReadHalf<DuplexStream>,
    mut to_origin: WriteHalf<DuplexStream>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let up = async move {
        let _ = tokio::io::copy(&mut from_edge, &mut to_origin).await;
        let _ = to_origin.shutdown().await;
    };
    let down = async move {
        if to_edge.write_all(&rest).await.is_ok() {
            let _ = tokio::io::copy(&mut from_origin, &mut to_edge).await;
        }
        let _ = to_edge.shutdown().await;
    };
    tokio::pin!(up, down);
    tokio::select! {
        () = &mut down => {}
        () = &mut up => {
            let _ = tokio::time::timeout(origin::END_WAIT, down).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_is_the_path_and_the_query_of_the_visitor_s_url() {
        assert_eq!(target_of("https://podssh-test.trycloudflare.com/"), "/");
        assert_eq!(target_of("https://h.example/v1/mint"), "/v1/mint");
        let target = target_of("https://h.example/connect/github.com/22?dial=lazy#x");
        assert_eq!(target, "/connect/github.com/22?dial=lazy");
        assert_eq!(target_of("https://h.example?x=1"), "/?x=1");
        assert_eq!(target_of("https://h.example"), "/");
        assert_eq!(authority_of("https://h.example:8443/health"), "h.example:8443");
    }

    /// The request of the reference's fixture, for a WebSocket, as the
    /// origin takes it: its Host, its method and its headers.
    #[test]
    fn the_fixture_s_request_reads_as_the_origin_takes_it() {
        let frame = include_bytes!("../../tests/fixtures/quick/quic-connect-request.bin");
        let request = connect::read_request(frame).expect("the reference's request");
        let asked = asked(&request);
        assert_eq!((asked.method.as_str(), asked.target.as_str()), ("GET", "/"));
        assert_eq!(asked.host, "podssh-test.trycloudflare.com");
        assert!(asked.websocket);
        assert!(asked.headers.contains(&("Sec-Websocket-Key".to_string(), "dGhlIHNhbXBsZSBub25jZQ==".to_string())));
        assert!(!asked.headers.iter().any(|(name, _)| name.starts_with("Http")), "{:?}", asked.headers);
    }
}
