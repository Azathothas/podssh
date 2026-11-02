//! VLESS over XHTTP (Xray-core, `transport/internet/splithttp/`), on HTTP/2:
//! TLS with `h2` chosen by ALPN, or HTTP/2 with prior knowledge and no TLS,
//! which the server takes (`hub.go`, `SetUnencryptedHTTP2`). Each request
//! carries the padding that the server checks: `Referer` is a URL whose
//! query is `x_padding=` and 100 to 1000 `X` (`config.go`, `FillStreamRequest`
//! and `FillPacketRequest`; `xpadding.go`, `PlacementQueryInHeader`), and a
//! length out of that range is a 400. The session's id and a POST's number go
//! in the path (`config.go`, `ApplyMetaToRequest`), which ends with `/`.
//!
//! - stream-one: one POST to the path, its body up and its answer down; a
//!   POST without a session's id is that mode (`hub.go`).
//! - stream-up: a GET of `PATH/SESSION` down, and one streamed POST to it up.
//! - packet-up ([`super::packet`]): the same GET down, and a POST of
//!   `PATH/SESSION/SEQ` for each chunk up, numbered from 0, which the server
//!   puts in order (`upload_queue.go`).
//!
//! A streamed upload says `Content-Type: application/grpc` unless the link's
//! `extra` says `noGRPCHeader`, as Xray-core's client does, so that a CDN
//! does not hold it. HTTP/1.1 is refused: its split modes need a second
//! connection, which this road does not open, and Go's server reads a whole
//! body before it answers on HTTP/1.1, which stream-one cannot wait for.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::client::{ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};

use super::link::{Mode, Server};
use super::split::Halves;
use super::{Dial, VlessError};
use crate::via::{Duplex, Stream};

/// The windows that the client grants, as `--via` grants them.
const STREAM_WINDOW: u32 = 4 << 20;
const CONNECTION_WINDOW: u32 = 8 << 20;

pub(super) async fn open(
    server: &Server,
    mode: Mode,
    first: Vec<u8>,
    dial: &Dial<'_>,
) -> Result<(Box<dyn Duplex>, String), VlessError> {
    let (sender, over) = connection(server, dial).await?;
    let how = format!("XHTTP {} over {over}", mode.name());
    let limit = dial.timeout;
    let stream: Box<dyn Duplex> = match mode {
        Mode::StreamOne => Box::new(stream_one(server, sender, first, limit).await?),
        Mode::StreamUp => Box::new(stream_up(server, sender, first, limit).await?),
        Mode::PacketUp | Mode::Auto => Box::new(super::packet::open(server, sender, first, limit).await?),
    };
    Ok((stream, how))
}

/// TCP through the host's proxy, TLS with the link's ALPN, and HTTP/2's
/// handshake; the connection runs in a task while a handle or a stream of
/// it lasts.
async fn connection(server: &Server, dial: &Dial<'_>) -> Result<(SendRequest<Bytes>, &'static str), VlessError> {
    let tcp = crate::dial::dial(&server.host, server.port, dial.proxy, dial.timeout).await.map_err(VlessError::Dial)?;
    if !server.tls {
        return Ok((handshake(tcp, dial.timeout).await?, "HTTP/2 with no TLS"));
    }
    let config = crate::tls::config_for(dial.trust).map_err(|e| VlessError::Carry(e.to_string()))?;
    let mut config = (*config).clone();
    config.alpn_protocols = server.alpn.clone();
    let name = rustls_pki_types::ServerName::try_from(server.sni.clone())
        .map_err(|e| VlessError::Carry(format!("{:?} is not a server name: {e}", server.sni)))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let secs = dial.timeout.as_secs();
    let tls = tokio::time::timeout(dial.timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| VlessError::Carry(format!("no TLS handshake within {secs} s")))?
        .map_err(|e| VlessError::Carry(format!("TLS: {}", crate::tls::handshake_failure(&e))))?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(VlessError::Http1(
            "it did not choose HTTP/2 by ALPN (h2): XHTTP over HTTP/1.1 needs a second connection, which this road \
             does not open; serve h2, or type=ws"
                .into(),
        ));
    }
    Ok((handshake(tls, dial.timeout).await?, "HTTP/2"))
}

async fn handshake<S>(io: S, limit: Duration) -> Result<SendRequest<Bytes>, VlessError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(STREAM_WINDOW).initial_connection_window_size(CONNECTION_WINDOW);
    let (sender, connection) = tokio::time::timeout(limit, builder.handshake::<_, Bytes>(io))
        .await
        .map_err(|_| VlessError::Carry(format!("no HTTP/2 handshake within {} s", limit.as_secs())))?
        .map_err(|e| VlessError::Carry(format!("HTTP/2: {e}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

/// The path with `tail` after it, then the link's query.
pub(super) fn at(server: &Server, tail: &str) -> String {
    match server.path.split_once('?') {
        Some((path, query)) => format!("{path}{tail}?{query}"),
        None => format!("{}{tail}", server.path),
    }
}

/// A request of XHTTP: its URI, `Referer` with the padding, the link's
/// headers, and gRPC's type on a streamed upload.
pub(super) fn request(
    server: &Server,
    method: http::Method,
    path: &str,
    streamed: bool,
) -> Result<http::Request<()>, VlessError> {
    let scheme = if server.tls { "https" } else { "http" };
    let (from, to) = server.extra.padding;
    let len = from + random_below(to - from + 1)?;
    let bare = server.path.split('?').next().unwrap_or("/");
    let referer = format!("{scheme}://{}{bare}?x_padding={}", server.authority, "X".repeat(len as usize));
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("{scheme}://{}{path}", server.authority))
        .header(http::header::REFERER, referer)
        .header(http::header::USER_AGENT, crate::url::USER_AGENT);
    if streamed && !server.extra.no_grpc_header {
        builder = builder.header(http::header::CONTENT_TYPE, "application/grpc");
    }
    for (name, value) in &server.extra.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(()).map_err(|e| VlessError::Carry(format!("a request of XHTTP: {e}")))
}

/// A random number below `n`, from the system's source.
fn random_below(n: u32) -> Result<u32, VlessError> {
    use rustls::crypto::SecureRandom as _;
    let mut b = [0u8; 4];
    crate::crypto::random::OsRandom.fill(&mut b).map_err(|_| VlessError::Carry("no random bytes".into()))?;
    Ok(u32::from_le_bytes(b) % n.max(1))
}

/// A session's id: a random UUID, as `GenerateSessionID` makes one.
pub(super) fn session_id() -> Result<String, VlessError> {
    use rustls::crypto::SecureRandom as _;
    let mut b = [0u8; 16];
    crate::crypto::random::OsRandom.fill(&mut b).map_err(|_| VlessError::Carry("no random bytes".into()))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}

/// A request sent, within `limit` for a free stream.
pub(super) async fn send(
    sender: &SendRequest<Bytes>,
    request: http::Request<()>,
    end: bool,
    limit: Duration,
) -> Result<(ResponseFuture, SendStream<Bytes>), VlessError> {
    let mut ready = tokio::time::timeout(limit, sender.clone().ready())
        .await
        .map_err(|_| VlessError::Carry(format!("no free stream of HTTP/2 within {} s", limit.as_secs())))?
        .map_err(|e| VlessError::Carry(format!("HTTP/2: {e}")))?;
    ready.send_request(request, end).map_err(|e| VlessError::Carry(format!("HTTP/2: {e}")))
}

/// The answer to `what`, which must be a 200: a 404 is a path or a host
/// that the server does not serve, a 400 a padding, a session or a mode
/// that it refuses (`hub.go`).
pub(super) async fn answer(
    response: ResponseFuture,
    limit: Duration,
    what: &str,
) -> Result<http::Response<RecvStream>, VlessError> {
    let response = tokio::time::timeout(limit, response)
        .await
        .map_err(|_| VlessError::Carry(format!("no answer to {what} within {} s", limit.as_secs())))?
        .map_err(|e| VlessError::Carry(format!("{what}: HTTP/2: {e}")))?;
    let status = response.status().as_u16();
    if status == 200 {
        return Ok(response);
    }
    let why = match status {
        404 => format!("{what}: no XHTTP at the link's path, or for its host"),
        400 => format!("{what}: its padding, its session or its mode"),
        _ => what.to_string(),
    };
    Err(VlessError::Refused { status, why })
}

/// The bytes of `data` on `send`, as the windows let them go.
pub(super) async fn send_all(send: &mut SendStream<Bytes>, mut data: Bytes, end: bool) -> Result<(), String> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let room = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(0)) => continue,
            Some(Ok(room)) => room,
            Some(Err(e)) => return Err(format!("HTTP/2: {e}")),
            None => return Err("the server ended the request's stream".into()),
        };
        let chunk = data.split_to(room.min(data.len()));
        send.send_data(chunk, false).map_err(|e| format!("HTTP/2: {e}"))?;
    }
    if end {
        send.send_data(Bytes::new(), true).map_err(|e| format!("HTTP/2: {e}"))?;
    }
    Ok(())
}

async fn stream_one(
    server: &Server,
    sender: SendRequest<Bytes>,
    first: Vec<u8>,
    limit: Duration,
) -> Result<Stream, VlessError> {
    let request = request(server, http::Method::POST, &at(server, ""), true)?;
    let (response, mut up) = send(&sender, request, false, limit).await?;
    send_all(&mut up, Bytes::from(first), false).await.map_err(VlessError::Carry)?;
    let response = answer(response, limit, "the POST of stream-one").await?;
    Ok(Stream::from_parts(up, response.into_body()))
}

async fn stream_up(
    server: &Server,
    sender: SendRequest<Bytes>,
    first: Vec<u8>,
    limit: Duration,
) -> Result<Halves<Stream, Stream>, VlessError> {
    let id = session_id()?;
    let get = request(server, http::Method::GET, &at(server, &id), false)?;
    let (down, closed) = send(&sender, get, true, limit).await?;
    let post = request(server, http::Method::POST, &at(server, &id), true)?;
    let (posted, mut up) = send(&sender, post, false, limit).await?;
    send_all(&mut up, Bytes::from(first), false).await.map_err(VlessError::Carry)?;
    let down = answer(down, limit, "the GET of stream-up").await?;
    let posted = answer(posted, limit, "the POST of stream-up").await?;
    let read = Stream::from_parts(closed, down.into_body());
    Ok(Halves { read, write: Stream::from_parts(up, posted.into_body()), failed: Arc::default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(query: &str) -> Server {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        Server::parse(&format!("vless://{id}@v.example:443?type=xhttp&security=tls&path=%2Fxh{query}")).unwrap()
    }

    /// The padding's length is in the server's range, the path ends with
    /// `/`, and gRPC's type goes with a streamed upload alone.
    #[test]
    fn a_request_carries_the_padding_the_session_and_grpc_s_type() {
        let plain = server("");
        assert_eq!(at(&plain, "abc/3"), "/xh/abc/3");
        for _ in 0..20 {
            let request = request(&plain, http::Method::POST, &at(&plain, ""), true).unwrap();
            let referer = request.headers()[http::header::REFERER].to_str().unwrap().to_string();
            let padding = referer.strip_prefix("https://v.example/xh/?x_padding=").expect("Referer's form");
            assert!((100..=1000).contains(&padding.len()) && padding.bytes().all(|b| b == b'X'), "{}", padding.len());
            assert_eq!(request.uri().to_string(), "https://v.example/xh/");
            assert_eq!(request.headers()[http::header::CONTENT_TYPE], "application/grpc");
        }
        let get = request(&plain, http::Method::GET, &at(&plain, "s"), false).unwrap();
        assert!(get.headers().get(http::header::CONTENT_TYPE).is_none());
        let id = session_id().unwrap();
        assert_eq!((id.len(), &id[14..15]), (36, "4"), "{id}");
        let queried = server("%3Fk%3Dv");
        assert_eq!(at(&queried, "s/0"), "/xh/s/0?k=v");
    }
}
