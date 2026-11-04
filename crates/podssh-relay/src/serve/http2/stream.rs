//! One stream of HTTP/2 at the role (T-321), as one request of HTTP/1.1 to
//! the role's own routes on a pipe in memory, which no socket carries. An
//! extended CONNECT with `:protocol websocket` becomes the upgrade of its
//! path, with the client's fields, its token's among them, and a key of
//! this end's, as RFC 8441 sends none (section 5); its 101 becomes a 200,
//! and the frames of RFC 6455 then cross the stream and the pipe as they
//! come, each way waiting for its reader. A refusal of the upgrade, and the
//! answer of a document or of the mint, goes back with its status, its
//! fields but those of one hop, and its body.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{Reason, RecvStream};
use http::{HeaderMap, Method};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::serve::Config;

/// The pipe's buffer each way.
const PIPE: usize = 64 * 1024;
/// The largest body of a request taken whole: the mint's is 4 KiB.
const BODY: usize = 64 * 1024;
/// The largest answer of a document, read whole.
const ANSWER: usize = 1 << 20;
/// The longest head of an answer, as a client reads one.
const HEAD: usize = 16 * 1024;
/// How long the role has to answer: its dial of a target comes first.
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// The fields of one hop, which HTTP/2 does not carry (RFC 9113 section
/// 8.2.2).
const HOP: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te"];

/// Whether a request that is no CONNECT is one that the role answers whole
/// and then closes: a document's GET, or the mint.
fn whole(method: &Method, path: &str) -> bool {
    matches!(
        (method.as_str(), path),
        ("GET", "/health" | "/relays.json" | "/trace" | "/llms-full.txt") | ("POST", "/v1/mint")
    )
}

/// Serve the stream of `request`, of a client at `from` that asked for the
/// name `sni`.
pub(super) async fn serve(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    cfg: Arc<Config>,
    sni: Option<String>,
    from: Option<IpAddr>,
) {
    let protocol = request.extensions().get::<h2::ext::Protocol>().map(|p| p.as_str().to_ascii_lowercase());
    let connect = request.method() == Method::CONNECT;
    match protocol.as_deref() {
        Some("websocket") if connect => websocket(request, respond, cfg, sni, from).await,
        Some(_) => refuse(&mut respond, 501, "this relay's extended CONNECT takes websocket alone"),
        None if connect => refuse(&mut respond, 405, "this relay is no proxy: a CONNECT names websocket in :protocol"),
        None if whole(request.method(), request.uri().path()) => document(request, respond, cfg, sni, from).await,
        // Asked for again over HTTP/1.1, which a client of HTTP/2 does at once.
        None => respond.send_reset(Reason::HTTP_1_1_REQUIRED),
    }
}

/// An answer of this end's own: `status`, and `words` as a body of text.
fn refuse(respond: &mut SendResponse<Bytes>, status: u16, words: &str) {
    let head = http::Response::builder().status(status).header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    let Ok(head) = head.body(()) else { return respond.send_reset(Reason::INTERNAL_ERROR) };
    if let Ok(mut send) = respond.send_response(head, false) {
        let _ = send.send_data(Bytes::from(format!("{words}\n")), true);
    }
}

/// The client's fields of `headers` as lines of HTTP/1.1, but for those of
/// one hop and of `skip`; a value that is not text is left out.
fn fields(head: &mut String, headers: &HeaderMap, skip: &[&str]) {
    for (name, value) in headers {
        let name = name.as_str();
        if HOP.contains(&name) || skip.contains(&name) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
}

/// The upgrade of HTTP/1.1 that the extended CONNECT of `parts` asks for.
fn upgrade_head(parts: &http::request::Parts) -> Result<String, (u16, &'static str)> {
    let authority = parts.uri.authority().ok_or((400, "an extended CONNECT names its :authority"))?;
    let target = parts.uri.path_and_query().ok_or((400, "an extended CONNECT names its :path"))?;
    let key = podssh_ws::handshake::generate_key().map_err(|_| (500, "relay: no entropy for the upgrade's key"))?;
    let mut head = format!(
        "GET {target} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n"
    );
    fields(&mut head, &parts.headers, &["host", "sec-websocket-key", "content-length"]);
    head.push_str("\r\n");
    Ok(head)
}

/// `request` to the role's routes, served in a task of its own as a
/// connection of the listener is: the pipe's other end, once the request
/// went in.
async fn route(request: Vec<u8>, cfg: Arc<Config>, sni: Option<String>, from: Option<IpAddr>) -> Option<DuplexStream> {
    let (inner, mut outer) = tokio::io::duplex(PIPE);
    tokio::spawn(crate::serve::serve_from(inner, cfg, sni, from));
    outer.write_all(&request).await.ok()?;
    Some(outer)
}

/// The head of the role's answer on `pipe`: its status, the bytes read,
/// and where the head ends in them.
async fn read_head(pipe: &mut DuplexStream) -> Option<(u16, Vec<u8>, usize)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let read = async {
        loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Some(at + 4);
            }
            if buf.len() > HEAD {
                return None;
            }
            let n = pipe.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    };
    let end = tokio::time::timeout(ANSWER_WAIT, read).await.ok()??;
    let (status, _, _) = podssh_ws::http::parse_head(&String::from_utf8_lossy(&buf[..end])).ok()?;
    Some((status, buf, end))
}

/// The extended CONNECT of `request`: the upgrade at the role, and then
/// the session's bytes both ways.
async fn websocket(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    cfg: Arc<Config>,
    sni: Option<String>,
    from: Option<IpAddr>,
) {
    let (parts, body) = request.into_parts();
    let head = match upgrade_head(&parts) {
        Ok(head) => head,
        Err((status, why)) => return refuse(&mut respond, status, why),
    };
    let Some(mut pipe) = route(head.into_bytes(), cfg, sni, from).await else {
        return refuse(&mut respond, 502, "relay: the upgrade reached no route");
    };
    let Some((status, buf, end)) = read_head(&mut pipe).await else {
        return refuse(&mut respond, 502, "relay: no answer to the upgrade");
    };
    if status != 101 {
        return answer(&mut pipe, buf, respond).await;
    }
    let Ok(opened) = http::Response::builder().status(200).body(()) else { return };
    let Ok(send) = respond.send_response(opened, false) else { return };
    let mut stream = podssh_ws::h2_road::duplex(send, body);
    // The role's first frames may have come with its 101.
    if end < buf.len() && stream.write_all(&buf[end..]).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional_with_sizes(&mut stream, &mut pipe, PIPE, PIPE).await;
    let _ = stream.shutdown().await;
}

/// A document's GET, or the mint's POST, whose body comes whole first.
async fn document(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    cfg: Arc<Config>,
    sni: Option<String>,
    from: Option<IpAddr>,
) {
    let (parts, mut body) = request.into_parts();
    let Some(authority) = parts.uri.authority().map(|a| a.to_string()) else {
        return refuse(&mut respond, 400, "a request names its :authority");
    };
    let target = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let Some(sent) = taken(&mut body).await else {
        return refuse(&mut respond, 413, "a body of 64 KiB at most, whole within 30 s");
    };
    let mut head = format!("{} {target} HTTP/1.1\r\nHost: {authority}\r\n", parts.method);
    fields(&mut head, &parts.headers, &["host", "content-length"]);
    if !sent.is_empty() || parts.method == Method::POST {
        head.push_str(&format!("Content-Length: {}\r\n", sent.len()));
    }
    head.push_str("\r\n");
    let mut request = head.into_bytes();
    request.extend_from_slice(&sent);
    let Some(mut pipe) = route(request, cfg, sni, from).await else {
        return refuse(&mut respond, 502, "relay: the request reached no route");
    };
    answer(&mut pipe, Vec::new(), respond).await
}

/// A request's body whole, [`BODY`] at most, within [`ANSWER_WAIT`].
async fn taken(body: &mut RecvStream) -> Option<Vec<u8>> {
    let mut sent = Vec::new();
    let read = async {
        while let Some(chunk) = body.data().await {
            let chunk = chunk.ok()?;
            let _ = body.flow_control().release_capacity(chunk.len());
            sent.extend_from_slice(&chunk);
            if sent.len() > BODY {
                return None;
            }
        }
        Some(())
    };
    tokio::time::timeout(ANSWER_WAIT, read).await.ok()??;
    Some(sent)
}

/// The role's answer on `pipe`, `buffered` its first bytes, given back on
/// the stream whole.
async fn answer(pipe: &mut DuplexStream, buffered: Vec<u8>, mut respond: SendResponse<Bytes>) {
    let read = tokio::time::timeout(ANSWER_WAIT, podssh_ws::http::read_response(pipe, buffered, ANSWER)).await;
    let Ok(Ok(answer)) = read else { return refuse(&mut respond, 502, "relay: its answer did not come whole") };
    let mut head = http::Response::builder().status(answer.status);
    for (name, value) in &answer.headers {
        if HOP.contains(&name.as_str()) || name == "content-length" {
            continue;
        }
        head = head.header(name.as_str(), value.as_str());
    }
    let Ok(head) = head.body(()) else { return respond.send_reset(Reason::INTERNAL_ERROR) };
    let body = Bytes::from(answer.body);
    let Ok(mut send) = respond.send_response(head, body.is_empty()) else { return };
    if !body.is_empty() {
        let _ = send.send_data(body, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8441 sends no key: the role's upgrade gets one of this end's, the
    /// client's fields but those of one hop, and the path with its query.
    #[test]
    fn the_upgrade_of_a_connect_holds_its_path_its_name_its_token_and_a_key() {
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri("https://relay.example:443/connect/github.com/22?dial=lazy")
            .header("x-relay-token", "t0ken")
            .header("sec-websocket-version", "13")
            .header("te", "trailers")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let head = upgrade_head(&parts).unwrap();
        let parsed = podssh_ws::http::request::parse_request(head.as_bytes()).unwrap();
        assert_eq!((parsed.method.as_str(), parsed.target.as_str()), ("GET", "/connect/github.com/22?dial=lazy"));
        assert_eq!(parsed.header("host"), Some("relay.example:443"));
        assert_eq!(parsed.header("x-relay-token"), Some("t0ken"));
        assert!(parsed.header("te").is_none(), "{head}");
        let key = podssh_ws::server::check_upgrade(&parsed).expect("an upgrade that RFC 6455 takes");
        assert_eq!(key.len(), 24);
        assert!(whole(&Method::GET, "/health") && whole(&Method::POST, "/v1/mint"));
        assert!(!whole(&Method::GET, "/v1/mint") && !whole(&Method::POST, "/v1/http/open/h/22"));
    }
}
