//! The tunnel: TCP to the endpoint's address, through the proxy when one is
//! set; TLS of [`crate::tls`]; HTTP/2; and one CONNECT, as connect-ip-go's
//! fork sends it over HTTP/2 (`client_h2.go`, `DialH2`, with usque's
//! headers from `api/masque.go`): `:method CONNECT`, `:authority`
//! [`crate::AUTHORITY`], `cf-connect-proto: cf-connect-ip` and `pq-enabled:
//! false`, no `User-Agent`. Its request body carries the client's packets,
//! and its response body the edge's, each in a capsule.
//!
//! [`pump`] moves the packets of such a stream both ways, for the client and
//! for the stand-in's far end alike.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use podssh_ws::dial::{self, DialError, ProxyChoice};
use tokio::sync::mpsc;

use crate::capsule;
use crate::device::Device;
use crate::stack::{Link, Why};

/// The windows of HTTP/2 that the client grants: a few round trips of a
/// fast link, so that a copy is not held to HTTP/2's 64 KiB.
pub const STREAM_WINDOW: u32 = 4 << 20;
pub const CONNECTION_WINDOW: u32 = 8 << 20;
/// The smallest DATA frame that the edge sends, as it sends one for each
/// packet: the capsule of an IPv4 TCP segment with no option and no data, 40
/// bytes, after a type and a length of one byte each.
pub const SMALLEST_FRAME: usize = 42;
/// h2's budget of small DATA frames that wait unread (T-398). h2 counts,
/// for each frame under 256 bytes, 256 bytes less its size until the reader
/// takes it, and past the budget ends the connection with ENHANCE_YOUR_CALM
/// ("too_many_data_frames"). Its own budget, half the connection's window,
/// is 4 MiB here: 21,400 unread frames of 60 bytes, a third of what the
/// stream's window lets the edge send, and cfrs's WARP road died of it. This
/// one holds the stream's whole window in the smallest frames, so that the
/// window, which the reader releases, stops the edge first.
pub const FRAME_BUDGET: usize = STREAM_WINDOW as usize / SMALLEST_FRAME * (256 - SMALLEST_FRAME);
// It holds a window of the 60 bytes of cfrs's test, as h2's own does not.
const _: () = assert!(FRAME_BUDGET >= STREAM_WINDOW as usize / 60 * (256 - 60));
/// Packets that wait between the stack and the tunnel's tasks.
const PACKETS: usize = 256;
/// The most bytes of capsules sent in one DATA frame's worth.
const BATCH: usize = 64 * 1024;
/// A PING of HTTP/2 on a silent tunnel, and how long its answer may take.
const PING_EVERY: Duration = Duration::from_secs(25);
const PING_WAIT: Duration = Duration::from_secs(20);

/// Why the tunnel did not open, by its step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    /// The TCP connection, or the proxy's CONNECT to the address.
    Dial(DialError),
    /// A certificate of another key than the endpoint's: a proxy that
    /// re-terminates TLS, whose issuer is named.
    Intercepted { issuer: String },
    /// The edge took no certificate of this device: not enrolled, or gone.
    NotEnrolled(String),
    /// Another failure of TLS.
    Tls(String),
    /// HTTP/2, or the CONNECT, failed.
    Http2(String),
    /// The edge answered the CONNECT with this status.
    Refused { status: u16 },
    /// Within the limit, no answer.
    Timeout(&'static str),
    /// This host's part: the key, the configuration.
    Local(String),
}

/// The CONNECT's request.
pub fn request() -> Result<http::Request<()>, String> {
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(crate::AUTHORITY)
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .body(())
        .map_err(|e| e.to_string())
}

/// HTTP/2's client as the tunnel speaks it: the windows and the budget of
/// small frames above.
pub fn client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .data_frame_budget(FRAME_BUDGET);
    builder
}

/// Open the tunnel of `device`, through `proxy`, each step within `limit`.
pub async fn open(device: &Device, proxy: &ProxyChoice, limit: Duration) -> Result<Link, Opening> {
    let (ip, port) = (device.endpoint.ip().to_string(), device.endpoint.port());
    let tcp = dial::dial(&ip, port, proxy, limit).await.map_err(Opening::Dial)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    // A certificate from a minute ago, for a clock a little ahead of the edge's.
    let (config, pinned) = crate::tls::config(&device.key, &device.endpoint_point, now - 60).map_err(Opening::Local)?;
    let name = rustls_pki_types::ServerName::try_from(crate::SERVER_NAME).map_err(|e| Opening::Local(e.to_string()))?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tls = match tokio::time::timeout(limit, connector.connect(name, tcp)).await {
        Err(_) => return Err(Opening::Timeout("the TLS handshake with WARP's endpoint")),
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            if let Some(issuer) = pinned.refused() {
                return Err(Opening::Intercepted { issuer });
            }
            let text = e.to_string();
            let denied = matches!(
                e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()),
                Some(rustls::Error::AlertReceived(rustls::AlertDescription::AccessDenied))
            ) || text.contains("AccessDenied");
            return Err(if denied { Opening::NotEnrolled(text) } else { Opening::Tls(text) });
        }
    };
    if tls.get_ref().1.alpn_protocol() != Some(crate::tls::ALPN) {
        return Err(Opening::Tls("the endpoint did not take HTTP/2 (ALPN h2)".into()));
    }
    let handshake = client_builder().handshake::<_, Bytes>(tls);
    let (client, mut connection) = tokio::time::timeout(limit, handshake)
        .await
        .map_err(|_| Opening::Timeout("HTTP/2's handshake with WARP's endpoint"))?
        .map_err(|e| http2(e.to_string()))?;
    let why = Why::default();
    let pings = connection.ping_pong();
    let driven = {
        let why = why.clone();
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                why.set(format!("HTTP/2 with WARP's endpoint: {e}"));
            }
        })
    };
    let asked = async {
        let mut client = client.ready().await.map_err(|e| http2(e.to_string()))?;
        let request = request().map_err(Opening::Local)?;
        let (response, send) = client.send_request(request, false).map_err(|e| http2(e.to_string()))?;
        let response = response.await.map_err(|e| http2(e.to_string()))?;
        Ok::<_, Opening>((response, send, client))
    };
    let (response, send, client) = match tokio::time::timeout(limit, asked).await {
        Ok(Ok(answered)) => answered,
        Ok(Err(e)) => {
            // The connection's own error, which holds a TLS alert that a
            // stream's error may not, comes a moment after the stream's.
            let _ = tokio::time::timeout(Duration::from_millis(500), why.ended()).await;
            driven.abort();
            return Err(match (e, why.get().map(http2)) {
                (Opening::Http2(_), Some(Opening::NotEnrolled(said))) => Opening::NotEnrolled(said),
                (e, _) => e,
            });
        }
        Err(_) => {
            driven.abort();
            return Err(Opening::Timeout("the edge's answer to the CONNECT"));
        }
    };
    if !response.status().is_success() {
        driven.abort();
        return Err(Opening::Refused { status: response.status().as_u16() });
    }
    let mut link = pump(response.into_body(), send, why.clone());
    link.tasks.push(driven.abort_handle());
    link.tasks.push(tokio::spawn(keep_alive(pings, why, client)).abort_handle());
    Ok(link)
}

/// A failure of HTTP/2. In TLS 1.3 the server checks the client's
/// certificate after the client's handshake has ended, so its refusal, the
/// alert `access_denied` (usque: "tls: access denied"), comes at the first
/// read of HTTP/2.
fn http2(text: String) -> Opening {
    if text.contains("AccessDenied") || text.contains("access denied") {
        Opening::NotEnrolled(text)
    } else {
        Opening::Http2(text)
    }
}

/// A PING each [`PING_EVERY`]: a tunnel whose PING gets no answer within
/// [`PING_WAIT`] has ended, as a proxy may drop a quiet connection with no
/// word. The task holds the connection's handle of requests while the
/// tunnel lasts.
async fn keep_alive(pings: Option<h2::PingPong>, why: Why, _client: h2::client::SendRequest<Bytes>) {
    let Some(mut pings) = pings else { return std::future::pending().await };
    loop {
        tokio::time::sleep(PING_EVERY).await;
        match tokio::time::timeout(PING_WAIT, pings.ping(h2::Ping::opaque())).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                why.set(format!("a PING of HTTP/2 failed: {e}"));
                return;
            }
            Err(_) => {
                why.set(format!("WARP's endpoint answered no PING within {} s", PING_WAIT.as_secs()));
                return;
            }
        }
    }
}

/// The packets of a stream of capsules, both ways: those that come on
/// `recv`, to the link's `inbound`; those that the link sends, on `send`.
pub fn pump(recv: RecvStream, send: SendStream<Bytes>, why: Why) -> Link {
    let (to_stack, inbound) = mpsc::channel(PACKETS);
    let (out, from_stack) = mpsc::channel(PACKETS);
    let reader = tokio::spawn(read(recv, to_stack, why.clone()));
    let writer = tokio::spawn(write(send, from_stack, why.clone()));
    Link { out, inbound, why, tasks: vec![reader.abort_handle(), writer.abort_handle()] }
}

async fn read(mut recv: RecvStream, to_stack: mpsc::Sender<Vec<u8>>, why: Why) {
    let mut reader = capsule::Reader::default();
    loop {
        // A silent PING or a lost connection says the end before the
        // stream does: the stack's channel ends here, and with it the stack.
        let data = tokio::select! {
            data = recv.data() => data,
            () = why.ended() => return,
        };
        let chunk = match data {
            Some(Ok(chunk)) => chunk,
            Some(Err(e)) => return why.set(format!("the tunnel's stream failed: {e}")),
            None => return why.set("the edge ended the tunnel's stream"),
        };
        let _ = recv.flow_control().release_capacity(chunk.len());
        reader.push(&chunk);
        loop {
            match reader.next_packet() {
                Ok(Some(packet)) => {
                    if to_stack.send(packet).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(e) => return why.set(e),
            }
        }
    }
}

async fn write(mut send: SendStream<Bytes>, mut from_stack: mpsc::Receiver<Vec<u8>>, why: Why) {
    while let Some(packet) = from_stack.recv().await {
        let mut bytes = capsule::datagram(&packet);
        while bytes.len() < BATCH {
            match from_stack.try_recv() {
                Ok(more) => bytes.extend_from_slice(&capsule::datagram(&more)),
                Err(_) => break,
            }
        }
        if let Err(e) = send_all(&mut send, &bytes).await {
            return why.set(format!("the tunnel's stream took no more: {e}"));
        }
    }
    let _ = send.send_data(Bytes::new(), true);
}

/// Send `bytes` on `send` as the peer's window lets them go.
async fn send_all(send: &mut SendStream<Bytes>, mut bytes: &[u8]) -> Result<(), h2::Error> {
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len());
        let room = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(room)) => room,
            Some(Err(e)) => return Err(e),
            None => return Err(h2::Error::from(h2::Reason::CANCEL)),
        };
        let take = room.min(bytes.len());
        if take == 0 {
            continue;
        }
        send.send_data(Bytes::copy_from_slice(&bytes[..take]), false)?;
        bytes = &bytes[take..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The CONNECT as usque sends it: no :scheme or :path, as a CONNECT
    /// with no :protocol has none (h2 leaves them out for it).
    #[test]
    fn the_connect_is_usque_s() {
        let request = super::request().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri().authority().map(|a| a.as_str()), Some("cloudflareaccess.com:443"));
        assert_eq!(request.uri().scheme(), None);
        assert_eq!(request.headers()["cf-connect-proto"], "cf-connect-ip");
        assert_eq!(request.headers()["pq-enabled"], "false");
        assert!(request.headers().get("user-agent").is_none());
    }
}
