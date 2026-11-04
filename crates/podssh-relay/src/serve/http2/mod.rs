//! HTTP/2 at the role's own listener (T-321, RFC 8441), for a client that
//! chose `h2` by ALPN (`podssh relay serve --http2`, on by default): the
//! role's SETTINGS offer extended CONNECT (`SETTINGS_ENABLE_CONNECT_PROTOCOL`)
//! and [`STREAMS`] streams at once, each with a window of [`STREAM_WINDOW`]
//! and [`CONNECTION_WINDOW`] for them together, so that a stream that a slow
//! target holds full takes no other stream's window, and a connection holds
//! that much of a client's bytes at most. Each stream is one request of
//! HTTP/1.1 to the role's own routes ([`super::serve_from`]) over a pipe in
//! memory ([`stream`]), so that each road keeps its own code, its token, its
//! checks and its brake: an extended CONNECT with `:protocol websocket` is
//! the upgrade of its path, answered 200 for the 101, then the frames of RFC
//! 6455 both ways; a document's GET and the mint's POST, their answers. Each
//! other request is asked for again over HTTP/1.1 (`HTTP_1_1_REQUIRED`, RFC
//! 9113 section 7), as the HTTP road, the probes and the reverse road's calls
//! keep a connection, or a stream, as HTTP/1.1 gives them. A connection with
//! no stream for [`IDLE`] ends with a GOAWAY.

mod stream;

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use super::Config;

/// The ALPN of HTTP/2, which the listener offers before `http/1.1`.
pub const H2: &[u8] = b"h2";

/// The streams of one connection at once: the most sessions of a client on
/// one connection, as podssh's client takes them.
pub const STREAMS: u32 = 16;

/// The window of each stream, and of the connection: each stream's,
/// together.
pub const STREAM_WINDOW: u32 = 1 << 20;
pub const CONNECTION_WINDOW: u32 = STREAM_WINDOW * STREAMS;

/// How long a connection with no stream stays.
pub const IDLE: Duration = Duration::from_secs(120);

/// How often a connection looks at its streams.
const TICK: Duration = Duration::from_secs(1);

/// What the loop of a connection met.
enum Next<T> {
    Stream(Option<T>),
    Tick,
}

/// A stream that the role serves, counted while it lasts.
struct Held(Arc<AtomicUsize>);

impl Held {
    fn of(open: &Arc<AtomicUsize>) -> Held {
        open.fetch_add(1, Ordering::SeqCst);
        Held(open.clone())
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve the connection of `tls`, whose TLS chose `h2`, for a client at
/// `from` that asked for the name `sni`, until it ends.
pub async fn serve<S>(tls: S, cfg: Arc<Config>, sni: Option<String>, from: Option<IpAddr>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    builder
        .enable_connect_protocol()
        .max_concurrent_streams(STREAMS)
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW);
    let handshake = builder.handshake::<_, Bytes>(tls);
    let Ok(Ok(mut connection)) = tokio::time::timeout(super::listener::HANDSHAKE_WAIT, handshake).await else {
        return;
    };
    cfg.event("h2");
    let open = Arc::new(AtomicUsize::new(0));
    let (mut quiet, mut closing) = (Duration::ZERO, false);
    loop {
        let next = tokio::select! {
            next = connection.accept() => Next::Stream(next),
            () = tokio::time::sleep(TICK), if !closing => Next::Tick,
        };
        let (request, respond) = match next {
            Next::Tick => {
                quiet = if open.load(Ordering::SeqCst) == 0 { quiet + TICK } else { Duration::ZERO };
                if quiet >= IDLE {
                    connection.graceful_shutdown();
                    closing = true;
                }
                continue;
            }
            Next::Stream(Some(Ok(accepted))) => accepted,
            // The connection ended or failed; its streams end with it.
            Next::Stream(_) => break,
        };
        let held = Held::of(&open);
        let (cfg, sni) = (cfg.clone(), sni.clone());
        tokio::spawn(async move {
            stream::serve(request, respond, cfg, sni, from).await;
            drop(held);
        });
    }
}
