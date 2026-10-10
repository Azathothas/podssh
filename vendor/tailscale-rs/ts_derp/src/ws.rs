//! DERP over WebSocket.
//!
//! The DERP framing in [`crate::frame`] and the handshake in [`crate::Client`]
//! are transport-agnostic: they operate on any [`AsyncRead`] + [`AsyncWrite`]
//! stream. This module supplies one, dialling a DERP server the way the Go
//! client does when it is built for WebSockets (`derp/derphttp`'s
//! `dialWebsocket` and `net/wsconn`):
//!
//! 1. TCP to `hostname:port`, then TLS with the hostname as the SNI name.
//! 2. An RFC 6455 client handshake carrying `Sec-WebSocket-Protocol: derp`.
//! 3. A byte-stream adapter in which one `poll_write` is one binary message,
//!    and reads span message boundaries.
//!
//! The DERP frame codec runs unchanged on top of [`WsIo`], so a DERP server
//! reachable only over a WebSocket upgrade (for example behind an HTTP/443-only
//! egress path) is usable through [`crate::Client::handshake`].

use core::task::{Context, Poll};
use std::io;
use std::pin::Pin;

use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message};
use tokio_tungstenite::tungstenite::ClientRequestBuilder;
use tokio_tungstenite::WebSocketStream;
use ts_tls_util::{ServerName, TlsStream};

use crate::Error;

/// The WebSocket subprotocol that DERP-over-WebSocket uses.
pub const SUBPROTOCOL: &str = "derp";

/// A DERP connection carried over a WebSocket, exposed as a byte stream.
///
/// Writes are binary messages: each `poll_write` accepts its whole buffer as
/// one message. Reads concatenate the payloads of consecutive binary messages.
/// A close frame is reported as an error carrying the WebSocket close code and
/// reason, so the caller can distinguish a refusal from a transport failure.
pub struct WsIo {
    stream: WebSocketStream<TlsStream<TcpStream>>,
    /// Payload of the binary message currently being drained.
    read_buf: Vec<u8>,
    /// How much of `read_buf` has already been handed to the caller.
    read_off: usize,
}

/// Dial a DERP server over WebSocket, offering the `derp` subprotocol.
///
/// The URL dialled is `wss://{hostname}:{port}/derp`, matching the Go client's
/// derivation from a DERP map entry.
pub async fn connect(hostname: &str, port: u16) -> Result<WsIo, Error> {
    connect_with_subprotocol(hostname, port, Some(SUBPROTOCOL)).await
}

/// Dial a DERP server over WebSocket, offering `subprotocol` when it is set.
///
/// Passing `None` is a negative control: a relay that requires the subprotocol
/// refuses the upgrade.
pub async fn connect_with_subprotocol(
    hostname: &str,
    port: u16,
    subprotocol: Option<&str>,
) -> Result<WsIo, Error> {
    // Through the proxy when one applies, within a bound either way, as each
    // other dial site (podssh's patch 0017).
    let tcp = ts_http_util::proxy::dial(hostname, port).await?;

    let server_name = ServerName::try_from(hostname.to_owned()).map_err(|e| {
        tracing::error!(error = %e, %hostname, "invalid DERP server hostname");
        Error::IoFailure(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid DERP server hostname",
        ))
    })?;
    let tls = ts_tls_util::connect(server_name, tcp).await?;

    let uri: Uri = format!("wss://{hostname}:{port}/derp")
        .parse()
        .map_err(tokio_tungstenite::tungstenite::Error::from)?;
    let mut request = ClientRequestBuilder::new(uri);
    if let Some(subprotocol) = subprotocol {
        request = request.with_sub_protocol(subprotocol);
    }

    let (stream, response) =
        tokio_tungstenite::client_async(request.into_client_request()?, tls).await?;
    tracing::debug!(
        status = %response.status(),
        %hostname,
        port,
        subprotocol = subprotocol.unwrap_or(""),
        "derp websocket upgrade complete"
    );

    Ok(WsIo {
        stream,
        read_buf: Vec::new(),
        read_off: 0,
    })
}

impl AsyncRead for WsIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if this.read_off < this.read_buf.len() {
                let available = &this.read_buf[this.read_off..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.read_off += n;
                if this.read_off == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_off = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut this.stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    this.read_buf = data;
                    this.read_off = 0;
                }
                Poll::Ready(Some(Ok(Message::Ping(_)))) => {
                    // tungstenite queues the RFC 6455 Pong reply itself; send it
                    // now if the socket is writable, otherwise on the next write.
                    if let Poll::Ready(Err(e)) = Pin::new(&mut this.stream).poll_flush(cx) {
                        return Poll::Ready(Err(ws_io_error(e)));
                    }
                }
                Poll::Ready(Some(Ok(Message::Pong(_) | Message::Frame(_)))) => {}
                Poll::Ready(Some(Ok(Message::Text(_)))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DERP over WebSocket expects binary messages, got a text message",
                    )));
                }
                Poll::Ready(Some(Ok(Message::Close(frame)))) => {
                    return Poll::Ready(Err(close_error(frame)));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(ws_io_error(e))),
            }
        }
    }
}

impl AsyncWrite for WsIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();
        match Pin::new(&mut this.stream).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(ws_io_error(e))),
            Poll::Pending => return Poll::Pending,
        }

        // One whole poll_write is one DERP frame is one binary message.
        match Pin::new(&mut this.stream).start_send(Message::Binary(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(ws_io_error(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx).map_err(ws_io_error)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_close(cx).map_err(ws_io_error)
    }
}

/// A WebSocket close as the far end sent it (podssh's patch 0019). It travels inside the
/// `io::Error` that a read returns, so a caller can tell a refusal, such as a relay's 1008 "not
/// authorized", from a broken transport: [`crate::Error::ws_close`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsClose {
    /// The close code, or `None` when the far end sent no close frame.
    pub code: Option<u16>,
    /// The close reason, as sent.
    pub reason: String,
}

impl core::fmt::Display for WsClose {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.code {
            Some(code) => write!(f, "websocket closed: code={code} reason={:?}", self.reason),
            None => write!(f, "websocket closed: no close frame"),
        }
    }
}

impl std::error::Error for WsClose {}

/// Describe a received close frame, including its code and reason.
fn close_error(frame: Option<CloseFrame<'static>>) -> io::Error {
    let close = match frame {
        Some(frame) => WsClose {
            code: Some(u16::from(frame.code)),
            reason: frame.reason.to_string(),
        },
        None => WsClose {
            code: None,
            reason: String::new(),
        },
    };
    io::Error::new(io::ErrorKind::ConnectionAborted, close)
}

fn ws_io_error(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::other(e)
}

#[cfg(test)]
mod tests {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    use super::*;

    /// podssh's patch 0019: a close keeps its code and its reason through `crate::Error`, and
    /// its text is the one that it always had.
    #[test]
    fn a_close_keeps_its_code_and_reason() {
        let frame = CloseFrame {
            code: CloseCode::Policy,
            reason: "not authorized".into(),
        };
        let e = crate::Error::from(close_error(Some(frame)));
        assert_eq!(
            e.ws_close(),
            Some(&WsClose {
                code: Some(1008),
                reason: "not authorized".to_string()
            })
        );
        assert_eq!(
            e.to_string(),
            "websocket closed: code=1008 reason=\"not authorized\""
        );
        let e = crate::Error::from(close_error(None));
        assert_eq!(e.ws_close().and_then(|c| c.code), None);
        assert_eq!(e.to_string(), "websocket closed: no close frame");
    }
}
