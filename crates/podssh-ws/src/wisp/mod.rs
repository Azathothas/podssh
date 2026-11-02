//! A Wisp client (T-438): many TCP streams over one WebSocket, by Mercury
//! Workshop's protocol, version 2 and version 1, written from its document
//! (MercuryWorkshop/wisp-protocol:protocol.md). The server dials the host
//! and the port that each CONNECT names; its CONTINUE says how many DATA
//! packets it can buffer for a stream, and this side sends none past that
//! credit; its CLOSE gives a reason. Version 2 opens with an INFO from each
//! side, and only where the upgrade offers a protocol; a server that sends
//! its CONTINUE first speaks version 1, with no INFO. Each stream is given
//! to its caller as a byte stream ([`WispStream`]).
//!
//! The dial is that of a WebSocket by its URL ([`crate::url`]): TLS checked
//! for the server's name, through the proxy of the environment, one
//! connection, and no token. A forwarder of `podssh_ws::forwarder` whose
//! template is `wisp+wss://HOST/PATH/` takes this road ([`forward`]).

pub(crate) mod forward;
mod handshake;
mod mux;
pub mod packet;
mod stream;

use std::sync::Arc;
use std::time::Duration;

pub use handshake::{answer, Opened};
pub use packet::Reason;
pub use stream::WispStream;

use crate::client::ConnectError;
use crate::dial::ProxyChoice;
use crate::forwarder::Note;
use crate::tls::Trust;
use crate::url::{self, WsUrl};

/// The protocol that the upgrade offers. A server speaks version 2 only
/// where the request names one, whatever its value; `wisp-v2` is the value
/// of Mercury Workshop's own client (read in
/// MercuryWorkshop/wisp-js:src/client/connection.mjs).
pub const PROTOCOL: &str = "wisp-v2";

/// The newest version that this side speaks: 2.1, the document's.
pub const VERSION: (u8, u8) = (2, 1);

/// The largest DATA payload sent: 32 KiB, as each forwarder's frame.
const CHUNK: usize = crate::frame::FORWARD_SEND_PAYLOAD;

/// The largest message taken from a server, which publishes no size:
/// wisp-server-python sends what one read of 64 KiB gave.
pub const RECEIVE_CAP: usize = 1024 * 1024;

/// The most characters of a server's words that a note shows.
const NOTE_CHARS: usize = 200;

/// What a connection needs beside its URL.
pub struct Connect<'a> {
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// Bound on the dial, on the upgrade, and on the opening.
    pub timeout: Duration,
    /// Where the server's message of the day and its other words go.
    pub note: Note,
}

/// Why a connection or a stream carried nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WispError {
    /// The dial or the upgrade, as [`crate::url::dial`] gives it.
    Connect(ConnectError),
    /// The opening: a packet out of turn, an extension that this side
    /// cannot meet, or no opening within the bound.
    Opening(String),
    /// The server's CLOSE of the connection, on stream 0.
    Refused(Reason),
    /// The server's CLOSE of a stream, with its reason.
    Closed(Reason),
    /// The WebSocket's Close.
    Gone { code: Option<u16>, reason: String },
    /// A failure of the WebSocket, or a target that cannot go.
    Failed(String),
}

impl std::fmt::Display for WispError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WispError::Connect(e) => write!(f, "{e}"),
            WispError::Opening(why) | WispError::Failed(why) => f.write_str(why),
            WispError::Refused(r) => write!(f, "the Wisp server refused the connection: {r}"),
            WispError::Closed(r) => write!(f, "the Wisp server closed the stream: {r}"),
            WispError::Gone { code, reason } => {
                let code = code.map_or_else(|| "no code".to_string(), |c| c.to_string());
                match reason.is_empty() {
                    true => write!(f, "the Wisp server closed the WebSocket: {code}"),
                    false => write!(f, "the Wisp server closed the WebSocket: {code} {reason}"),
                }
            }
        }
    }
}

impl std::error::Error for WispError {}

/// How a stream ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The server's CLOSE: [`Reason::VOLUNTARY`] when the target closed.
    Closed(Reason),
    /// This side's CLOSE.
    ClosedHere,
    /// The WebSocket's Close, which ends each stream.
    Gone { code: Option<u16>, reason: String },
    /// A failure of the WebSocket.
    Failed(String),
}

impl End {
    fn into_error(self) -> WispError {
        match self {
            End::Closed(r) => WispError::Closed(r),
            End::ClosedHere => WispError::Failed("this side closed the stream".into()),
            End::Gone { code, reason } => WispError::Gone { code, reason },
            End::Failed(why) => WispError::Failed(why),
        }
    }
}

/// Called once, with a stream's end, before its caller reads the end of its
/// bytes: a forwarder's status is set by it, so that the line of an end is
/// there when the session sees it.
pub(crate) type OnEnd = Box<dyn Fn(&End) + Send + Sync>;

/// A server's words for a line: one line, made safe for a terminal, short.
fn note_text(bytes: &[u8]) -> String {
    let line = crate::text::one_line(&String::from_utf8_lossy(bytes));
    match line.char_indices().nth(NOTE_CHARS) {
        Some((at, _)) => format!("{}...", &line[..at]),
        None => line,
    }
}

/// A Wisp connection: one WebSocket, which closes once this handle and
/// each of its streams are gone.
pub struct Wisp {
    shared: Arc<mux::Shared>,
}

impl std::fmt::Debug for Wisp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wisp").field("opened", &self.shared.opened).finish()
    }
}

impl Wisp {
    /// Dial `url`, upgrade offering [`PROTOCOL`], and open: version 2 when
    /// the server sends its INFO, version 1 when it sends its CONTINUE. A
    /// server that refuses the offer of a protocol (HTTP 400) is dialed once
    /// more with none, as version 1 asks none.
    pub async fn connect(url: &WsUrl, how: &Connect<'_>) -> Result<Wisp, WispError> {
        let idle = Some(crate::client::DEFAULT_IDLE_TIMEOUT);
        let offered = url::dial_offering(url, Some(PROTOCOL), how.trust, how.proxy, how.timeout, idle).await;
        let session = match offered {
            Ok(session) => session,
            Err(ConnectError::Refused { status: 400, .. }) => {
                url::dial(url, how.trust, how.proxy, how.timeout, idle).await.map_err(WispError::Connect)?
            }
            Err(e) => return Err(WispError::Connect(e)),
        };
        let session = session.naming("the Wisp server");
        session.set_receive_cap(RECEIVE_CAP);
        let opened = handshake::open(&session, how.timeout).await?;
        if let Some(motd) = &opened.motd {
            (how.note)(&format!("the Wisp server's message: {motd}"));
        }
        let shared = Arc::new(mux::Shared::new(session, opened, how.note.clone()));
        tokio::spawn(mux::read(shared.clone()));
        Ok(Wisp { shared })
    }

    /// What the opening settled: the version, the buffer of each stream,
    /// whether the server confirms a stream, its message of the day.
    pub fn opened(&self) -> &Opened {
        &self.shared.opened
    }

    /// Whether the server confirms each stream once its target's socket is
    /// open (stream open confirmation, on both sides' INFO).
    pub fn confirms(&self) -> bool {
        self.shared.opened.confirm
    }

    /// A stream to `host:port`: its CONNECT is sent, and its bytes may go at
    /// once, within the buffer of the opening. With `close_at_end`, the end
    /// of the caller's bytes sends a CLOSE (Wisp has no half-close); else
    /// the stream waits for the server's CLOSE, as the target may still
    /// answer. The host is checked as each target of the relay is.
    pub async fn open(&self, host: &str, port: u16, close_at_end: bool) -> Result<WispStream, WispError> {
        self.open_noting(host, port, close_at_end, None).await
    }

    /// [`Wisp::open`], with `on_end` called at the stream's end.
    pub(crate) async fn open_noting(
        &self,
        host: &str,
        port: u16,
        close_at_end: bool,
        on_end: Option<OnEnd>,
    ) -> Result<WispStream, WispError> {
        let opening = self.shared.open(host, port, close_at_end, on_end).await?;
        Ok(WispStream::new(opening, self.shared.clone()))
    }
}

impl Drop for Wisp {
    fn drop(&mut self) {
        self.shared.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_says_the_server_and_its_reason() {
        assert_eq!(
            WispError::Closed(Reason::REFUSED).to_string(),
            "the Wisp server closed the stream: 0x44, the destination refused the connection"
        );
        assert_eq!(
            WispError::Refused(Reason::INCOMPATIBLE).to_string(),
            "the Wisp server refused the connection: 0x04, incompatible extensions"
        );
        let gone = WispError::Gone { code: Some(1011), reason: "upstream".into() };
        assert_eq!(gone.to_string(), "the Wisp server closed the WebSocket: 1011 upstream");
        assert_eq!(End::Closed(Reason::BLOCKED).into_error(), WispError::Closed(Reason(0x48)));
    }

    #[test]
    fn a_note_is_one_safe_short_line() {
        assert_eq!(note_text(b"Welcome\r\n\x1b[2Jto Wisp"), "Welcome [2Jto Wisp");
        assert_eq!(note_text("y".repeat(300).as_bytes()).len(), NOTE_CHARS + 3);
    }
}
