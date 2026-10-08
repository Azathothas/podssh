//! ⛔ **C1: the live session behind the seam.**
//!
//! `impl WsSession for podssh_ws::client::RelaySession` — the one line the
//! relay path exists for. `podssh-transport` owns the protocol,
//! `podssh-ws` owns RFC 6455 and TLS, and this file is the whole of where
//! they meet: four one-line forwards and the opcode mapping, and nothing
//! else may learn both sides.
//!
//! ⛔ **Why each forward is shaped the way it is:**
//!
//! * `send` → `send_binary`: the seam's binary write is the session's binary
//!   write. `WsSocket` enforces the cap before this is reached, so no second
//!   check lives here — two checks drift, and the wrong one is trusted.
//! * `send_pong` → `send_pong`: the Pong `WsSocket::recv` answers a Ping
//!   with. `RelaySession::read_frame` already answers Pings it meets while
//!   reading, so a Ping that arrives between two `read` calls is answered at
//!   most twice — harmless, and RFC 6455 answers MUSTs, not counts.
//! * `send_text` → `send_text`: the node leg's JSON control must leave as a
//!   text frame. A binary one is read by the relay as a session id, and the
//!   relay closes the node `1003 bad multiplex id`.
//! * `read` → `read_frame`, mapped to [`WsFrame`]. Only `opcode` and
//!   `payload` cross: `fin` is always true on the frames this client reads,
//!   and carrying it would invite a caller to branch on it.
//!
//! * `close_code_and_reason` and `one_line`: the Close parser and the one
//!   definition of text that is safe to print, lent from `podssh-ws` to
//!   `WsSocket::recv` and to the close table, so neither crate has a second
//!   copy and no other module names `podssh-ws`.
//!
//! ⛔ **What this file does NOT do.** It does not construct a session
//! (`connect` dials; C4 owns the runner), it does not map Close frames to
//! [`crate::closes::RelayClose`] (`WsSocket::recv` does, with the parser
//! lent here), and it never sees the token (`connect` took it; E12 owns it
//! from there).

use podssh_ws::client::RelaySession;

use crate::socket::{WsFrame, WsSession};

/// The status code and reason of a Close payload; the reason is already safe
/// to print.
pub(crate) fn close_code_and_reason(payload: &[u8]) -> (Option<u16>, String) {
    podssh_ws::session::close_code_and_reason(payload)
}

/// Text from the network, made safe to print on one line.
pub(crate) fn one_line(text: &str) -> String {
    podssh_ws::text::one_line(text)
}

/// ⛔ **C1, as an impl.** Four forwards and the opcode mapping. If the live
/// session's signatures drift, this file — not a caller — is what fails to
/// compile, and `tests/adapt.rs` turns that into a red suite.
impl WsSession for RelaySession {
    async fn send(&mut self, payload: &[u8]) -> Result<(), String> {
        RelaySession::send_binary(self, payload).await
    }

    async fn send_pong(&mut self, payload: &[u8]) -> Result<(), String> {
        RelaySession::send_pong(self, payload).await
    }

    async fn send_text(&mut self, text: &str) -> Result<(), String> {
        RelaySession::send_text(self, text).await
    }

    async fn read(&mut self) -> Result<WsFrame, String> {
        RelaySession::read_frame(self)
            .await
            .map(|frame| WsFrame { opcode: frame.opcode, payload: frame.payload })
    }
}
