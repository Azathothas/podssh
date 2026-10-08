//! ⛔ **C1: the live session behind the seam, and the constants both crates
//! share.**
//!
//! `podssh-transport` owns the protocol and `podssh-ws` owns RFC 6455; the two
//! meet at `impl WsSession for RelaySession` (`src/adapt.rs`). A RelaySession
//! cannot be constructed without a network — its fields are private and
//! `connect` dials — so no test here holds one. What is asserted instead:
//!
//! 1. the impl exists (delete it and this file does not compile, which fails
//!    the suite rather than passing it), and
//! 2. the opcode numbers duplicated in `socket.rs` (deliberately, per its
//!    `:89-91`) still agree with `podssh-ws`'s — a fake and a real socket
//!    that disagree on what a text frame is corrupt each other silently.

use podssh_transport::socket::{
    WsSession, OPCODE_BINARY, OPCODE_PING, OPCODE_PONG, OPCODE_TEXT,
};
use podssh_ws::client::RelaySession;
use podssh_ws::frame as ws_frame;

/// ⛔ **C1 exists.** `RelaySession` satisfies the seam's trait. If the impl in
/// `src/adapt.rs` is deleted, or its signatures drift from the trait, this
/// fails to compile — and a suite that does not compile is red, not green.
#[test]
fn relay_session_implements_ws_session() {
    fn assert_ws_session<T: WsSession>() {}
    assert_ws_session::<RelaySession>();
}

/// ⛔ **The duplicated opcodes agree.** `socket.rs` keeps its own constants
/// rather than importing them; this is the test that keeps the two copies
/// one decision.
#[test]
fn both_crates_agree_on_opcodes() {
    assert_eq!(OPCODE_TEXT, ws_frame::OPCODE_TEXT);
    assert_eq!(OPCODE_BINARY, ws_frame::OPCODE_BINARY);
    assert_eq!(OPCODE_PING, ws_frame::OPCODE_PING);
    assert_eq!(OPCODE_PONG, ws_frame::OPCODE_PONG);
}
