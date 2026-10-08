//! The socket seam: [`Transport`] over a `podssh-ws` session, and ⛔ **a
//! frame-queue fake under the same trait**.
//!
//! ⛔ **The trait is generic over one method, and that is the whole design.**
//! `podssh-transport` owns the protocol; `podssh-ws` owns RFC 6455 and TLS; and
//! nothing above this file needs a socket to be tested. E02's live acceptance
//! (`podssh doctor --relay`, `podssh ssh user@github.com`) ⛔ **cannot run from
//! this machine** — the CLI is E31 and does not exist, and a relay token must be
//! minted, used and discarded in one shell — ⛔ **so the framing half of E02 is
//! proven against [`FrameQueue`], and the socket half against `podssh-ws`'s own
//! suite.**

use std::collections::VecDeque;

use crate::closes::RelayClose;
use crate::control;
use crate::endpoint::{AddressFamily, EgressRoad, Knobs, LegTarget, RelayConfig, TOKEN_HEADER};
use crate::error::{HttpFailure, TransportError};
use crate::framing::legs::{encode_forward_frame, encode_node_frame, encode_operator_frame};
use crate::framing::SessionId;
use crate::transport::{Control, LegShape, Limits};

/// ⛔ **The one method that reaches a socket.** ⛔ **Everything else in this crate
/// is pure**, so a defect in the framing rules cannot hide behind a network that
/// is down.
#[allow(async_fn_in_trait)]
pub trait Socket {
    async fn send_binary(&mut self, payload: &[u8]) -> Result<(), TransportError>;
    async fn send_text(&mut self, text: &[u8]) -> Result<(), TransportError>;
    async fn recv(&mut self) -> Result<WireFrame, TransportError>;

    /// ⛔ **How many frames went out.** ⛔ Needed by a guard that asserts a
    /// *refused* frame never reached the wire: an error return alone does not
    /// prove the bytes were not written.
    fn sent_frames(&self) -> usize;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireFrame {
    Binary(Vec<u8>),
    Text(Vec<u8>),
}

/// ⛔ **The live socket, over `podssh-ws`.**
pub struct WsSocket<S> {
    session: S,
    limits: Limits,
    sent: usize,
}

impl<S: WsSession> WsSocket<S> {
    pub const fn new(session: S, limits: Limits) -> Self {
        Self { session, limits, sent: 0 }
    }

    /// ⛔ **The session underneath**, so a test can read what the adapter did
    /// with it. ⛔ Read-only: every write goes through the [ `Socket` ] methods,
    /// which is where the caps and the counting live.
    pub const fn session(&self) -> &S {
        &self.session
    }
}

/// ⛔ **What the `Socket` adapter needs from a live session.** An async trait
/// rather than a sync one, for the reason `Socket` already is: the live
/// session's methods are async (`RelaySession` holds its stream behind a
/// `tokio::sync::Mutex`), and a sync bridge would have to smuggle a runtime
/// into every call. `#[allow(async_fn_in_trait)]` matches `Socket` above.
///
/// ⛔ **The live implementor is `src/adapt.rs`** (`impl WsSession for
/// RelaySession` — C1). This file keeps no second copy of that impl: one
/// read path, one write path.
#[allow(async_fn_in_trait)]
pub trait WsSession {
    async fn send(&mut self, payload: &[u8]) -> Result<(), String>;
    /// ⛔ **A Pong, in answer to a Ping** (RFC 6455 §5.5.2). It is a separate
    /// method because a Pong is a control frame and not data: a session that
    /// could only send binary could not answer a Ping at all.
    async fn send_pong(&mut self, payload: &[u8]) -> Result<(), String>;
    async fn read(&mut self) -> Result<WsFrame, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// ⛔ **Opcode numbers from RFC 6455 §5.6**, duplicated here as four constants
/// rather than imported, because a fake and a real socket must agree on what a
/// text frame is and a live socket's module may still be in flux.
pub const OPCODE_TEXT: u8 = 0x1;
pub const OPCODE_BINARY: u8 = 0x2;
pub const OPCODE_PING: u8 = 0x9;
pub const OPCODE_PONG: u8 = 0xa;

impl<S: WsSession> Socket for WsSocket<S> {
    async fn send_binary(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        // ⛔ **The cap is enforced here, on the way out**, so an over-cap frame is
        // never put on the wire and the close that follows it.
        if payload.len() > self.limits.max_wire_frame {
            return Err(TransportError::Codec(
                crate::framing::CodecError::FrameTooLong {
                    got: payload.len(),
                    max: self.limits.max_wire_frame,
                },
            ));
        }
        self.session.send(payload).await.map_err(TransportError::Unexpected)?;
        self.sent += 1;
        Ok(())
    }

    async fn send_text(&mut self, text: &[u8]) -> Result<(), TransportError> {
        self.session.send(text).await.map_err(TransportError::Unexpected)?;
        self.sent += 1;
        Ok(())
    }

    async fn recv(&mut self) -> Result<WireFrame, TransportError> {
        loop {
            match self.session.read().await {
                Ok(frame) if frame.opcode == OPCODE_BINARY => {
                    return Ok(WireFrame::Binary(frame.payload))
                }
                Ok(frame) if frame.opcode == OPCODE_TEXT => return Ok(WireFrame::Text(frame.payload)),
                // ⛔ **A Ping is answered, not reported.** RFC 6455 §5.5.2: an
                // endpoint "MUST send a Pong frame in response" to a Ping,
                // "with an identical Application data" in it. ⛔ Treating it as
                // an error made the session fatal (`Unexpected` is
                // `Retry::Never`), so a peer that pinged lost the connection.
                Ok(frame) if frame.opcode == OPCODE_PING => {
                    self.session
                        .send_pong(&frame.payload)
                        .await
                        .map_err(TransportError::Unexpected)?;
                    self.sent += 1;
                }
                // ⛔ **A Pong is neither data nor an error**, so it is skipped
                // and the read continues: a control frame that carries no data
                // must not be delivered to a caller that asked for bytes.
                Ok(frame) if frame.opcode == OPCODE_PONG => {}
                Ok(frame) => {
                    return Err(TransportError::Unexpected(format!(
                        "opcode 0x{:x} is not a data frame",
                        frame.opcode
                    )))
                }
                Err(detail) => {
                    let _ = detail;
                    return Err(TransportError::Aborted { clean: false });
                }
            }
        }
    }

    fn sent_frames(&self) -> usize {
        self.sent
    }
}

/// ⛔ **The three shapes, over any [`Socket`].
///
/// ⛔ **`shape` is a field and not a parameter at the call site**, so a caller
/// cannot build an operator and forward frames through it by accident: the shape
/// decides which encoder runs, and the shape is fixed when the transport is.
pub struct Leg<S> {
    socket: S,
    shape: LegShape,
    limits: Limits,
    ready: bool,
}

impl<S: Socket> Leg<S> {
    pub const fn new(socket: S, shape: LegShape, limits: Limits) -> Self {
        Self { socket, shape, limits, ready: false }
    }

    pub const fn leg(&self) -> LegShape {
        self.shape
    }

    /// ⛔ **Mark a session readied.** ⛔ `ready` **gates a session, not the
    /// socket** — `reverse-node.md:171-173` — and on the node leg it is what
    /// keeps `1003 data before ready` off the wire.
    pub fn set_ready(&mut self, ready: bool) {
        self.ready = ready;
    }

    pub const fn is_ready(&self) -> bool {
        self.ready
    }

    /// ⛔ **How many frames this leg has put on the wire.** ⛔ A refused frame
    /// must not have reached it, and the only way to know is to count.
    pub fn sent_frames(&self) -> usize {
        self.socket.sent_frames()
    }

    /// ⛔ **Whether this leg has a control channel.** ⛔ `false` for the forward
    /// path, and ⛔ **that is not an EOF**: a caller that read it as one would
    /// tear down a healthy forward session on its first read.
    pub fn recv_control_is_absent(&self) -> bool {
        !self.shape.has_control_channel()
    }

    /// ⛔ **Write one data frame on this leg.**
    ///
    /// ⛔ **The node leg takes a `SessionId`; the other two do not take a
    /// parameter that could hold one.** That asymmetry is the whole defence
    /// against the silent operator-prefix defect, and it is in the signature
    /// rather than in a comment.
    pub async fn send_data(&mut self, id: Option<&SessionId>, payload: &[u8]) -> Result<(), TransportError> {
        match self.shape {
            LegShape::ReverseNode => {
                // ⛔ A node frame with no id cannot be expressed: `id` is `None`
                // only when a caller forgot, and that is refused here rather
                // than written as a bare payload the relay closes 1009 on.
                let id = id.ok_or_else(|| {
                    TransportError::Unexpected(
                        "the node leg cannot send without a session id: a bare node frame is \
                         closed 1009 bad multiplex frame"
                            .into(),
                    )
                })?;
                let frame = encode_node_frame(id, payload)?;
                self.socket.send_binary(&frame).await
            }
            LegShape::ReverseOperator => {
                let frame = encode_operator_frame(payload)?;
                self.socket.send_binary(&frame).await
            }
            LegShape::Forward => {
                let frame = encode_forward_frame(payload, self.limits.max_wire_frame)?;
                self.socket.send_binary(&frame).await
            }
        }
    }

    /// ⛔ **Write a control frame — ⛔ and only on the node leg.**
    ///
    /// ⛔ Spec lines 110-111: *"the operator receives text control frames and
    /// sends binary data frames only — an operator text frame closes the socket
    /// `1003`."* ⛔ **And the forward path has no control channel at all.**
    /// So this returns `Err` rather than sending, and the refusal names the code
    /// the relay would have answered with.
    pub async fn send_control(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > control::CONTROL_MAX {
            return Err(TransportError::Codec(
                crate::framing::CodecError::ControlFrameTooLong {
                    got: frame.len(),
                    max: control::CONTROL_MAX,
                },
            ));
        }
        if !self.shape.may_send_control() {
            return Err(TransportError::Unexpected(format!(
                "the {:?} leg is binary-only; a text frame closes it 1003 binary frames required",
                self.shape
            )));
        }
        self.socket.send_text(frame).await
    }

    /// ⛔ **Read the next data frame.** ⛔ On the node leg the id is stripped and
    /// returned beside the payload; ⛔ on the other two the payload is returned
    /// untouched, ⛔ **and on the operator leg nothing is ever subtracted** — the
    /// strip half is undocumented (`01-relay-protocol.md:352-355`) and the
    /// inbound frame is already payload.
    pub async fn recv_data(&mut self) -> Result<RecvFrame, TransportError> {
        match self.socket.recv().await? {
            WireFrame::Binary(bytes) => match self.shape {
                LegShape::ReverseNode => {
                    let (id, payload) = crate::framing::legs::decode_node_frame(&bytes)?;
                    Ok(RecvFrame { id: Some(id), payload: payload.to_vec() })
                }
                _ => Ok(RecvFrame { id: None, payload: bytes }),
            },
            // ⛔ A text frame arriving where data was expected is `1003` on the
            // operator leg and on the forward leg. It is refused here as well,
            // because podssh never sends one and a peer that does is a fault
            // this client cannot recover from by reading more.
            WireFrame::Text(_) => Err(TransportError::Unexpected(format!(
                "the {:?} leg received a text frame; its data channel is binary-only",
                self.shape
            ))),
        }
    }

    /// ⛔ **Read the next control frame, or `None` on a leg that has none.**
    ///
    /// ⛔ `None` is **not an error and not an EOF**: the forward path has no
    /// control channel, and a caller that treated `None` as "the socket ended"
    /// would tear down a healthy forward session on its first read.
    pub async fn recv_control(&mut self) -> Option<Result<Control, TransportError>> {
        match self.shape {
            LegShape::Forward => None,
            LegShape::ReverseNode => match self.socket.recv().await {
                Ok(WireFrame::Text(bytes)) => Some(parse_node_control(&bytes)),
                Ok(WireFrame::Binary(_)) => Some(Err(TransportError::Unexpected(
                    "the node leg received binary where a control frame was expected".into(),
                ))),
                Err(e) => Some(Err(e)),
            },
            LegShape::ReverseOperator => match self.socket.recv().await {
                Ok(WireFrame::Text(bytes)) => Some(parse_operator_control(&bytes)),
                Ok(WireFrame::Binary(_)) => Some(Err(TransportError::Unexpected(
                    "the operator leg received binary where a control frame was expected".into(),
                ))),
                Err(e) => Some(Err(e)),
            },
        }
    }
}

fn parse_node_control(bytes: &[u8]) -> Result<Control, TransportError> {
    match control::parse_inbound(bytes) {
        Ok(message) => Ok(Control::from_inbound(message)),
        Err(control::ControlError::Malformed { detail }) => Ok(Control::Malformed { detail }),
        Err(control::ControlError::Codec(e)) => Err(TransportError::Control(control::ControlError::Codec(e))),
        Err(e) => Err(TransportError::Control(e)),
    }
}

fn parse_operator_control(bytes: &[u8]) -> Result<Control, TransportError> {
    match control::parse_operator_control(bytes) {
        Ok(message) => Ok(Control::from_outbound(message)),
        Err(control::ControlError::Malformed { detail }) => Ok(Control::Malformed { detail }),
        Err(e) => Err(TransportError::Control(e)),
    }
}

/// ⛔ **What `recv_data` hands back.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvFrame {
    /// ⛔ **`None` on every leg but the node's.** ⛔ The operator's inbound frame
    /// is already payload and ⛔ **must not be shortened by 32** — the strip
    /// behaviour is undocumented, and a client that subtracts 32 eats the first
    /// 32 bytes of every message it receives.
    pub id: Option<SessionId>,
    pub payload: Vec<u8>,
}

/// ⛔ **A socket that is a queue. ⛔ This is the seam E02's acceptance runs on.**
///
/// ⛔ **It records the exact bytes that went out**, so a test can assert the wire
/// image rather than "something was sent". E02's `Prove` block is explicit that
/// *"a test that only checks that 'something was sent' cannot catch this class of
/// bug"*, and a fake that stored only a frame *count* would be exactly that
/// test.
#[derive(Debug, Default)]
pub struct FrameQueue {
    outbound: Vec<WireFrame>,
    inbound: VecDeque<WireFrame>,
    failure: Option<TransportError>,
}

impl FrameQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// ⛔ **Queue a binary frame as if the relay had sent it.**
    pub fn push_binary(&mut self, payload: Vec<u8>) {
        self.inbound.push_back(WireFrame::Binary(payload));
    }

    /// ⛔ **Queue a text frame as if the relay had sent it.**
    pub fn push_text(&mut self, payload: Vec<u8>) {
        self.inbound.push_back(WireFrame::Text(payload));
    }

    /// ⛔ **Make the next read fail, for a close-path test.**
    pub fn fail_with(&mut self, error: TransportError) {
        self.failure = Some(error);
    }

    /// ⛔ **The exact bytes that went out, in order.** ⛔ This is the assertion
    /// surface: `assert_eq!(wire(), expected)` and nothing weaker.
    pub fn wire(&self) -> &[WireFrame] {
        &self.outbound
    }

    /// ⛔ **The binary payloads that went out, in order, concatenated.** ⛔ For a
    /// test that cares about the byte image and not the frame boundaries —
    /// ⛔ **and frame boundaries carry no meaning**, so this is a legitimate view
    /// and not a weaker one.
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for frame in &self.outbound {
            if let WireFrame::Binary(bytes) = frame {
                out.extend_from_slice(bytes);
            }
        }
        out
    }

    pub fn wire_text(&self) -> Vec<String> {
        self.outbound
            .iter()
            .filter_map(|frame| match frame {
                WireFrame::Text(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
                WireFrame::Binary(_) => None,
            })
            .collect()
    }
}

impl Socket for FrameQueue {
    async fn send_binary(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        self.outbound.push(WireFrame::Binary(payload.to_vec()));
        Ok(())
    }

    async fn send_text(&mut self, text: &[u8]) -> Result<(), TransportError> {
        self.outbound.push(WireFrame::Text(text.to_vec()));
        Ok(())
    }

    fn sent_frames(&self) -> usize {
        self.outbound.len()
    }

    async fn recv(&mut self) -> Result<WireFrame, TransportError> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.inbound
            .pop_front()
            .ok_or(TransportError::Aborted { clean: true })
    }
}

/// ⛔ **Build the request for a leg. ⛔ No default relay path, and no token in the
/// URL.**
pub fn build(
    config: &RelayConfig,
    target: &LegTarget,
    token: &str,
) -> crate::endpoint::Endpoint {
    let _ = (
        AddressFamily::V4,
        EgressRoad::Vpc,
        Knobs::default(),
        TOKEN_HEADER,
    );
    crate::endpoint::endpoint(config, target, token)
}

/// ⛔ **The HTTP statuses a relay answers instead of upgrading**, named so a
/// caller can branch without parsing a string.
pub fn http_failure(status: u16) -> TransportError {
    TransportError::Http(HttpFailure::from_status(status))
}

/// ⛔ **A close, as `podssh-ws` hands one over.**
pub fn closed(code: u16, reason: &str, clean: bool) -> TransportError {
    TransportError::Closed(RelayClose { code, reason: reason.to_string(), clean })
}