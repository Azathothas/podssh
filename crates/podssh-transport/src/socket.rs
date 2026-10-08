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

use crate::adapt::SessionError;
use crate::closes::RelayClose;
use crate::control;
use crate::endpoint::{AddressFamily, EgressRoad, Knobs, LegTarget, RelayConfig, TOKEN_HEADER};
use crate::error::{Asked, HttpFailure, TransportError};
use crate::framing::legs::{encode_forward_frame, encode_node_frame, encode_operator_frame};
use crate::framing::SessionId;
use crate::sessions::{
    Outbound, OperatorState, Sessions, BAD_MULTIPLEX_FRAME, BINARY_FRAMES_REQUIRED, WAIT_FOR_READY,
};
use crate::transport::{Control, Inbound, LegShape, Limits};

pub use crate::queue::FrameQueue;

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
    /// Set by a Close or a read error. A later read returns the same error
    /// and never reads the socket again: after a Close nothing more is valid.
    ended: Option<Ended>,
}

/// How the socket ended, kept to answer each later read the same way.
#[derive(Debug, Clone)]
enum Ended {
    Closed(RelayClose),
    Failed(SessionError),
}

impl Ended {
    fn error(&self) -> TransportError {
        match self {
            Ended::Closed(c) => closed(c.code, &c.reason, c.clean),
            Ended::Failed(e) => lost(e),
        }
    }
}

/// A failure of the session, by its class (T-069). A frame or a message that
/// RFC 6455 forbids is not repaired by sending the same way again:
/// `Unexpected`, never retried. Each other class is a link that broke (a
/// socket error, no data, a stalled write, unanswered pings, an end with no
/// Close): `Aborted`, after which a caller may reconnect. The text is kept,
/// safe to print, because it is what a user can act on.
pub fn lost(e: &SessionError) -> TransportError {
    let detail = crate::adapt::one_line(&e.to_string());
    match e {
        SessionError::Protocol(_) | SessionError::TooLarge(_) => TransportError::Unexpected(detail),
        _ => TransportError::Aborted { clean: false, detail },
    }
}

impl<S: WsSession> WsSocket<S> {
    pub const fn new(session: S, limits: Limits) -> Self {
        Self { session, limits, sent: 0, ended: None }
    }

    /// Record how the socket ended, and return that error.
    fn end(&mut self, ended: Ended) -> TransportError {
        let error = ended.error();
        self.ended = Some(ended);
        error
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
    async fn send(&mut self, payload: &[u8]) -> Result<(), SessionError>;
    /// ⛔ **A Pong, in answer to a Ping** (RFC 6455 §5.5.2). It is a separate
    /// method because a Pong is a control frame and not data: a session that
    /// could only send binary could not answer a Ping at all.
    async fn send_pong(&mut self, payload: &[u8]) -> Result<(), SessionError>;
    /// A text frame: the node leg's JSON control. It takes `&str` because
    /// RFC 6455 allows only UTF-8 in a text frame; the relay reads a binary
    /// node frame as a session id and closes `1003 bad multiplex id`.
    async fn send_text(&mut self, text: &str) -> Result<(), SessionError>;
    async fn read(&mut self) -> Result<WsFrame, SessionError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// ⛔ **Opcode numbers from RFC 6455 §5.6**, duplicated here as five constants
/// rather than imported, because a fake and a real socket must agree on what a
/// text frame is and a live socket's module may still be in flux.
pub const OPCODE_TEXT: u8 = 0x1;
pub const OPCODE_BINARY: u8 = 0x2;
pub const OPCODE_CLOSE: u8 = 0x8;
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
        self.session.send(payload).await.map_err(|e| lost(&e))?;
        self.sent += 1;
        Ok(())
    }

    async fn send_text(&mut self, text: &[u8]) -> Result<(), TransportError> {
        // Refused before the wire, as `send_binary` refuses: the relay closes
        // a node control over 4 KiB, and a text frame that is not UTF-8 fails
        // the connection (RFC 6455 section 8.1).
        if text.len() > control::CONTROL_MAX {
            return Err(TransportError::Codec(crate::framing::CodecError::ControlFrameTooLong {
                got: text.len(),
                max: control::CONTROL_MAX,
            }));
        }
        let text = std::str::from_utf8(text).map_err(|e| {
            TransportError::Codec(crate::framing::CodecError::ControlNotUtf8 { valid_up_to: e.valid_up_to() })
        })?;
        self.session.send_text(text).await.map_err(|e| lost(&e))?;
        self.sent += 1;
        Ok(())
    }

    async fn recv(&mut self) -> Result<WireFrame, TransportError> {
        if let Some(ended) = &self.ended {
            return Err(ended.error());
        }
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
                        .map_err(|e| lost(&e))?;
                    self.sent += 1;
                }
                // ⛔ **A Pong is neither data nor an error**, so it is skipped
                // and the read continues: a control frame that carries no data
                // must not be delivered to a caller that asked for bytes.
                Ok(frame) if frame.opcode == OPCODE_PONG => {}
                // A Close keeps its code and reason, because the close table
                // branches on both: `1001 pair expired` and `1001 operator
                // stopped reverse relay` need opposite actions. `podssh-ws`
                // has already echoed it. RFC 6455 section 7.1.5: a Close with
                // no status code is read as 1005.
                Ok(frame) if frame.opcode == OPCODE_CLOSE => {
                    let (code, reason) = crate::adapt::close_code_and_reason(&frame.payload);
                    let close = RelayClose { code: code.unwrap_or(1005), reason, clean: true };
                    return Err(self.end(Ended::Closed(close)));
                }
                Ok(frame) => {
                    return Err(TransportError::Unexpected(format!(
                        "opcode 0x{:x} is not a data frame",
                        frame.opcode
                    )))
                }
                // The class decides what the caller may do; `lost` keeps the text.
                Err(e) => return Err(self.end(Ended::Failed(e))),
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
    /// The sessions of the node leg, by id; empty on the other two.
    sessions: Sessions,
    /// The one session of the operator leg; nothing reads it on the others.
    operator: OperatorState,
}

impl<S: Socket> Leg<S> {
    pub const fn new(socket: S, shape: LegShape, limits: Limits) -> Self {
        Self { socket, shape, limits, sessions: Sessions::new(), operator: OperatorState::Waiting }
    }

    pub const fn leg(&self) -> LegShape {
        self.shape
    }

    /// The socket underneath, read-only, so a test can see which frame type
    /// each write became.
    pub const fn socket(&self) -> &S {
        &self.socket
    }

    /// The sessions of the node leg, as the relay opened them and the node
    /// readied them. `ready` gates a session, not the socket. The node's
    /// runner reads this state; it keeps no copy of its own.
    pub const fn sessions(&self) -> &Sessions {
        &self.sessions
    }

    /// Where the one session of the operator leg is.
    pub const fn operator_state(&self) -> OperatorState {
        self.operator
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
                let id = id.ok_or(TransportError::Refused(BAD_MULTIPLEX_FRAME))?;
                // Data for a session that is not readied closes the whole node
                // socket, so it is refused before a byte reaches it.
                self.sessions.may_send_data(id).map_err(TransportError::Refused)?;
                let frame = encode_node_frame(id, payload)?;
                self.socket.send_binary(&frame).await
            }
            LegShape::ReverseOperator => {
                match self.operator {
                    OperatorState::Readied => {}
                    OperatorState::Waiting => return Err(TransportError::Refused(WAIT_FOR_READY)),
                    OperatorState::Closed => {
                        return Err(TransportError::Unexpected(
                            "the node closed this session; the operator sends nothing after it".into(),
                        ))
                    }
                }
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
        match self.shape {
            LegShape::ReverseNode => {}
            LegShape::ReverseOperator => return Err(TransportError::Refused(BINARY_FRAMES_REQUIRED)),
            LegShape::Forward => {
                return Err(TransportError::Unexpected(
                    "the forward leg has no control channel; it carries binary frames only".into(),
                ))
            }
        }
        // Checked as the relay checks it, so that no frame of this crate
        // closes the node socket: JSON, a known type, a valid id, and a
        // `ready` only for a session that is open.
        let message = crate::sessions::check_outbound(frame).map_err(TransportError::Refused)?;
        if let Outbound::Ready(id) = &message {
            self.sessions.may_send_ready(id).map_err(TransportError::Refused)?;
        }
        self.socket.send_text(frame).await?;
        // Only after the send: a refused or failed frame changes nothing.
        match message {
            Outbound::Ready(id) => self.sessions.readied(id),
            Outbound::Reject(id) | Outbound::Close(id) => self.sessions.closed(&id),
        }
        Ok(())
    }

    /// The next frame on this leg, data or control, in the order of the
    /// socket. One reader for both: the node socket carries them mixed, and a
    /// reader of one kind would lose each frame of the other.
    ///
    /// ⛔ On the node leg the id is stripped from a data frame and returned
    /// beside the payload; on the other two the payload is returned untouched,
    /// ⛔ **and on the operator leg nothing is ever subtracted** — the strip
    /// half is undocumented (`01-relay-protocol.md:352-355`) and the inbound
    /// frame is already payload. A control frame moves its session before it
    /// is returned. A text frame on the forward leg is an error: that path has
    /// no control channel, and a peer that sends one is a fault this client
    /// cannot recover from by reading more.
    pub async fn recv(&mut self) -> Result<Inbound, TransportError> {
        match self.socket.recv().await? {
            WireFrame::Binary(bytes) => match self.shape {
                LegShape::ReverseNode => {
                    let (id, payload) = crate::framing::legs::decode_node_frame(&bytes)?;
                    Ok(Inbound::Data { id: Some(id), payload: payload.to_vec() })
                }
                _ => Ok(Inbound::Data { id: None, payload: bytes }),
            },
            WireFrame::Text(bytes) => {
                let control = match self.shape {
                    LegShape::Forward => {
                        return Err(TransportError::Unexpected(
                            "the forward leg received a text frame; its data channel is binary-only"
                                .into(),
                        ))
                    }
                    LegShape::ReverseNode => parse_node_control(&bytes)?,
                    LegShape::ReverseOperator => parse_operator_control(&bytes)?,
                };
                self.note(&control);
                Ok(Inbound::Control(control))
            }
        }
    }

    /// A control frame that arrived moves its session: `open` and `close` on
    /// the node leg; `ready`, then `reject` or `close`, on the operator leg.
    fn note(&mut self, control: &Control) {
        match (self.shape, control) {
            (LegShape::ReverseNode, Control::Open { id }) => self.sessions.opened(*id),
            (LegShape::ReverseNode, Control::Close { id, .. }) => self.sessions.closed(id),
            (LegShape::ReverseOperator, Control::Ready { .. }) if self.operator == OperatorState::Waiting => {
                self.operator = OperatorState::Readied
            }
            (LegShape::ReverseOperator, Control::Reject { .. } | Control::Close { .. }) => {
                self.operator = OperatorState::Closed
            }
            _ => {}
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

/// ⛔ **Build the request for a leg. ⛔ No default relay path, and no token in the
/// URL.**
pub fn build(
    config: &RelayConfig,
    target: &LegTarget,
    token: &str,
) -> Result<crate::endpoint::Endpoint, TransportError> {
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
pub fn http_failure(status: u16, body: &str, asked: Asked) -> TransportError {
    // The body comes from the network: printed only through the one
    // definition of safe text, and cut on a character boundary.
    let printable = crate::control::truncate_reason(&crate::adapt::one_line(body));
    TransportError::Http { failure: HttpFailure::from_answer(status, body, asked), body: printable }
}

/// ⛔ **A close, as `podssh-ws` hands one over.**
pub fn closed(code: u16, reason: &str, clean: bool) -> TransportError {
    TransportError::Closed(RelayClose { code, reason: reason.to_string(), clean })
}