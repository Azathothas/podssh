//! One `Transport` trait, three shapes, and the limits each shape carries.
//!
//! ⛔ **The trait moves bytes and knows nothing else.** `RULES.md:138-142`:
//! *"The transport is protocol-agnostic. `podssh-transport` moves bytes and must
//! never learn what protocol it is carrying … a design that special-cases one of
//! them inside the transport has already gone wrong."* ⛔ **`send` takes
//! `&[u8]` on every shape below**, and no method anywhere in this crate names
//! SSH.

use crate::control::{Hello, NodeInbound, NodeOutbound};
use crate::endpoint::LegTarget;
use crate::error::TransportError;
use crate::framing::SessionId;

/// ⛔ **One frame in, one frame out.** ⛔ **Frame boundaries carry no meaning** —
/// spec line 210 copies payload bytes verbatim and `01-relay-protocol.md:419-421`
/// says podssh must reassemble a byte stream rather than expect one SSH message
/// per frame — so a caller receives frames and joins them itself.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// ⛔ **Which leg this is**, so a caller never has to be told twice.
    fn leg(&self) -> LegShape;

    async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError>;

    /// ⛔ **The next frame, or the close that ended the socket.** A text frame is
    /// returned through [`Transport::next_control`] on the legs that have one,
    /// and never appears as a data frame on any leg.
    async fn recv(&mut self) -> Result<Vec<u8>, TransportError>;

    /// ⛔ **`None` on the legs that carry no control channel**, which is the
    /// forward leg and ⛔ **is not an error**: the forward path has no `hello`, no
    /// `open`, no `ready`, and no text frame at all.
    async fn next_control(&mut self) -> Option<Result<Control, TransportError>>;
}

/// One frame off a leg, in the order of the socket (`Leg::recv`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// ⛔ **`id` is `None` on every leg but the node's.** ⛔ The operator's
    /// inbound frame is already payload and ⛔ **must not be shortened by 32**
    /// — the strip behaviour is undocumented, and a client that subtracts 32
    /// eats the first 32 bytes of every message it receives.
    Data { id: Option<SessionId>, payload: Vec<u8> },
    Control(Control),
}

/// ⛔ **A control frame as it arrived, before any leg interprets it.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    Hello(Hello),
    Open { id: SessionId },
    Close { id: SessionId, reason: Option<String> },
    Ready { id: SessionId },
    Reject { id: SessionId, reason: String },
    /// ⛔ **A text frame that is not JSON.** ⛔ **Named, not dropped** — spec line
    /// 173 answers it `1003 invalid control JSON`, and a frame that vanished
    /// silently would look like a relay that stopped talking.
    Malformed { detail: String },
}

impl Control {
    /// ⛔ **Build from what the node was sent.** ⛔ A `hello` that fails to parse
    /// into `Hello` is `Malformed`, not a panic: the field set is the relay's and
    /// it may grow.
    pub fn from_inbound(message: NodeInbound) -> Self {
        match message {
            NodeInbound::Hello(hello) => Control::Hello(hello),
            NodeInbound::Open { id } => match SessionId::parse(id.as_bytes()) {
                Ok(id) => Control::Open { id },
                Err(e) => Control::Malformed { detail: e.to_string() },
            },
            NodeInbound::Close { id, reason } => match SessionId::parse(id.as_bytes()) {
                Ok(id) => Control::Close { id, reason },
                Err(e) => Control::Malformed { detail: e.to_string() },
            },
            NodeInbound::Unknown => Control::Malformed {
                detail: "control type is not hello, open or close".to_string(),
            },
        }
    }

    /// ⛔ **Build from what the operator was sent.** ⛔ The operator receives
    /// `ready`, `reject` and `close` — ⛔ **never `open` or `hello`**, because it
    /// is spliced to one session and has no name of its own to admit.
    pub fn from_outbound(message: NodeOutbound) -> Self {
        match message {
            NodeOutbound::Ready { id } => match SessionId::parse(id.as_bytes()) {
                Ok(id) => Control::Ready { id },
                Err(e) => Control::Malformed { detail: e.to_string() },
            },
            NodeOutbound::Reject { id, reason } => match SessionId::parse(id.as_bytes()) {
                Ok(id) => Control::Reject { id, reason },
                Err(e) => Control::Malformed { detail: e.to_string() },
            },
            NodeOutbound::Close { id, reason } => match SessionId::parse(id.as_bytes()) {
                Ok(id) => Control::Close { id, reason },
                Err(e) => Control::Malformed { detail: e.to_string() },
            },
        }
    }

    /// ⛔ **The session id, when there is one.** A `hello` has none, and returning
    /// `None` for it is honest rather than a sentinel.
    pub fn id(&self) -> Option<SessionId> {
        match self {
            Control::Hello(_) => None,
            Control::Open { id }
            | Control::Close { id, .. }
            | Control::Ready { id }
            | Control::Reject { id, .. } => Some(*id),
            Control::Malformed { .. } => None,
        }
    }
}

/// ⛔ **The three shapes, and what each one is allowed to do.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegShape {
    /// ⛔ Bare binary, **no id**, **no control**, cap 262144 (**MEASURED**).
    Forward,
    /// ⛔ **The only leg that writes a 32-byte id prefix**, and the only one that
    /// may send a text frame.
    ReverseNode,
    /// ⛔ Bare binary, **no id**, receives control, **never sends one**.
    ReverseOperator,
}

impl LegShape {
    /// ⛔ **Which role's token this leg authenticates with.** Spec lines 92-103
    /// scope the credentials per name *and role*.
    pub fn token_role(self) -> &'static str {
        match self {
            LegShape::Forward => "forward",
            LegShape::ReverseNode => "node_token",
            LegShape::ReverseOperator => "connect_token",
        }
    }

    /// ⛔ **Whether a text frame is legal here**, straight from the asymmetry
    /// table at `01-relay-protocol.md:371-376`.
    ///
    /// | | operator leg | node leg |
    /// | --- | --- | --- |
    /// | may carry control | **no** | **yes, and must** |
    pub fn may_send_control(self) -> bool {
        matches!(self, LegShape::ReverseNode)
    }

    /// ⛔ **Whether a data frame carries an id prefix.** ⛔ The forward path has
    /// no multiplexing and no id prefix, and prepending one injects 32 bytes of
    /// garbage into the banner — the highest-risk misreading in the whole
    /// specification.
    pub fn prefixes_with_id(self) -> bool {
        matches!(self, LegShape::ReverseNode)
    }

    /// ⛔ **Whether this leg has a control channel at all.** ⛔ The forward path
    /// has none — no `hello`, no `open`, no `ready`, and no text frame — so a
    /// caller that read `None` as "the socket ended" would tear down a healthy
    /// forward session on its first read.
    pub fn has_control_channel(self) -> bool {
        !matches!(self, LegShape::Forward)
    }

    /// ⛔ **Whether an inbound data frame on this leg carries a session id that
    /// podssh must strip.**
    ///
    /// ⛔ **`true` for the node leg only.** ⛔ On the operator leg the strip
    /// behaviour is **undocumented** — `01-relay-protocol.md:352-355` records
    /// that `grep -i strip` over the live document returns zero hits — and a
    /// client that subtracted 32 would eat the first 32 bytes of every message it
    /// received. ⛔ **The safe rule is that the operator subtracts nothing
    /// either way**: the relay prepends and strips in one hop, so what lands on
    /// the operator's socket is already payload.
    pub fn inbound_carries_id(self) -> bool {
        matches!(self, LegShape::ReverseNode)
    }
}

/// ⛔ **The cap in force on a leg. ⛔ Not a constant: the forward cap is read from
/// `/relays.json` at startup** and the node cap may be lowered by a `hello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_wire_frame: usize,
}

impl Limits {
    /// ⛔ **Named `forward` and not `default`,** because it is only correct once
    /// `/relays.json` has been read. `01-relay-protocol.md:215-217`: the forward
    /// path has no `hello`, so ⛔ *"podssh reads the forward cap from
    /// `/relays.json` at startup rather than compiling a constant."*
    pub const fn forward(from_relays_json: usize) -> Self {
        Self { max_wire_frame: from_relays_json }
    }

    /// ⛔ **The conservative floor used before `/relays.json` has been read.**
    /// ⚠ **Not a measurement of the relay.** It is the value from
    /// `FORWARD_MAX_FRAME_MEASURED`, named separately so the two roles cannot be
    /// confused, and it is safe because it is *at or below* the published cap.
    pub const fn unmeasured_floor() -> Self {
        Self { max_wire_frame: crate::endpoint::FORWARD_MAX_FRAME_MEASURED }
    }

    pub const fn reverse_operator() -> Self {
        Self { max_wire_frame: crate::framing::OPERATOR_PAYLOAD_MAX }
    }

    pub const fn reverse_node() -> Self {
        Self { max_wire_frame: crate::framing::NODE_FRAME_MAX_WIRE }
    }
}

/// ⛔ **The target a shape connects to**, so a caller that builds a `Transport`
/// cannot hand it the wrong leg.
pub fn target_for(shape: LegShape, host: &str, port: u16, name: &str) -> LegTarget {
    match shape {
        LegShape::Forward => LegTarget::Forward { host: host.to_string(), port },
        LegShape::ReverseNode => LegTarget::ReverseNode { name: name.to_string() },
        LegShape::ReverseOperator => LegTarget::ReverseOperator { name: name.to_string() },
    }
}