//! Each close of the reverse table, one row each, and what podssh does about
//! it. The relay publishes one table, for the reverse path (generated from its
//! `worker/src/reverse.js`, version 2026-10-03-r2); the forward close set is
//! published nowhere, so no row is invented for it. The column "Observed by"
//! is part of each row, and the reason tells apart two rows of one code:
//! `1011 node unavailable` and `1011 node offline` differ in their prose alone.

/// How far a close lets a retry go. Retrying `1009 session byte cap` on the
/// same session, or `1001 pair expired` on the same name, is a loop that never
/// ends; so each class is its own decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// No retry: the fault is in podssh's own bytes, a credential, or the
    /// relay's policy, and a reconnection gets the same close.
    Never,
    /// The session is over, and the socket is fine: open a new session.
    NewSession,
    /// The pair is over (its 72 hours passed): make a new pair.
    NewPair,
    /// The socket is gone, and the pair and the name are good: reconnect.
    Reconnect,
}

impl Retry {
    pub fn is_retryable(self) -> bool {
        matches!(self, Retry::NewSession | Retry::NewPair | Retry::Reconnect)
    }
}

/// The action that the table's column "Meaning and action" gives, one for each
/// distinct action of its rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    /// `1001 operator stopped reverse relay`: `POST /v1/stop/<name>` ran.
    Stop,
    /// `1001 pair expired`: make a new pair.
    MintNewPair,
    /// `1003 unknown session id`: open the session again; never invent an id.
    ReopenSession,
    /// `1003` for control or a prefix: the bytes that podssh sent were wrong.
    FixCodec,
    /// `1003 data before ready`: answer `open` with `ready` first.
    AnswerReadyFirst,
    /// `1003 binary frames required`: the operator sent a text frame.
    DoNotSendText,
    /// `1008 unknown role`: reconnect if it is seen.
    Reconnect,
    /// `1008 wait for ready`: the operator sent data before the node readied.
    WaitForReady,
    /// `1009 control frame byte cap`: a control frame over 4 KiB.
    ShrinkControl,
    /// `1009 bad multiplex frame`: the whole id, in the same frame.
    AlwaysPrefixFullId,
    /// `1009 session byte cap`: one session passed 64 MiB, both ways together.
    OpenNewSession,
    /// `1009 frame byte cap`: an operator frame over 65536 bytes.
    ChunkTo64K,
    /// `1011 relay backpressure`: over 1 MiB queued, and the frame dropped.
    SlowDown,
    /// `1011 node unavailable`: the `open` could not be queued to the node.
    RetryOpen,
    /// `1011 node offline`: data came with no node connected.
    WaitAndRetry,
    /// `1011 node disconnected`: the node's socket ended with no reason.
    ReconnectNode,
    /// `1011 socket error`: an error of the socket itself.
    ReconnectSocket,
    /// `1013 node open timeout`: no `ready` within 15 s.
    ReadyDeadlineMissed,
    /// `1013 reverse message rate cap`: the optional fuse of a name tripped.
    BackOff,
    /// A node's `close` (1000) or `reject` (1011): read the reason, not the code.
    ParseReasonNotCode,
    /// `1000 session ended`: the answer to a Close of the client.
    NormalEnd,
    /// No row matched. Not a default action: there is nothing to be right
    /// about for a close that no table gives.
    Unknown,
}

impl SessionAction {
    pub fn explain(self) -> &'static str {
        match self {
            SessionAction::Stop => "revocation ran; do not retry this name",
            SessionAction::MintNewPair => "the 72h pair TTL elapsed; create a new pair",
            SessionAction::ReopenSession => "the frame named a stale id; re-open the session",
            SessionAction::FixCodec => "podssh sent bytes the relay refused; fix the codec",
            SessionAction::AnswerReadyFirst => "answer open with ready before sending data",
            SessionAction::DoNotSendText => "the operator leg is binary-only; never send a text frame",
            SessionAction::Reconnect => "no role attachment; reconnect if seen",
            SessionAction::WaitForReady => "data arrived before ready; wait for it",
            SessionAction::ShrinkControl => "node JSON control exceeded 4 KiB; keep controls small",
            SessionAction::AlwaysPrefixFullId => "the id and the payload must be one frame",
            SessionAction::OpenNewSession => "one session exceeded 64 MiB; open a new one",
            SessionAction::ChunkTo64K => "one operator frame exceeded 65536; chunk to 64 KiB",
            SessionAction::SlowDown => "over 1 MiB queued and the frame was dropped; slow down",
            SessionAction::RetryOpen => "the open could not be queued; retry opening",
            SessionAction::WaitAndRetry => "no node connected; wait and retry",
            SessionAction::ReconnectNode => "the node socket ended; reconnect the session",
            SessionAction::ReconnectSocket => "transport socket error; reconnect",
            SessionAction::ReadyDeadlineMissed => "no ready within 15 s; answer open faster",
            SessionAction::BackOff => "the per-name rate fuse tripped; back off",
            SessionAction::ParseReasonNotCode => "a node close or reject relayed this; read the reason",
            SessionAction::NormalEnd => "answer to a client-initiated close",
            SessionAction::Unknown => "no published row matches this close",
        }
    }
}

/// The socket that a close lands on, as the column "Observed by" gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    Either,
    /// The node's socket; a close that the relay makes there for cause is
    /// forwarded to the operator's sessions too.
    Node,
    Operator,
}

/// One row of the table, with the action that the row states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseRow {
    pub code: u16,
    /// The column "Reason", lower-cased for matching: the reason, not the
    /// code, tells two rows apart.
    pub reason: &'static str,
    pub observed_by: Leg,
    pub action: SessionAction,
    /// The line of the row in the pinned copy of the contract, which a
    /// message cites; a test reads that line back.
    pub spec_line: u16,
}

/// The table, in the order of the contract; a test checks each row against
/// its line of the pinned copy.
pub const CLOSE_ROWS: &[CloseRow] = &[
    CloseRow { code: 1001, reason: "operator stopped reverse relay", observed_by: Leg::Either, action: SessionAction::Stop, spec_line: 170 },
    CloseRow { code: 1001, reason: "pair expired", observed_by: Leg::Either, action: SessionAction::MintNewPair, spec_line: 171 },
    CloseRow { code: 1003, reason: "unknown session id", observed_by: Leg::Node, action: SessionAction::ReopenSession, spec_line: 172 },
    CloseRow { code: 1003, reason: "invalid control json", observed_by: Leg::Node, action: SessionAction::FixCodec, spec_line: 173 },
    CloseRow { code: 1003, reason: "invalid session id", observed_by: Leg::Node, action: SessionAction::FixCodec, spec_line: 174 },
    CloseRow { code: 1003, reason: "unknown control type", observed_by: Leg::Node, action: SessionAction::FixCodec, spec_line: 175 },
    CloseRow { code: 1003, reason: "bad multiplex id", observed_by: Leg::Node, action: SessionAction::FixCodec, spec_line: 176 },
    CloseRow { code: 1003, reason: "data before ready", observed_by: Leg::Node, action: SessionAction::AnswerReadyFirst, spec_line: 177 },
    CloseRow { code: 1003, reason: "binary frames required", observed_by: Leg::Operator, action: SessionAction::DoNotSendText, spec_line: 178 },
    CloseRow { code: 1008, reason: "unknown role", observed_by: Leg::Either, action: SessionAction::Reconnect, spec_line: 179 },
    CloseRow { code: 1008, reason: "wait for ready", observed_by: Leg::Operator, action: SessionAction::WaitForReady, spec_line: 180 },
    CloseRow { code: 1009, reason: "control frame byte cap", observed_by: Leg::Node, action: SessionAction::ShrinkControl, spec_line: 181 },
    CloseRow { code: 1009, reason: "bad multiplex frame", observed_by: Leg::Node, action: SessionAction::AlwaysPrefixFullId, spec_line: 182 },
    CloseRow { code: 1009, reason: "session byte cap", observed_by: Leg::Operator, action: SessionAction::OpenNewSession, spec_line: 183 },
    CloseRow { code: 1009, reason: "frame byte cap", observed_by: Leg::Operator, action: SessionAction::ChunkTo64K, spec_line: 184 },
    CloseRow { code: 1011, reason: "relay backpressure", observed_by: Leg::Either, action: SessionAction::SlowDown, spec_line: 185 },
    CloseRow { code: 1011, reason: "node unavailable", observed_by: Leg::Operator, action: SessionAction::RetryOpen, spec_line: 186 },
    CloseRow { code: 1011, reason: "node offline", observed_by: Leg::Operator, action: SessionAction::WaitAndRetry, spec_line: 187 },
    CloseRow { code: 1011, reason: "node disconnected", observed_by: Leg::Operator, action: SessionAction::ReconnectNode, spec_line: 188 },
    CloseRow { code: 1011, reason: "socket error", observed_by: Leg::Either, action: SessionAction::ReconnectSocket, spec_line: 189 },
    CloseRow { code: 1013, reason: "node open timeout", observed_by: Leg::Operator, action: SessionAction::ReadyDeadlineMissed, spec_line: 190 },
    CloseRow { code: 1013, reason: "reverse message rate cap", observed_by: Leg::Either, action: SessionAction::BackOff, spec_line: 191 },
    // One row with two codes: a node's `close` arrives as 1000 and its
    // `reject` as 1011, each with the node's own reason.
    CloseRow { code: 1000, reason: "node-supplied", observed_by: Leg::Operator, action: SessionAction::ParseReasonNotCode, spec_line: 192 },
    CloseRow { code: 1011, reason: "node-supplied", observed_by: Leg::Operator, action: SessionAction::ParseReasonNotCode, spec_line: 192 },
    CloseRow { code: 1000, reason: "session ended", observed_by: Leg::Either, action: SessionAction::NormalEnd, spec_line: 193 },
];

/// A close as podssh received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayClose {
    pub code: u16,
    /// Kept when it is empty: a `1006` with no reason says that the socket
    /// went away with no closing handshake.
    pub reason: String,
    pub clean: bool,
}

/// What podssh makes of a close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    /// `None` when no row matches: the close is reported as unmatched, not
    /// forced into a reverse row that never applied.
    pub row: Option<CloseRow>,
    /// Whether the relay connection may be made again.
    pub retry: Retry,
    /// Whether the close ends the session or the socket.
    pub session: SessionAction,
    /// The code as received, matched or not.
    pub code: u16,
    /// The reason as received, safe to print: no control character, and within
    /// the relay's own cap of 100 characters and 123 bytes.
    pub reason: String,
}

impl Classified {
    /// The message for a user. It names the code and the reason as received:
    /// the reason is what a user acts on. It never holds a token.
    pub fn message(&self) -> String {
        let reason = if self.reason.is_empty() { "(no reason)" } else { self.reason.as_str() };
        match self.row {
            Some(row) => format!(
                "relay closed {} {} ({}, spec line {}): {}",
                self.code,
                reason,
                match row.observed_by {
                    Leg::Either => "either leg",
                    Leg::Node => "node leg, possibly forwarded to the operator",
                    Leg::Operator => "operator leg",
                },
                row.spec_line,
                row.action.explain()
            ),
            None => format!(
                "relay closed {} {}: the relay's table has no row for it; \
                 the forward close set is unpublished, so no row applies",
                self.code, reason
            ),
        }
    }
}

/// Classify a close by its code and its reason: the contract says to parse the
/// reason, not the code.
pub fn classify(close: &RelayClose) -> Classified {
    let needle = close.reason.trim().to_lowercase();
    let row = CLOSE_ROWS
        .iter()
        .find(|row| row.code == close.code && needle == row.reason)
        // The node-supplied row carries the node's own words: a refusal in
        // them is still that row, for the two codes that it names.
        .or_else(|| {
            let node_supplied = matches!(close.code, 1000 | 1011)
                && (needle == "node-supplied" || needle == "node supplied" || is_a_node_refusal(&close.reason));
            node_supplied.then(|| CLOSE_ROWS.iter().find(|r| r.code == close.code && r.spec_line == 192)).flatten()
        })
        // The code alone, only where it names one action. `1001` (stopped or
        // expired) and `1003` (six rows) are never matched without their
        // reason: a guess would mint a new pair after a revocation.
        .or_else(|| match close.code {
            1008 => CLOSE_ROWS.iter().find(|r| r.code == 1008),
            1009 => CLOSE_ROWS.iter().find(|r| r.code == 1009),
            1013 => CLOSE_ROWS.iter().find(|r| r.code == 1013),
            _ => None,
        });

    let session = row.map(|r| r.action).unwrap_or(SessionAction::Unknown);
    let retry = match session {
        // A fault of the node's own bytes: a reconnection would hide a codec
        // defect behind a loop.
        SessionAction::FixCodec
        | SessionAction::DoNotSendText
        | SessionAction::AnswerReadyFirst
        | SessionAction::AlwaysPrefixFullId
        | SessionAction::ShrinkControl
        | SessionAction::ChunkTo64K
        | SessionAction::Unknown
        | SessionAction::SlowDown => Retry::Never,
        // One session passed 64 MiB: the socket is fine.
        SessionAction::OpenNewSession => Retry::NewSession,
        // The pair is over; no session on it opens again.
        SessionAction::MintNewPair => Retry::NewPair,
        // Revocation ran: retrying the name is what the row forbids.
        SessionAction::Stop | SessionAction::NormalEnd | SessionAction::ParseReasonNotCode => Retry::Never,
        SessionAction::ReopenSession | SessionAction::WaitForReady | SessionAction::ReadyDeadlineMissed => {
            Retry::NewSession
        }
        SessionAction::RetryOpen
        | SessionAction::WaitAndRetry
        | SessionAction::Reconnect
        | SessionAction::ReconnectNode
        | SessionAction::ReconnectSocket
        | SessionAction::BackOff => Retry::Reconnect,
    };

    // The reason comes from the network: printed through the one definition
    // of safe text, and cut on a character boundary.
    let reason = super::control::truncate_reason(&podssh_ws::text::one_line(&close.reason));
    Classified { row: row.copied(), retry, session, code: close.code, reason }
}

/// Whether a reason reads as a node's refusal. A small closed set: the row
/// names a refusal, a closed port, a refusal to start, and no string; to
/// accept any reason would make each unmatched close a node's refusal.
fn is_a_node_refusal(reason: &str) -> bool {
    const REFUSALS: &[&str] = &[
        "connection refused",
        "refused",
        "rejected",
        "closed",
        "target closed",
        "no route to host",
        "not listening",
        "eof",
        "session closed",
    ];
    REFUSALS.iter().any(|needle| reason == *needle)
}
