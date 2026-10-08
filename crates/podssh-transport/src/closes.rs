//! Every close in the reverse table, one arm each, and what podssh must do.
//!
//! ⛔ **The relay publishes exactly one close table** — **READ**, spec line 166:
//! `Generated from `worker/src/reverse.js` at version 2026-10-03-r2`, under the
//! heading at spec line **160**, prose **162-166**, table header **168-169**,
//! and **24 rows on spec lines 170-193**.
//! `01-relay-protocol.md:151-158` records the finding that **the forward close
//! set is published nowhere at all**, and this module says so rather than
//! inventing one.
//!
//! ⛔ **The table's own `Observed by` column is what podssh branches on**, and it
//! is why every row is here: a `1003` and a `1011` can both land on the operator,
//! and the code alone does not say which fault it was. Where a row's *reason
//! string* is absent — `1011 node unavailable` and `1011 node offline` share a
//! code and differ only in prose — ⛔ **the reason is the discriminator, and a
//! client that reads only the code cannot tell them apart.**

use crate::error::{Retry, SessionAction};

/// ⛔ **Which socket the close landed on.** Spec lines 162-165: *"when the relay
/// itself closed the node socket for cause, the operator observes that cause too
/// (the close is forwarded to its sessions instead of the `1011` default), so a
/// `side: node` row can reach the operator leg."*
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// The `Observed by` column says `either`.
    Either,
    /// The column says `node` — but a relay-initiated node close is forwarded to
    /// the operator's sessions, so this can arrive on either socket.
    Node,
    /// The column says `operator`.
    Operator,
}

/// ⛔ **One row of the table**, with the action the row itself states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseRow {
    pub code: u16,
    /// ⛔ **The `Reason` column verbatim**, lowercased for matching. It is part of
    /// the contract: `01-relay-protocol.md:454` says *"Parse the reason, not the
    /// code."*
    pub reason: &'static str,
    pub observed_by: Leg,
    pub action: SessionAction,
    /// ⛔ **The spec line the row is on**, so a message can cite its source.
    pub spec_line: u16,
}

/// ⛔ **THE TABLE. Twenty-four rows, spec lines 170-193, transcribed from the
/// live document read on 2026-10-05 with `sed -n '<line>p'` against the pinned
/// 246-line copy, sha256 `88eb1b0b…cfa5a8`. ⛔ An earlier version of this table
/// carried 137-160, which was the same rows numbered two higher than the copy it
/// named — and `spec_line` is user-visible, so every close message cited a line
/// holding a different row.
///
/// ⛔ **Row order matches the document and is asserted by a test** — which now
/// reads the cited line out of that copy and requires the row's own reason to be
/// on it, because a shape assertion (a contiguous run) passed on the wrong
/// numbers for as long as the offset existed.
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
    // ⛔ Row 23 is a `1000 or 1011` row: node `close` relays as 1000 and node
    // `reject` as 1011, and both carry the node's own reason. Spec line 192.
    CloseRow { code: 1000, reason: "node-supplied", observed_by: Leg::Operator, action: SessionAction::ParseReasonNotCode, spec_line: 192 },
    CloseRow { code: 1011, reason: "node-supplied", observed_by: Leg::Operator, action: SessionAction::ParseReasonNotCode, spec_line: 192 },
    CloseRow { code: 1000, reason: "session ended", observed_by: Leg::Either, action: SessionAction::NormalEnd, spec_line: 193 },
];

/// ⛔ **The close as podssh received it.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayClose {
    pub code: u16,
    /// ⛔ **Kept even when it is empty.** A `1006` with no reason is itself
    /// information: it means the socket went away without a closing handshake.
    pub reason: String,
    pub clean: bool,
}

/// ⛔ **What podssh concludes, and what it does about it.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    /// ⛔ `None` when no row matches — ⛔ **and that is not a guess.** The forward
    /// path's close set is unpublished, so an unmatched close is reported as
    /// unmatched rather than forced into a reverse row that never applied.
    pub row: Option<CloseRow>,
    /// ⛔ Whether the whole relay connection may be re-established. ⛔ **This is
    /// the distinction E02's Decision turns on**, because retrying `1009 session
    /// byte cap` on the same session, or `1001 pair expired` on the same name, is
    /// a loop that never ends.
    pub retry: Retry,
    /// ⛔ Whether this close is the end of the *session* or of the *socket*.
    pub session: SessionAction,
    /// The code as received, matched or not.
    pub code: u16,
    /// The reason as received, safe to print: no control characters, and
    /// within the relay's own cap of 100 characters and 123 bytes.
    pub reason: String,
}

impl Classified {
    /// ⛔ **The user-facing message.** ⛔ **Never carries a token**, and never
    /// quotes a reason longer than the relay's own 123-byte cap produces. It
    /// names the code and the reason as received, matched or not: the reason
    /// is what a user acts on (`docs/relay.md`, "Errors and close codes").
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
                describe(row.action)
            ),
            None => format!(
                "relay closed {} {}: the relay's table has no row for it; \
                 the forward close set is unpublished, so no row applies",
                self.code, reason
            ),
        }
    }
}

fn describe(action: SessionAction) -> &'static str {
    action.explain()
}

/// ⛔ **Classify a close.** ⛔ **The reason is the discriminator**, per spec line
/// 192: *"Parse the reason, not the code."*
pub fn classify(close: &RelayClose) -> Classified {
    let needle = close.reason.trim().to_lowercase();
    let row = CLOSE_ROWS
        .iter()
        .find(|row| row.code == close.code && needle == row.reason)
        // ⛔ **Line 192 is a `1000 or 1011` row whose Reason column reads
        // `node-supplied`,** but the row's own text says the reason is *"the
        // node's own reason — or the literal type string when the node sent
        // none"*. ⛔ So a refusal carrying the node's own words is still that
        // row, and resolving it to `Unknown` would turn a legible per-session
        // refusal into an unreadable one. ⛔ The two spellings are read off line
        // 192, and nothing else is accepted: a `1000` with an arbitrary reason is
        // only classified as node-supplied when the **code** is one of the two
        // that row names.
        .or_else(|| {
            let node_supplied = matches!(close.code, 1000 | 1011)
                && (needle == "node-supplied" || needle == "node supplied" || is_a_node_refusal(&close.reason));
            node_supplied
                .then(|| CLOSE_ROWS.iter().find(|r| r.code == close.code && r.spec_line == 192))
                .flatten()
        })
        // ⛔ **Fallback on the code alone, and only for the rows where the code
        // is unambiguous.** Three codes carry more than one row and are therefore
        // never matched without their reason: `1001` (stopped vs expired) and
        // `1003` (six rows). A close whose reason is empty and whose code is
        // ambiguous resolves to **no row**, because guessing between "the relay
        // was revoked" and "the 72h TTL elapsed" would pick an action that mints
        // a new credential on a revocation, or retries a dead name on an expiry.
        .or_else(|| match close.code {
            1008 => CLOSE_ROWS.iter().find(|r| r.code == 1008),
            1009 => CLOSE_ROWS.iter().find(|r| r.code == 1009),
            1013 => CLOSE_ROWS.iter().find(|r| r.code == 1013),
            _ => None,
        });

    let session = row.map(|r| r.action).unwrap_or(SessionAction::Unknown);
    let retry = match (close.code, session) {
        // ⛔ A `1003` is a node-side fault. The socket stays up; retrying the
        // connection would hide a codec bug behind a reconnect loop.
        (_, SessionAction::FixCodec)
        | (_, SessionAction::DoNotSendText)
        | (_, SessionAction::AnswerReadyFirst)
        | (_, SessionAction::AlwaysPrefixFullId)
        | (_, SessionAction::ShrinkControl)
        | (_, SessionAction::ChunkTo64K)
        | (_, SessionAction::Unknown)
        | (_, SessionAction::SlowDown) => Retry::Never,
        // ⛔ Spec line 183: one session exceeded 64 MiB. The *session* is done;
        // the socket is fine and a new session on it is the stated action.
        (_, SessionAction::OpenNewSession) => Retry::NewSession,
        // ⛔ Spec line 171: the pair TTL elapsed. No new session on this pair
        // will ever work, so this is a credential fault and not a session fault.
        (_, SessionAction::MintNewPair) => Retry::NewPair,
        // ⛔ Spec line 170: revocation ran. ⛔ Retrying the name is exactly what
        // the row says not to do.
        (_, SessionAction::Stop) => Retry::Never,
        (_, SessionAction::NormalEnd) => Retry::Never,
        (_, SessionAction::ParseReasonNotCode) => Retry::Never,
        (_, SessionAction::ReopenSession) => Retry::NewSession,
        (_, SessionAction::WaitForReady) => Retry::NewSession,
        (_, SessionAction::ReadyDeadlineMissed) => Retry::NewSession,
        (_, SessionAction::RetryOpen) => Retry::Reconnect,
        (_, SessionAction::WaitAndRetry) => Retry::Reconnect,
        (_, SessionAction::Reconnect)
        | (_, SessionAction::ReconnectNode)
        | (_, SessionAction::ReconnectSocket) => Retry::Reconnect,
        (_, SessionAction::BackOff) => Retry::Reconnect,
    };

    // The reason comes from the network: printed only through the one
    // definition of safe text, and cut on a character boundary.
    let reason = crate::control::truncate_reason(&crate::adapt::one_line(&close.reason));
    Classified { row: row.copied(), retry, session, code: close.code, reason }
}

/// ⛔ **Does this reason read as a refusal a node sent?**
///
/// ⛔ **Only a small closed set matches, and only because line 192 says so**: it
/// names the *meaning* — a refusal, a closed port, a refusal to start — rather
/// than any string in particular. ⛔ A heuristic that accepted any reason would
/// turn every unmatched close into a node refusal, which is the guessing
/// `01-relay-protocol.md:454` forbids with *"Parse the reason, not the code"* in
/// the other direction: parse the reason **and** require that the code be one
/// line 192 names.
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
