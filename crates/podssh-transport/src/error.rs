//! What podssh does with a close, and the HTTP failures that never reach one.
//!
//! ⛔ **The three retry classes, and they are not the same decision.** E02's
//! Decision says: *"Retry only on retryable closes. `1009 session byte cap` means
//! open a new session; `1001 pair expired` means mint a new pair; retrying either
//! is a loop that never ends."*

use crate::framing::CodecError;

/// ⛔ **How far a close is allowed to propagate the retry.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// ⛔ **Do not retry anything.** The fault is in podssh's own bytes, in a
    /// credential, or in the relay's policy. Reconnecting produces the same
    /// close, so the loop is not merely useless — it is the bug.
    Never,
    /// ⛔ **The session is done; the socket is fine.** Spec line 148: open a new
    /// session. Spec line 145: wait for `ready` before writing.
    NewSession,
    /// ⛔ **The credentials are done.** Spec line 136: the 72h pair TTL elapsed,
    /// and no session on this pair will ever open.
    NewPair,
    /// ⛔ **The socket is gone but the credentials and the name are good.**
    /// Spec lines 151-153: the node was unavailable, offline, or disconnected.
    Reconnect,
}

impl Retry {
    pub fn is_retryable(self) -> bool {
        matches!(self, Retry::NewSession | Retry::NewPair | Retry::Reconnect)
    }
}

/// ⛔ **The action the table's own `Meaning and action` column states**, one
/// variant per distinct action across the twenty-four rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    /// Spec line 135. `POST /v1/stop/<name>` ran.
    Stop,
    /// Spec line 136. Create a new pair.
    MintNewPair,
    /// Spec line 137. Re-open the session; never invent addressing.
    ReopenSession,
    /// Spec lines 138-141. The bytes podssh sent were wrong.
    FixCodec,
    /// Spec line 142. Answer `open` with `ready` first.
    AnswerReadyFirst,
    /// Spec line 143. The operator sent a text frame.
    DoNotSendText,
    /// Spec line 144. No role attachment; reconnect if seen.
    Reconnect,
    /// Spec line 145. Operator data arrived before the node readied.
    WaitForReady,
    /// Spec line 146. Node JSON control over 4 KiB.
    ShrinkControl,
    /// Spec line 147. Always prefix the full id, in one frame.
    AlwaysPrefixFullId,
    /// Spec line 148. One session exceeded 64 MiB both ways.
    OpenNewSession,
    /// Spec line 149. One operator frame exceeded 65536.
    ChunkTo64K,
    /// Spec line 150. Over 1 MiB queued; ⛔ **the frame is dropped**.
    SlowDown,
    /// Spec line 151. The `open` could not be queued to the node.
    RetryOpen,
    /// Spec line 152. Data arrived with no node connected.
    WaitAndRetry,
    /// Spec line 153. The node socket ended with no forwardable reason.
    ReconnectNode,
    /// Spec line 154. Transport-level socket error.
    ReconnectSocket,
    /// Spec line 155. No `ready` within 15 s.
    ReadyDeadlineMissed,
    /// Spec line 156. The optional per-name fuse tripped.
    BackOff,
    /// Spec line 157. Node `close`/`reject`; parse the reason, not the code.
    ParseReasonNotCode,
    /// Spec line 158. Answer to a client-initiated Close.
    NormalEnd,
    /// ⛔ No row matched. ⛔ **Not a default action**: the forward close set is
    /// unpublished, so there is nothing to be right about here.
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

/// ⛔ **An HTTP status the relay answered *instead of* a WebSocket.** ⛔ **These
/// never reach `classify`**, because there is no socket to close.
///
/// ⚠ **`403` is named here and is never retried.** **READ**, spec lines 97-99:
/// *"A `403 missing or wrong token` means absent or wrong, not that the target is
/// unreachable. A `403` that names the target (`not in the ALLOW list`) is a
/// policy denial — minting a fresh token will not fix it."* ⛔ E02's Decision
/// says it flatly: **never retry a `403`**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailure {
    /// Spec lines 97-99. Authentication or policy. ⛔ **A fresh token does not
    /// fix a policy denial.**
    Forbidden,
    /// **READ**, spec line 154: *"Hitting `/v1/node/<name>` or
    /// `/v1/connect/<name>` without a WebSocket upgrade answers 426"*, and spec
    /// line 87's statement that the token is checked at each upgrade.
    UpgradeRequired,
    /// **READ**, spec lines 152-153: *"One name holds one node socket: a second
    /// node connection is refused HTTP 409 before accept, so the live node and
    /// its sessions are undisturbed."* ⛔ **Not a transient failure** — the live
    /// node is up and retrying is a loop that never ends.
    NameInUse,
    /// **READ**, spec line 212: *"a dead target comes back as a plain HTTP
    /// `502`"* — the relay dialed the target before the upgrade and it failed.
    BadGateway,
    /// Spec lines 88-89 and 136-137: the admission brake, with `Retry-After`.
    RateLimited,
    /// The relay is administratively disabled — **READ**, spec lines 102-103
    /// (`503 forward relay ...`).
    Unavailable,
    /// Anything else. ⛔ **Reported, never guessed at.**
    Other(u16),
}

impl HttpFailure {
    /// ⛔ **One place decides whether an HTTP failure may be retried**, and it is
    /// the same rule the close table follows.
    pub fn retry(self) -> Retry {
        match self {
            // ⛔ Spec line 66: a 403 naming the target is a policy denial, and
            // minting a fresh token will not fix it.
            HttpFailure::Forbidden => Retry::Never,
            HttpFailure::UpgradeRequired => Retry::Never,
            // ⛔ Spec lines 117-118: the live node is undisturbed, so this is a
            // name collision and not a transport failure.
            HttpFailure::NameInUse => Retry::Never,
            // ⛔ A 502 means the *target* refused. Re-dialing the same target is
            // the caller's decision, so it reconnects rather than being retried
            // silently here.
            HttpFailure::BadGateway => Retry::Reconnect,
            HttpFailure::RateLimited => Retry::Reconnect,
            HttpFailure::Unavailable => Retry::Reconnect,
            HttpFailure::Other(_) => Retry::Never,
        }
    }

    pub fn explain(self) -> &'static str {
        match self {
            HttpFailure::Forbidden => {
                "403: authentication or policy. Never retry; a fresh token does not fix a policy denial"
            }
            HttpFailure::UpgradeRequired => "426: the endpoint speaks WebSocket only; the token was accepted",
            HttpFailure::NameInUse => {
                "409: the name already holds a node; the live node and its sessions are undisturbed"
            }
            HttpFailure::BadGateway => "502: the relay dialed the target before the upgrade and it failed",
            HttpFailure::RateLimited => "429: the admission brake; honour Retry-After",
            HttpFailure::Unavailable => "503: the relay is administratively unavailable",
            HttpFailure::Other(_) => "an unclassified HTTP status; nothing is retried",
        }
    }

    pub fn from_status(status: u16) -> Self {
        match status {
            403 => HttpFailure::Forbidden,
            426 => HttpFailure::UpgradeRequired,
            409 => HttpFailure::NameInUse,
            502 => HttpFailure::BadGateway,
            429 => HttpFailure::RateLimited,
            503 => HttpFailure::Unavailable,
            other => HttpFailure::Other(other),
        }
    }
}

/// ⛔ **The transport's own failures, kept apart from the relay's.**
#[derive(Debug)]
pub enum TransportError {
    /// ⛔ **No relay target is configured.** podssh errors and says so; it does
    /// **not** fall back to a name that may be gone (`relay-transport.md:52`,
    /// `01-relay-protocol.md:76-77`).
    NoRelayConfigured,
    /// The relay answered with an HTTP status instead of upgrading.
    Http(HttpFailure),
    /// A frame podssh built was wrong before it left.
    Codec(crate::framing::CodecError),
    /// A control frame was malformed or over the 4 KiB cap.
    Control(crate::control::ControlError),
    /// The socket closed. ⛔ **The reason travels with it**, because the reason
    /// is the discriminator and the code alone is not.
    Closed(crate::closes::RelayClose),
    /// A frame refused before the wire, named by the close the relay would
    /// answer it with (`crate::sessions`). Nothing was sent, and the socket
    /// is still up.
    Refused(crate::sessions::Refusal),
    /// The socket ended without a closing handshake — `1006`. `detail` is the
    /// text of the failure, kept for the user.
    Aborted { clean: bool, detail: String },
    /// ⛔ **Something happened that this crate has no row for**, named rather
    /// than flattened into "unknown". Four sibling projects shipped a doctor that
    /// reported green over a broken environment.
    Unexpected(String),
}

impl TransportError {
    /// ⛔ **How far this failure propagates a retry**, from one place.
    pub fn retry(&self) -> Retry {
        match self {
            TransportError::NoRelayConfigured => Retry::Never,
            TransportError::Http(status) => status.retry(),
            TransportError::Codec(_) | TransportError::Control(_) => Retry::Never,
            TransportError::Closed(close) => crate::closes::classify(close).retry,
            // The same frame would be refused again.
            TransportError::Refused(_) => Retry::Never,
            TransportError::Aborted { .. } => Retry::Reconnect,
            TransportError::Unexpected(_) => Retry::Never,
        }
    }

    /// ⛔ **The session-level consequence**, from one place.
    pub fn session_action(&self) -> SessionAction {
        match self {
            TransportError::Closed(close) => crate::closes::classify(close).session,
            // The action of the close that the refusal avoided.
            TransportError::Refused(refusal) => crate::closes::classify(&crate::closes::RelayClose {
                code: refusal.code,
                reason: refusal.reason.to_string(),
                clean: true,
            })
            .session,
            _ => SessionAction::Unknown,
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::NoRelayConfigured => write!(
                f,
                "no relay target is configured. podssh ships no default relay path: the \
                 relay currently publishes none, and a client that falls back to a name \
                 that no longer exists dials a gateway that is gone. Set one explicitly."
            ),
            TransportError::Http(status) => write!(f, "{}", status.explain()),
            TransportError::Codec(e) => write!(f, "{e}"),
            TransportError::Control(e) => write!(f, "{e}"),
            TransportError::Closed(close) => {
                write!(f, "{}", crate::closes::classify(close).message())
            }
            TransportError::Refused(refusal) => write!(
                f,
                "refused before the wire: the relay closes the socket with {} {} for it",
                refusal.code, refusal.reason
            ),
            TransportError::Aborted { clean, detail } => {
                write!(f, "socket ended without a closing handshake (clean={clean}): {detail}")
            }
            TransportError::Unexpected(detail) => write!(f, "unexpected transport failure: {detail}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<CodecError> for TransportError {
    /// ⛔ **A frame podssh built itself was wrong**, so this is `Retry::Never` in
    /// `retry()` above: the next attempt would send the same bytes.
    fn from(e: CodecError) -> Self {
        TransportError::Codec(e)
    }
}