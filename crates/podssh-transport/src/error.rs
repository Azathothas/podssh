//! What podssh does with a close, and the HTTP failures that never reach one.
//!
//! ⛔ **The three retry classes, and they are not the same decision.** E02's
//! Decision says: *"Retry only on retryable closes. `1009 session byte cap` means
//! open a new session; `1001 pair expired` means mint a new pair; retrying either
//! is a loop that never ends."*

use crate::framing::CodecError;
use crate::transport::LegShape;

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
    /// A fresh token repairs it: mint once, then stop. A second refusal with
    /// a fresh token is final (spec lines 97-99).
    NewToken,
    /// A reverse leg's `403`: a new pair when the stored `expires` of the pair
    /// has passed, else never. Only the runner knows `expires`, so
    /// `is_retryable` says no until it has decided.
    ReverseForbidden,
}

impl Retry {
    pub fn is_retryable(self) -> bool {
        matches!(self, Retry::NewSession | Retry::NewPair | Retry::Reconnect | Retry::NewToken)
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

/// What podssh asked when the relay answered with an HTTP status: the
/// upgrade of a leg, or `POST /v1/pair`. One status means different things on
/// each: a `409` is "exit" on a node upgrade (`docs/reverse.md`, "Node", 6) and
/// "pair again" on `/v1/pair`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    Upgrade(LegShape),
    Pair,
}

/// ⛔ **An HTTP status the relay answered *instead of* a WebSocket.** ⛔ **These
/// never reach `classify`**, because there is no socket to close.
///
/// **READ**, spec lines 97-103: *"A `403 missing or wrong token` means absent
/// or wrong, not that the target is unreachable. A `403` that names the target
/// (`not in the ALLOW list`) is a policy denial — minting a fresh token will
/// not fix it."* A `503` means that the relay does not issue or check tokens.
/// So the body decides a forward `403`, and a `503` is not retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailure {
    /// A forward `403` that names no target: `missing or wrong token`. A
    /// fresh token repairs it.
    TokenRefused,
    /// A `403` or a `400` that names the target: a policy refusal. ⛔ **A
    /// fresh token does not fix it.**
    PolicyRefused,
    /// A reverse leg's `403`, `reverse: forbidden`: a wrong token, an expired
    /// pair and a stopped one look the same (measured 2026-10-01, after
    /// `POST /v1/stop`).
    ReverseForbidden,
    /// **READ**, spec line 154: *"Hitting `/v1/node/<name>` or
    /// `/v1/connect/<name>` without a WebSocket upgrade answers 426"*, and spec
    /// line 87's statement that the token is checked at each upgrade.
    UpgradeRequired,
    /// **READ**, spec lines 152-153: *"One name holds one node socket: a second
    /// node connection is refused HTTP 409 before accept, so the live node and
    /// its sessions are undisturbed."* ⛔ **Not a transient failure** — the live
    /// node is up and retrying is a loop that never ends.
    NameInUse,
    /// A `409` from `POST /v1/pair`: pair again (the relay's `/llms.txt`).
    PairAgain,
    /// **READ**, spec line 212: *"a dead target comes back as a plain HTTP
    /// `502`"* — the relay dialed the target before the upgrade and it failed.
    BadGateway,
    /// Spec lines 88-89 and 136-137: the admission brake, with `Retry-After`.
    RateLimited,
    /// **READ**, spec lines 100-103: the relay does not issue or check tokens
    /// (`503 forward relay authentication is not configured`).
    Unavailable,
    /// Anything else. ⛔ **Reported, never guessed at.**
    Other(u16),
}

impl HttpFailure {
    /// The failure of a status and its body, for what was asked. The body
    /// decides a `403` or a `400` through the one parser of a policy refusal.
    pub fn from_answer(status: u16, body: &str, asked: Asked) -> Self {
        let reverse = matches!(asked, Asked::Upgrade(LegShape::ReverseNode | LegShape::ReverseOperator));
        match status {
            400 | 403 if crate::adapt::is_policy_refusal(body) => HttpFailure::PolicyRefused,
            403 if reverse => HttpFailure::ReverseForbidden,
            403 if asked == Asked::Upgrade(LegShape::Forward) => HttpFailure::TokenRefused,
            426 => HttpFailure::UpgradeRequired,
            409 if asked == Asked::Pair => HttpFailure::PairAgain,
            409 => HttpFailure::NameInUse,
            502 => HttpFailure::BadGateway,
            429 => HttpFailure::RateLimited,
            503 => HttpFailure::Unavailable,
            other => HttpFailure::Other(other),
        }
    }

    /// ⛔ **One place decides whether an HTTP failure may be retried**, and it is
    /// the same rule the close table follows.
    pub fn retry(self) -> Retry {
        match self {
            HttpFailure::TokenRefused => Retry::NewToken,
            // ⛔ Spec line 99: minting a fresh token will not fix a policy denial.
            HttpFailure::PolicyRefused => Retry::Never,
            HttpFailure::ReverseForbidden => Retry::ReverseForbidden,
            HttpFailure::UpgradeRequired => Retry::Never,
            // ⛔ Spec lines 152-153: the live node is undisturbed, so this is a
            // name collision and not a transport failure. Exit.
            HttpFailure::NameInUse => Retry::Never,
            // Once: the caller counts.
            HttpFailure::PairAgain => Retry::NewPair,
            // ⛔ A 502 means the *target* refused. Re-dialing the same target is
            // the caller's decision, so it reconnects rather than being retried
            // silently here.
            HttpFailure::BadGateway => Retry::Reconnect,
            HttpFailure::RateLimited => Retry::Reconnect,
            // Not on this host. Failing over to another host is the caller's
            // rule, as for the forward path (`podssh_relay::open`).
            HttpFailure::Unavailable => Retry::Never,
            HttpFailure::Other(_) => Retry::Never,
        }
    }

    pub fn explain(self) -> &'static str {
        match self {
            HttpFailure::TokenRefused => "403: missing or wrong token; mint a new token once",
            HttpFailure::PolicyRefused => {
                "403: the relay's policy refuses this target; a new token does not help"
            }
            HttpFailure::ReverseForbidden => {
                "403 reverse: forbidden: a wrong token, an expired pair or a stopped one; \
                 pair again only when the pair has expired"
            }
            HttpFailure::UpgradeRequired => "426: the endpoint speaks WebSocket only; the token was accepted",
            HttpFailure::NameInUse => {
                "409: the name already holds a node; the live node and its sessions are undisturbed; exit"
            }
            HttpFailure::PairAgain => "409 from /v1/pair: pair again, once",
            HttpFailure::BadGateway => "502: the relay dialed the target before the upgrade and it failed",
            HttpFailure::RateLimited => "429: the admission brake; honour Retry-After",
            HttpFailure::Unavailable => {
                "503: the relay does not issue or check tokens; do not retry this host, and ask \
                 whoever gave you this relay for an operator token"
            }
            HttpFailure::Other(_) => "an unclassified HTTP status; nothing is retried",
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
    /// A host or a pair name that would change the relay path: refused
    /// before a URL exists.
    BadTarget(String),
    /// The relay answered with an HTTP status instead of upgrading. `body` is
    /// the start of its explanation, safe to print.
    Http { failure: HttpFailure, body: String },
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
            TransportError::BadTarget(_) => Retry::Never,
            TransportError::Http { failure, .. } => failure.retry(),
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
            TransportError::BadTarget(why) => write!(f, "the relay path cannot be built: {why}"),
            TransportError::Http { failure, body } if body.is_empty() => write!(f, "{}", failure.explain()),
            TransportError::Http { failure, body } => {
                write!(f, "{} (the relay said: {body})", failure.explain())
            }
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