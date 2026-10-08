//! E12: a relay token that cannot be printed.
//!
//! ⛔ **The rule this file exists to make unrepresentable.** `AGENTS.md`:
//! *"A token never enters source, output, a log, a URL, shell history, a
//! screenshot, or an issue report."* ⛔ **A redaction function a caller may
//! forget to call is a note, not a guard.** So there is no `redact(&str)` on the
//! token and no `log_token()`: the type has no `Display`, its `Debug` prints a
//! fixed string, and the only way out is [`RelayToken::expose`].
//!
//! ⛔ **`expose` is a separate, named call on purpose.** It cannot be reached by
//! a formatter, by `{}`, by `{:?}`, by a `Vec`'s `Debug`, or by a derived
//! `Debug` on an error that holds one. The two that a caller *can* still reach
//! are `assert_eq!` on two tokens and a deliberate `expose()`; both are visible
//! at the call site in a way a `Display` impl is not.

use std::fmt;
use std::str::FromStr;

use zeroize::Zeroize;

/// ⛔ **What every render of a token says.** Not "redacted", not the first four
/// characters: ⛔ **a prefix is a fragment, and a fragment is a credential that
/// helps somebody brute-force the rest.** A fixed string that is not a function
/// of the secret is the only thing that can be printed unconditionally.
pub const REDACTED: &str = "<relay-token: redacted>";

/// ⛔ **The header name, and nothing else may carry a token.** Spec line 239
/// allows three forms: `?token=<t>`, `/t/<t>/connect/...`, and `X-Relay-Token`.
/// Spec lines 94-96 prefer the header because *"URLs can appear in logs"*, and
/// this repository's `AGENTS.md` and [`../../../../docs/spec/01-relay-protocol.md`]
/// both carry that rule. ⛔ **podssh uses the header on the forward path, where
/// headers are always available, so the URL forms are not implemented at all.**
pub const TOKEN_HEADER: &str = "X-Relay-Token";

/// ⛔ **The shape a forward token has.** Spec lines 81-87:
/// `ephm1.<exp-ms>.forward.<mac>`. ⛔ **This is a *recogniser*, not a rule about
/// what may be logged** — it exists so the backstop in [`super::redact`] can
/// drop a line whose value happens to be a token even when the value did not
/// come through [`RelayToken`]. ⛔ The MAC is base64, so the character class is
/// base64 plus `.`, and the expiry is digits.
pub const TOKEN_SHAPE: &str = r"ephm1\.[0-9]{10,}\.[a-z]+\.[A-Za-z0-9+/=]+";

/// A relay credential that cannot be rendered.
///
/// ⛔ **Deliberately not `Clone`**, because a clone is a second copy nobody
/// zeroizes, and the whole lifecycle this type models is *"one copy, wiped at
/// the end"*.
pub struct RelayToken {
    bytes: Vec<u8>,
}

/// ⛔ **What a caller may say about a token in a message.** The expiry is the
/// millisecond expiry the relay publishes (spec lines 81-87: `expires` is ms
/// since epoch), and the role is `forward`, `node`, `connect` or `stop`. ⛔ **Both
/// are properties of the token, not of the secret**, which is why naming them
/// in a diagnostic is safe and is the *only* thing about a token a diagnostic is
/// allowed to say.
///
/// ⛔ `Debug` is written by hand rather than derived, and ⛔ **the reason is
/// durability, not style**: a `#[derive(Debug)]` would print every field, so
/// adding a `String` to this struct later would silently print it. ⛔ ⚠ **The
/// hand-written impl does not make a new field a compile error** ⛔ — a
/// `debug_struct` call that omits a field is not an error in `rustc`, so ⛔
/// **the guarantee here is that a reader sees the `debug_struct` listing and
/// knows the type is curated**, ⛔ and nothing more. ⛔ A type that genuinely
/// cannot grow a printable field is one with a single private field, which is
/// [`RelayToken`] and not this one. ⛔ That is why the struct is ⛔ **not** the
/// secret's container.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TokenFacts {
    pub expires_ms: i64,
    pub kind: TokenRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRole {
    Forward,
    Node,
    Connect,
    Stop,
}

impl TokenRole {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenRole::Forward => "forward",
            TokenRole::Node => "node",
            TokenRole::Connect => "connect",
            TokenRole::Stop => "stop",
        }
    }
}

impl fmt::Debug for TokenFacts {
    /// ⛔ Curated rather than derived. ⛔ **A `#[derive(Debug)]` would print every
    /// field**, so a new `String` here would leak ⛔ and the hand-written form
    /// makes that a decision somebody takes rather than a default.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenFacts")
            .field("expires_ms", &self.expires_ms)
            .field("kind", &self.kind.as_str())
            .finish()
    }
}

impl RelayToken {
    /// ⛔ **The only constructor that takes a secret.** It is public because
    /// [`crate::security::chain`] reads a cached file and E31 mints over HTTP,
    /// and neither can be given a `&str` otherwise — but it is deliberately not
    /// `From<&str>`, because `From` is a conversion a caller reaches for
    /// without thinking about redaction.
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        let mut bytes = secret.into();
        bytes.shrink_to_fit();
        RelayToken { bytes }
    }

    /// ⛔ **The only way to read the secret.** Named, explicit, and the thing
    /// `Display`, `Debug`, `String::from` and `format!` all fail to reach.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// ⛔ **Destroy the copy now, rather than at the end of the scope.**
    ///
    /// ⛔ `Drop` already zeroizes, so this is not strictly a different
    /// guarantee — and it is here anyway, for the one case where it is:
    /// ⛔ [`crate::security::redpair::ReversePair::revoke`] destroys three
    /// tokens at the moment the operator revokes, and a caller must be able to
    /// say so ⛔ without waiting for a `Drop` that may be a `Vec`'s, a frame's,
    /// or never reached at all in a `panic = "abort"` build, which is what
    /// this workspace's release profile uses (`Cargo.toml`: `panic = "abort"`).
    pub fn expire(&mut self) {
        self.bytes.zeroize();
    }

    /// ⛔ **The one caller is the header.** A `str` is not derivable from
    /// `expose`, so the only way to build the request is to ask for the value
    /// here and hand it straight to the header map.
    pub fn header_value(&self) -> String {
        String::from_utf8_lossy(self.expose()).into_owned()
    }

    /// Parse the token's own expiry.
    ///
    /// ⛔ **Read from the token, not from a second field.** The relay publishes
    /// `expires` in the mint response (spec lines 81-87) and the token embeds
    /// the same value as its second dot-separated field, so reading it from the
    /// secret means ⛔ **one source of truth that a malformed response cannot
    /// desynchronise from the thing the relay will actually check.**
    ///
    /// ⛔ Spec lines 81-87: a token expires at most **72 h** after
    /// minting. ⛔ The relay checks the token **when each session is established**
    /// (each WebSocket upgrade) and not per frame, so ⛔ a token that expires
    /// mid-life does not kill an open session, and the check belongs on the
    /// session-establishment path and nowhere else.
    pub fn facts(&self) -> Result<TokenFacts, TokenError> {
        let text = std::str::from_utf8(self.expose()).map_err(|_| TokenError::NotUtf8)?;
        let mut parts = text.split('.');
        let prefix = parts.next().unwrap_or_default();
        let exp = parts.next().ok_or(TokenError::Shape)?;
        let kind = parts.next().ok_or(TokenError::Shape)?;
        if prefix != "ephm1" {
            return Err(TokenError::Shape);
        }
        // ⛔ **Everything after the role is the MAC, and it is not read.**
        // ⛔ The relay’s shape, spec lines 81-87, is
        // `ephm1.<exp-ms>.forward.<mac>` — four fields — and a first
        // ⛔ version of this required **exactly** three, so ⛔ it refused every real
        // ⛔ token podssh could ever be handed, and ⛔ a mint response it cannot read
        // ⛔ is a token it cannot use, which is worse than one whose expiry it
        // ⛔ declines to interpret. ⛔ A token with no MAC is still a token.
        //
        // ⛔ **And a token with too many fields is still a token.** ⛔ The MAC is
        // ⛔ a secret, so podssh neither parses it nor length-checks it, and ⛔ **a
        // ⛔ reader that counted its dots would be validating something podssh has
        // ⛔ no business validating.** ⛔ `RULES.md` asks for `UNKNOWN` where
        // ⛔ evidence is absent, and a token shape is exactly that.
        // ⛔ The MAC is consumed and discarded, ⛔ **and the `let` is what makes
        // that explicit** — ⛔ `parts.next();` on its own reads as a
        // ⛔ forgotten call, and a reader would not know it was deliberate.
        let _mac_is_opaque = parts.next();
        if kind.is_empty() || !kind.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err(TokenError::Shape);
        }
        let expires_ms: i64 = exp.parse().map_err(|_| TokenError::Shape)?;
        let role = match kind {
            "forward" => TokenRole::Forward,
            "node" => TokenRole::Node,
            "connect" => TokenRole::Connect,
            "stop" => TokenRole::Stop,
            _ => return Err(TokenError::Shape),
        };
        Ok(TokenFacts {
            expires_ms,
            kind: role,
        })
    }

    /// ⛔ **Expiry is checked before a session is established, once.** Spec
    /// lines 53-54: the token is checked *per session establishment, not per
    /// frame*. ⛔ A caller that checked per frame would discover a dead token by
    /// watching frames fail, which is the 403 path the entry says to avoid.
    pub fn is_expired_at(&self, now_ms: i64) -> Result<bool, TokenError> {
        Ok(now_ms >= self.facts()?.expires_ms)
    }
}

impl fmt::Debug for RelayToken {
    /// ⛔ **A fixed string, and not a `DebugStruct` over the fields.** ⛔ A
    /// derived `Debug` would print `RelayToken { bytes: [...] }`; this prints
    /// one constant. ⛔ **The reason a *derived* one is impossible here is
    /// `Drop`**: ⛔ `rustc` has no derive for a type that implements `Drop`, so
    /// ⛔ the only way this type can have a `Debug` is for somebody to write one
    /// ⛔ — and the one they wrote does not read `self.bytes`. ⛔ **That is the
    /// structural half of the guarantee**, and the reason this comment can
    /// claim more than a hand-written impl normally could.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Drop for RelayToken {
    fn drop(&mut self) {
        // ⛔ `Zeroize` rather than a manual overwrite: it is the crate that
        // cannot be optimised away by a release build's dead-store elimination,
        // which is the same reason `AGENTS.md` requires zeroizing over `String`.
        self.bytes.zeroize();
    }
}

impl FromStr for RelayToken {
    type Err = TokenError;

    /// ⛔ **Parsing a token does not validate it.** A mint response, a cached file
    /// and a `ssh_config`-style override all arrive as text, and ⛔ rejecting one
    /// here would mean refusing a credential whose *shape* is not what this
    /// version of the spec says. ⛔ [`RelayToken::facts`] is where the shape is
    /// checked, and a caller that never asks for the facts accepts any
    /// non-empty credential — which is what a relay that changes its prefix
    /// needs.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(TokenError::Empty);
        }
        if trimmed.bytes().any(|b| b.is_ascii_whitespace() || b < 0x21 || b > 0x7e) {
            // ⛔ A token is an HTTP header value. A newline here is a header
            // injection, not a malformed token, and it is refused at the parse.
            return Err(TokenError::NotHeaderSafe);
        }
        Ok(RelayToken::new(trimmed.as_bytes().to_vec()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Empty,
    NotHeaderSafe,
    NotUtf8,
    Shape,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TokenError::Empty => "the token is empty",
            TokenError::NotHeaderSafe => {
                "the token is not a legal HTTP header value (whitespace or a control byte)"
            }
            TokenError::NotUtf8 => "the token is not UTF-8",
            TokenError::Shape => {
                "the token is not ephm1.<expiry-ms>.<role>.<mac> as the relay specification describes"
            }
        };
        f.write_str(s)
    }
}

impl std::error::Error for TokenError {}
