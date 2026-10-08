//! E12: the reverse-path triple, and what revoking it does.
//!
//! ⛔ **Spec lines 130-133**: `POST /v1/pair` (empty body or `'{}'`) returns
//! `{name, node_token, connect_token, stop_token, expires}`. ⛔ Four secrets and
//! a name, and the name is the only one that is not a credential.
//!
//! ⛔ **The `stopped` field is not a contract and is never read.**
//! `docs/research/verify/relay-spec-reverse.verify.md:411-415` records
//! `POST /v1/stop/<name>` returning `{"stopped":false,"sessions":0}` with no node
//! connected, *"and it still invalidated the pair"* — afterwards both
//! `node_token` and `connect_token` returned `403 reverse: forbidden`. ⛔ So
//! `stopped:false` does not mean "nothing happened", and a revocation routine
//! that branched on it would report a failure for a success.

use super::token::RelayToken;

/// ⛔ **The triple, plus the name it is scoped to.** ⛔ `stop_token` is held
/// because `/v1/stop` needs it, and it is ⛔ **revoked by the same wipe as the
/// other two** — a "revocation" that left the stop token on disk would have
/// left the one credential that can still destroy the pair.
#[derive(Debug)]
pub struct ReversePair {
    pub name: String,
    pub expires_ms: i64,
    pub node: RelayToken,
    pub connect: RelayToken,
    pub stop: RelayToken,
}

impl ReversePair {
    /// ⛔ **`Debug` is written by hand, not derived.** ⛔ A derived `Debug` over
    /// three `RelayToken`s is *safe today* because each of them redacts, and it
    /// is ⛔ **exactly the shape that stops being safe the day someone adds a
    /// fourth field of type `String`**. ⛔ The whole point of this module is
    /// that printing a credential is unrepresentable, so the one struct that
    /// holds four of them is the one struct that may not derive.
    pub fn new(
        name: impl Into<String>,
        expires_ms: i64,
        node: RelayToken,
        connect: RelayToken,
        stop: RelayToken,
    ) -> Self {
        ReversePair {
            name: name.into(),
            expires_ms,
            node,
            connect,
            stop,
        }
    }

    /// ⛔ What may be said about the pair: the name and the expiry. ⛔ Spec
    /// lines 97-100 say `expires` is within **72 h**.
    pub fn facts(&self) -> String {
        format!("pair {} expires {} ms since epoch", self.name, self.expires_ms)
    }

    /// ⛔ **What revoking a pair does, in the order podssh does it.**
    ///
    /// ⛔ 1. **Destroy the local copy.** This is the revocation, and it is the
    ///    one that is known to work.
    /// 2. **Then**, and only then, attempt the server-side stop. ⛔ The order
    ///    matters: ⛔ a routine that called the server first and branched on the
    ///    response would, on the `{"stopped": false}` the record contains, report
    ///    a failure ⛔ *after* the credentials were already destroyed*, and the
    ///    operator would go looking for a live credential that no longer exists.
    /// 3. **Report both, separately.** ⛔ `"local: destroyed, server: asked"` is
    ///    the honest sentence.
    pub fn revoke(&mut self) -> Revocation {
        self.node.expire();
        self.connect.expire();
        self.stop.expire();
        Revocation {
            name: self.name.clone(),
            local: LocalRevocation::Destroyed,
            server: ServerAttempt::NotAttempted,
        }
    }

    /// ⛔ **The server-side stop, and ⛔ the response is discarded.**
    ///
    /// ⛔ The signature takes the outcome of the HTTP call and returns nothing
    /// that depends on its body. ⛔ There is deliberately ⛔ **no `stopped: bool`
    /// field on [`ServerAttempt`]**, because a field nobody may read is a field
    /// somebody will read, and ⛔ the measurement says the field lies.
    pub fn record_server_attempt(&mut self, rev: &mut Revocation, ok: bool) {
        rev.server = if ok {
            ServerAttempt::Asked { body_ignored: true }
        } else {
            ServerAttempt::Unreachable
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRevocation {
    /// ⛔ The in-memory triple was zeroized and dropped.
    Destroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerAttempt {
    /// ⛔ **The body was read and thrown away.** ⛔ `{"stopped": false}` is a
    /// real observation and it means ⛔ **nothing about whether the credentials
    /// survived**, so the type records that the call was made and not what it
    /// said.
    Asked { body_ignored: bool },
    /// ⛔ The relay was not reachable. ⛔ **This is not a revocation
    /// failure**: the local copy is already gone, and the relay's own TTL of
    /// 72 h bounds the blast radius either way.
    Unreachable,
    NotAttempted,
}

impl std::fmt::Display for Revocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: local {}", self.name, self.local.as_str())?;
        match self.server {
            ServerAttempt::Asked { .. } => {
                f.write_str(", server asked (its answer is not a verdict)")
            }
            ServerAttempt::Unreachable => {
                f.write_str(", server unreachable (the local copy is already gone)")
            }
            ServerAttempt::NotAttempted => f.write_str(", server not asked"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub name: String,
    pub local: LocalRevocation,
    pub server: ServerAttempt,
}

impl LocalRevocation {
    fn as_str(self) -> &'static str {
        match self {
            LocalRevocation::Destroyed => "destroyed",
        }
    }
}
