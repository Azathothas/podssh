//! The SSH state machine — RFC 4251–4254 — and no I/O policy.
//!
//! ⛔ **Bytes in, bytes out.** Like `irc/`, this module owns no socket, no
//! clock, no dialing: the caller feeds frames and takes messages. That is
//! what makes every layer testable with vectors rather than waited for, and
//! it is the same seam E30 keeps (`podssh-core` never imports
//! `podssh-transport` or `podssh-ws` — grep-pinned by the workspace, not
//! trusted to review).
//!
//! Layout: `packet` (RFC 4253 §6 framing), `version` (§4.2 banner),
//! `types` (RFC 4251 §5 wire types), `kex` (KEXINIT + selection), `keys`
//! (ECDH + H + KDF + host verify), `cipher` (AEAD transport); `auth` and
//! `channel` arrives with Task 5.

pub mod auth;
pub mod channel;
pub mod cipher;
pub mod kex;
pub mod keys;
pub mod packet;
pub mod types;
pub mod version;
