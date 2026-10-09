//! podssh's `rustls::crypto::CryptoProvider`, in pure Rust.
//!
//! **The reason this module exists at all.** `ring` and `aws-lc-sys` both
//! need `cc` and both fail under `CC=/nonexistent`; MEASURED 2026-10-01, each
//! in isolation. `rustls-rustcrypto` does not resolve at any version, so there
//! is **no** built-in pure-Rust provider to name. podssh therefore supplies
//! its own, and the gate `scripts/dev.sh check` runs is what proves the
//! difference.
//!
//! **A provider is not a capability until it has exchanged a certificate
//! with a real peer.** Everything here was a proposal until
//! `tests/live_handshake.rs` completed a handshake against the live relay with
//! a verified chain; that test is the acceptance and it runs in CI, not only
//! on a developer machine.

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod kx;
pub mod random;
pub mod rsa_sig;
pub mod sign;
pub mod suites;

pub use suites::provider;
