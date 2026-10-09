//! The OS random source. `rand::rngs::OsRng` and nothing else.
//!
//! **No `small_rng`, no `StdRng::from_entropy`, no seeded fallback.** A
//! deterministic RNG anywhere in a protocol path is a key-recovery bug, and the
//! workspace manifest already says so in a comment; this module is where that
//! becomes a type.

use rustls::crypto::GetRandomFailed;

#[derive(Debug)]
pub struct OsRandom;

impl rustls::crypto::SecureRandom for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        fill_from(&mut rand::rngs::OsRng, buf)
    }
}

/// Fill `buf` from `source`, or report that it gave no bytes. Reading the OS
/// can fail (no `getrandom`, a seccomp filter, an exhausted descriptor
/// table), and `fill_bytes` of `rand_core` 0.6 then panics, which ends the
/// whole process where an error ends one session; `try_fill_bytes` returns
/// the error. There is still no degraded path: a failure is reported, never
/// answered with weaker bytes. The source is a parameter so that a test can
/// plant one that fails.
pub fn fill_from(source: &mut impl rand::RngCore, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
    source.try_fill_bytes(buf).map_err(|_| GetRandomFailed)
}
