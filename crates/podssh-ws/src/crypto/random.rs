//! The OS random source. `rand::rngs::OsRng` and nothing else.
//!
//! ⛔ **No `small_rng`, no `StdRng::from_entropy`, no seeded fallback.** A
//! deterministic RNG anywhere in a protocol path is a key-recovery bug, and the
//! workspace manifest already says so in a comment; this module is where that
//! becomes a type.

use rustls::crypto::GetRandomFailed;

#[derive(Debug)]
pub struct OsRandom;

impl rustls::crypto::SecureRandom for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        // ⛔ `rand_core 0.6`'s `RngCore` is implemented for `OsRng` directly —
        // it is infallible by construction, because it reads the OS and there
        // is no fallback. A `try_fill` that could fail would have to invent a
        // degraded path, and this is the one place in the crate where a
        // degraded path must not exist.
        use rand::RngCore as _;
        rand::rngs::OsRng.fill_bytes(buf);
        Ok(())
    }
}
