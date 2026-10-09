//! ⛔ **The shared test harness: both legs, kept apart.**
//!
//! ⛔ **Every test in this suite drives the discipline through `feed` or `Session`,
//! never by touching internal state**, so no assertion can read something the
//! bytes did not produce.
//!
//! ⛔ **The two legs are separate fields and never merged.** ⛔ The entry names
//! the failure this prevents: *"the failure is the right bytes in the wrong
//! direction or the wrong sequence substituted."* ⛔ A single merged buffer
//! cannot tell those apart, so neither can a test that reads one.

#![allow(dead_code)] // each test file uses a subset; a shared harness is expected.

use podssh_terminal::echo::{Discipline, Event, Sig};

/// Drive a discipline with bytes and collect both legs separately.
pub fn feed(d: &mut Discipline, bytes: &[u8]) -> Legs {
    let mut legs = Legs::default();
    for b in bytes {
        for event in d.key(*b) {
            match event {
                Event::ToLocal(c) => legs.local.extend_from_slice(&c),
                Event::ToRemote(r) => legs.remote.extend_from_slice(&r),
                Event::Signal(s) => legs.signals.push(s),
                Event::Eof => legs.eof = true,
            }
        }
    }
    legs
}

/// What one input produced, one field per destination.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Legs {
    /// Bytes for the user's terminal.
    pub local: Vec<u8>,
    /// Bytes for the remote shell.
    pub remote: Vec<u8>,
    /// Signal characters, in order.
    pub signals: Vec<Sig>,
    /// Whether input ended.
    pub eof: bool,
}

impl Legs {
    /// ⛔ **A `Display` that prints every leg, so a failing assertion shows what
    /// arrived and not merely that something did.**
    pub fn show(&self) -> String {
        format!(
            "local={} remote={} signals={:?} eof={}",
            podssh_terminal::bytes::quoted(&self.local),
            podssh_terminal::bytes::quoted(&self.remote),
            self.signals,
            self.eof
        )
    }
}

/// ⛔ **The local bytes out of a `Vec<Event>` reply.** ⛔ The pass-through
/// discipline returns `Vec<Event>` where each `ToLocal` is one chunk, and a frame
/// arrives in several of them. ⛔ Concatenating them is exactly what the terminal
/// does, and ⛔ asserting on the concatenation is what makes "the frame is intact"
/// a byte-for-byte claim rather than a count.
pub trait LocalBytes {
    fn concat_local(&self) -> Vec<u8>;
}

impl LocalBytes for Vec<Event> {
    fn concat_local(&self) -> Vec<u8> {
        self.iter()
            .filter_map(|e| match e {
                Event::ToLocal(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }
}

/// ⛔ **True when `needle` occurs anywhere in `hay`.**
///
/// ⛔ **`Vec::contains` takes an element, not a slice**, so every subsequence
/// check in this suite goes through here. ⛔ The reference has the same helper
/// and the same reason for it — **READ**, `session.rs:770-774`, *"so
/// subsequence checks go through here"* — and ⛔ **a test written as
/// `hay.contains(&b'\x1b')` does not compile, which is how this error is caught
/// rather than asserted around.**
pub fn has(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}
