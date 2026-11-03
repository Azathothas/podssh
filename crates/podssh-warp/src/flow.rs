//! The counts of a tunnel's two pumps, which its stack keeps: the packets
//! that each way carried, the bytes of capsules that HTTP/2 took, and
//! whether the writer waits for HTTP/2's window now. A test that stalls
//! says them, beside each stack's connections, to name where the bytes
//! waited (T-599).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The counts of one tunnel.
#[derive(Debug, Default)]
pub struct Flow {
    /// Packets that came in the tunnel and went to the stack.
    inbound: AtomicU64,
    /// Bytes of the tunnel's stream that came in.
    received: AtomicU64,
    /// Packets that the stack gave, taken to go out.
    outbound: AtomicU64,
    /// Bytes of capsules that HTTP/2 took to send.
    sent: AtomicU64,
    /// Whether the writer waits for room in HTTP/2's window.
    waiting: AtomicBool,
}

impl Flow {
    pub(crate) fn came(&self, bytes: usize) {
        self.received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn handed_in(&self) {
        self.inbound.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn taken_out(&self) {
        self.outbound.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn sent(&self, bytes: usize) {
        self.sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn wait(&self, waiting: bool) {
        self.waiting.store(waiting, Ordering::Relaxed);
    }

    /// The counts in words.
    pub fn words(&self) -> String {
        let get = |n: &AtomicU64| n.load(Ordering::Relaxed);
        let waiting = if self.waiting.load(Ordering::Relaxed) { ", waiting for HTTP/2's window" } else { "" };
        format!(
            "{} packets in ({} bytes), {} out ({} bytes sent){waiting}",
            get(&self.inbound),
            get(&self.received),
            get(&self.outbound),
            get(&self.sent)
        )
    }
}
