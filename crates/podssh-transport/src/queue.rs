//! The queue double of [`Socket`]: frames in and frames out, with no
//! network. It lives apart from `socket.rs` to keep that file under the
//! 500-line limit; `socket::FrameQueue` still names it.

use std::collections::VecDeque;

use crate::error::TransportError;
use crate::socket::{Socket, WireFrame};

/// ⛔ **A socket that is a queue. ⛔ This is the seam E02's acceptance runs on.**
///
/// ⛔ **It records the exact bytes that went out**, so a test can assert the wire
/// image rather than "something was sent". E02's `Prove` block is explicit that
/// *"a test that only checks that 'something was sent' cannot catch this class of
/// bug"*, and a fake that stored only a frame *count* would be exactly that
/// test.
#[derive(Debug, Default)]
pub struct FrameQueue {
    outbound: Vec<WireFrame>,
    inbound: VecDeque<WireFrame>,
    failure: Option<TransportError>,
}

impl FrameQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// ⛔ **Queue a binary frame as if the relay had sent it.**
    pub fn push_binary(&mut self, payload: Vec<u8>) {
        self.inbound.push_back(WireFrame::Binary(payload));
    }

    /// ⛔ **Queue a text frame as if the relay had sent it.**
    pub fn push_text(&mut self, payload: Vec<u8>) {
        self.inbound.push_back(WireFrame::Text(payload));
    }

    /// ⛔ **Make the next read fail, for a close-path test.**
    pub fn fail_with(&mut self, error: TransportError) {
        self.failure = Some(error);
    }

    /// ⛔ **The exact bytes that went out, in order.** ⛔ This is the assertion
    /// surface: `assert_eq!(wire(), expected)` and nothing weaker.
    pub fn wire(&self) -> &[WireFrame] {
        &self.outbound
    }

    /// ⛔ **The binary payloads that went out, in order, concatenated.** ⛔ For a
    /// test that cares about the byte image and not the frame boundaries —
    /// ⛔ **and frame boundaries carry no meaning**, so this is a legitimate view
    /// and not a weaker one.
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for frame in &self.outbound {
            if let WireFrame::Binary(bytes) = frame {
                out.extend_from_slice(bytes);
            }
        }
        out
    }

    pub fn wire_text(&self) -> Vec<String> {
        self.outbound
            .iter()
            .filter_map(|frame| match frame {
                WireFrame::Text(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
                WireFrame::Binary(_) => None,
            })
            .collect()
    }
}

impl Socket for FrameQueue {
    async fn send_binary(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        self.outbound.push(WireFrame::Binary(payload.to_vec()));
        Ok(())
    }

    async fn send_text(&mut self, text: &[u8]) -> Result<(), TransportError> {
        self.outbound.push(WireFrame::Text(text.to_vec()));
        Ok(())
    }

    fn sent_frames(&self) -> usize {
        self.outbound.len()
    }

    async fn recv(&mut self) -> Result<WireFrame, TransportError> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.inbound
            .pop_front()
            .ok_or_else(|| TransportError::Aborted { clean: true, detail: "the queue is empty".into() })
    }
}
