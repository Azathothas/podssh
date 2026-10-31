//! The flow of one IAP session (T-351), with no I/O: the bytes of each
//! direction, the acknowledgements, and what a reconnect sends again.
//!
//! The rules of gcloud 570.0.0 (`iap_tunnel_websocket.py`) and of IAP
//! Desktop (`SshRelayStream.cs`): a client acknowledges once more than two
//! messages of data came since its last acknowledgement, before data that
//! it sends, and when it has had nothing to send for a while; the server's
//! acknowledgement confirms the client's bytes up to it, and one below the
//! last, or above what was sent, ends the session. After a reconnect the
//! server says which bytes it took, and the client sends the rest again,
//! so each byte that went stays until the server confirms it.

use std::collections::VecDeque;
use std::fmt;

use super::frame::MAX_DATA;

/// The bytes kept for a resend: past them a lost link ends the session, as
/// a reconnect could not send them again. gcloud and IAP Desktop keep each
/// one; podssh bounds what a stalled server can make it hold.
pub const KEEP: usize = 8 * 1024 * 1024;

/// The bytes of a session, both ways.
pub struct Flow {
    /// Bytes of data sent, and those that the server confirmed.
    sent: u64,
    confirmed: u64,
    /// The bytes after `confirmed`, in the messages that carried them.
    unconfirmed: VecDeque<Vec<u8>>,
    kept: usize,
    /// Whether `unconfirmed` holds each byte after `confirmed`.
    whole: bool,
    /// Bytes of data delivered, and the last acknowledgement of them.
    received: u64,
    acked: u64,
}

/// Why the server's word on the flow ends the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// An acknowledgement below one that came before.
    Backwards { ack: u64, confirmed: u64 },
    /// An acknowledgement of bytes that were never sent.
    Beyond { ack: u64, sent: u64 },
    /// A reconnect needs bytes that were not kept (more than [`KEEP`]).
    NotKept { lost: u64 },
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowError::Backwards { ack, confirmed } => {
                write!(f, "IAP acknowledged {ack} bytes after it had acknowledged {confirmed}")
            }
            FlowError::Beyond { ack, sent } => write!(f, "IAP acknowledged {ack} bytes of the {sent} that went"),
            FlowError::NotKept { lost } => write!(
                f,
                "the new link needs {lost} bytes sent again, more than the {} MiB that podssh keeps",
                KEEP >> 20
            ),
        }
    }
}

impl std::error::Error for FlowError {}

impl fmt::Debug for Flow {
    // The counts alone: the kept bytes are the session's.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flow")
            .field("sent", &self.sent)
            .field("confirmed", &self.confirmed)
            .field("kept", &self.kept)
            .field("whole", &self.whole)
            .field("received", &self.received)
            .field("acked", &self.acked)
            .finish()
    }
}

impl Default for Flow {
    fn default() -> Self {
        Flow::new()
    }
}

impl Flow {
    pub fn new() -> Flow {
        Flow { sent: 0, confirmed: 0, unconfirmed: VecDeque::new(), kept: 0, whole: true, received: 0, acked: 0 }
    }

    /// `chunk`, at most [`MAX_DATA`] bytes, goes out: counted, and kept
    /// until the server confirms it. It is kept before it goes, as gcloud
    /// keeps it: the server's acknowledgement can come before the send ends.
    pub fn sending(&mut self, chunk: &[u8]) {
        self.sent += chunk.len() as u64;
        if self.whole && self.kept + chunk.len() <= KEEP {
            self.kept += chunk.len();
            self.unconfirmed.push_back(chunk.to_vec());
        } else {
            self.unconfirmed.clear();
            self.kept = 0;
            self.whole = false;
        }
    }

    /// The server's acknowledgement of `ack` bytes of the client's stream.
    pub fn confirm(&mut self, ack: u64) -> Result<(), FlowError> {
        if ack < self.confirmed {
            return Err(FlowError::Backwards { ack, confirmed: self.confirmed });
        }
        if ack > self.sent {
            return Err(FlowError::Beyond { ack, sent: self.sent });
        }
        let mut drop = ack - self.confirmed;
        while drop > 0 {
            let Some(front) = self.unconfirmed.front_mut() else { break };
            let len = front.len() as u64;
            if len <= drop {
                drop -= len;
                self.kept -= front.len();
                self.unconfirmed.pop_front();
            } else {
                // The server took part of a message: the rest goes again.
                front.drain(..drop as usize);
                self.kept -= drop as usize;
                drop = 0;
            }
        }
        self.confirmed = ack;
        if self.confirmed == self.sent {
            self.unconfirmed.clear();
            self.kept = 0;
            self.whole = true;
        }
        Ok(())
    }

    /// `n` bytes of the server's data reached the reader.
    pub fn delivered(&mut self, n: usize) {
        self.received += n as u64;
    }

    /// The bytes of the server's stream delivered so far: where a new link
    /// takes the session up.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// The client's bytes that went, and those that the server confirmed.
    pub fn sent(&self) -> (u64, u64) {
        (self.sent, self.confirmed)
    }

    /// Whether an acknowledgement is due at once: more than two messages of
    /// data came since the last one, gcloud's rule.
    pub fn ack_due(&self) -> bool {
        self.received - self.acked > 2 * MAX_DATA as u64
    }

    /// The acknowledgement to send, when a byte came since the last one; it
    /// counts as sent.
    pub fn ack(&mut self) -> Option<u64> {
        (self.received > self.acked).then(|| {
            self.acked = self.received;
            self.received
        })
    }

    /// After a reconnect, the server took `ack` bytes: the messages to send
    /// again, in order, each at most [`MAX_DATA`] bytes. They stay kept
    /// until the server confirms them.
    pub fn resume(&mut self, ack: u64) -> Result<Vec<Vec<u8>>, FlowError> {
        self.confirm(ack)?;
        if !self.whole {
            return Err(FlowError::NotKept { lost: self.sent - self.confirmed });
        }
        Ok(self.unconfirmed.iter().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// gcloud's capture: 17 bytes went, the link was lost, and the reconnect's
    /// success said 10; gcloud sent `pture\r\n` again, and so does podssh.
    #[test]
    fn iap_resume_sends_again_what_the_server_did_not_take() {
        let mut flow = Flow::new();
        flow.sending(b"SSH-2.0-capture\r\n");
        assert_eq!(flow.resume(10).unwrap(), vec![b"pture\r\n".to_vec()]);
        // Still kept: a second loss before the server confirms them sends
        // them once more.
        assert_eq!(flow.resume(10).unwrap(), vec![b"pture\r\n".to_vec()]);
        flow.confirm(17).unwrap();
        assert_eq!(flow.resume(17).unwrap(), Vec::<Vec<u8>>::new());
        assert_eq!(flow.sent(), (17, 17));
    }

    #[test]
    fn iap_confirm_drops_whole_and_cut_messages() {
        let mut flow = Flow::new();
        for chunk in [&b"aaaa"[..], &b"bbbb"[..], &b"cccc"[..]] {
            flow.sending(chunk);
        }
        flow.confirm(6).unwrap();
        assert_eq!(flow.resume(6).unwrap(), vec![b"bb".to_vec(), b"cccc".to_vec()]);
        flow.confirm(8).unwrap();
        assert_eq!(flow.resume(8).unwrap(), vec![b"cccc".to_vec()]);
    }

    #[test]
    fn iap_an_ack_backwards_or_beyond_ends_the_session() {
        let mut flow = Flow::new();
        flow.sending(b"0123456789");
        flow.confirm(6).unwrap();
        assert_eq!(flow.confirm(5), Err(FlowError::Backwards { ack: 5, confirmed: 6 }));
        assert_eq!(flow.confirm(11), Err(FlowError::Beyond { ack: 11, sent: 10 }));
        // The same acknowledgement again is no fault, as IAP may send it.
        assert_eq!(flow.confirm(6), Ok(()));
        assert!(flow.resume(5).is_err());
    }

    /// An acknowledgement is due past twice 16 KiB, and one goes only for
    /// bytes that came since the last.
    #[test]
    fn iap_acks_follow_gcloud_s_rule() {
        let mut flow = Flow::new();
        assert_eq!(flow.ack(), None);
        flow.delivered(2 * MAX_DATA);
        assert!(!flow.ack_due(), "two messages are not yet due");
        flow.delivered(1);
        assert!(flow.ack_due());
        assert_eq!(flow.ack(), Some(2 * MAX_DATA as u64 + 1));
        assert!(!flow.ack_due());
        assert_eq!(flow.ack(), None);
        flow.delivered(5);
        assert_eq!(flow.ack(), Some(2 * MAX_DATA as u64 + 6));
        assert_eq!(flow.received(), 2 * MAX_DATA as u64 + 6);
    }

    /// Past the bound nothing is kept, and a reconnect that needs a byte
    /// says so; once the server confirmed each byte, the flow keeps again.
    #[test]
    fn iap_more_than_the_bound_is_not_kept() {
        let mut flow = Flow::new();
        let chunk = vec![1u8; MAX_DATA];
        for _ in 0..KEEP / MAX_DATA {
            flow.sending(&chunk);
        }
        assert_eq!(flow.resume(0).unwrap().len(), KEEP / MAX_DATA, "the bound itself is kept");
        flow.sending(b"one more");
        let lost = KEEP as u64 + 8;
        assert_eq!(flow.resume(0), Err(FlowError::NotKept { lost }));
        assert!(flow.resume(0).unwrap_err().to_string().contains("8 MiB"));
        flow.confirm(lost).unwrap();
        flow.sending(b"kept again");
        assert_eq!(flow.resume(lost).unwrap(), vec![b"kept again".to_vec()]);
    }
}
