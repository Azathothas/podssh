//! A relay session as the byte stream russh needs.
//!
//! The relay carries the TCP stream in binary WebSocket frames whose
//! boundaries mean nothing. Two tasks copy between one end of an in-memory
//! duplex pipe and the session: SSH bytes out as binary frames, binary frames
//! back in as SSH bytes, the relay's empty keepalive frames dropped. The other
//! end of the pipe is what russh reads and writes.
//!
//! When the relay ends the session, its close code and reason are kept in a
//! [`RelayStatus`], because SSH alone can only say "the connection closed",
//! while the relay often says why (an idle cut, the 64 MiB limit, an expired
//! token). The status also counts the payload bytes both ways, as the relay
//! counts its cap, so that a copy can open a new session first (T-137).
//!
//! When one task ends with the link, it stops the other: russh can wait on a
//! write into the pipe that only the sending task reads, while the receiving
//! task waits for russh to read, and neither would see the broken link.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_ws::frame;
use podssh_ws::session::close_code_and_reason;
use podssh_ws::{RelaySession, SessionError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

/// Size of the in-memory pipe in each direction.
const PIPE: usize = 256 * 1024;
/// The largest frame sent. The relay accepts 262144 bytes; SSH packets are
/// far smaller, so this only bounds a burst.
const CHUNK: usize = 64 * 1024;

/// How the relay leg ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEnd {
    /// The relay (or this side) sent a WebSocket Close.
    Closed { code: Option<u16>, reason: String },
    /// The connection failed without a Close, by the class of the failure;
    /// it prints the same text as before the classes.
    Failed(SessionError),
}

impl RelayEnd {
    /// A sentence for the user, or `None` for an ordinary close that SSH
    /// already explains.
    pub fn explain(&self) -> Option<String> {
        match self {
            RelayEnd::Closed { code: None | Some(1000), reason } if reason.is_empty() => None,
            RelayEnd::Closed { code: Some(code), reason } if reason.is_empty() => {
                Some(format!("the relay closed the connection (code {code})"))
            }
            RelayEnd::Closed { code: Some(code), reason } => {
                Some(format!("the relay closed the connection (code {code}): {reason}"))
            }
            RelayEnd::Closed { code: None, reason } => Some(format!("the relay closed the connection: {reason}")),
            RelayEnd::Failed(why) => Some(format!("the relay connection failed: {why}")),
        }
    }
}

/// Where the copying tasks leave the reason the relay leg ended, and the
/// payload bytes that they carried. Cloneable; all clones see the same
/// values. The first reason recorded wins.
#[derive(Debug, Clone)]
pub struct RelayStatus {
    end: Arc<Mutex<Option<RelayEnd>>>,
    bytes: Arc<AtomicU64>,
    started: Instant,
}

impl Default for RelayStatus {
    fn default() -> Self {
        RelayStatus { end: Arc::default(), bytes: Arc::default(), started: Instant::now() }
    }
}

impl RelayStatus {
    pub fn get(&self) -> Option<RelayEnd> {
        self.end.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_once(&self, end: RelayEnd) {
        let mut slot = self.end.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(end);
        }
    }

    fn count(&self, n: usize) {
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// The payload bytes of the session so far, out and in together: what
    /// the relay counts against its cap. Keepalives carry none.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// How long ago the session began.
    pub fn age(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Start copying between `session` and a new pipe; returns russh's end of the
/// pipe. Must be called inside a tokio runtime.
pub fn spawn<S>(session: RelaySession<S>) -> (DuplexStream, RelayStatus)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let status = RelayStatus::default();
    let session = Arc::new(session);
    let (mut from_ssh, mut to_ssh) = tokio::io::split(theirs);
    // Each task's end with the link stops the other; the pipe then closes,
    // and a write of russh's that waits on it fails.
    let up_failed = Arc::new(Notify::new());
    let down_ended = Arc::new(Notify::new());

    let up_session = session.clone();
    let up_status = status.clone();
    let (up_failed_tx, down_ended_rx) = (up_failed.clone(), down_ended.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let read = tokio::select! {
                read = from_ssh.read(&mut buf) => read,
                () = down_ended_rx.notified() => break,
            };
            match read {
                Ok(0) | Err(_) => {
                    // SSH is done with the connection: close it properly.
                    let _ = up_session.send_close(1000, "").await;
                    break;
                }
                Ok(n) => {
                    let sent = tokio::select! {
                        sent = up_session.send_binary(&buf[..n]) => sent,
                        () = down_ended_rx.notified() => break,
                    };
                    if let Err(e) = sent {
                        up_status.set_once(RelayEnd::Failed(e.context("sending failed")));
                        up_failed_tx.notify_one();
                        break;
                    }
                    up_status.count(n);
                }
            }
        }
    });

    let down_status = status.clone();
    tokio::spawn(async move {
        // A link that dies without a word is found by pinging, in about 30 s
        // instead of at the 90 s idle read limit.
        let liveness = session.watch_liveness(podssh_ws::LIVENESS_EVERY, podssh_ws::LIVENESS_ALLOWED);
        tokio::pin!(liveness);
        loop {
            let frame = tokio::select! {
                frame = session.read_frame() => frame,
                reason = &mut liveness => {
                    down_status.set_once(RelayEnd::Failed(reason));
                    break;
                }
                () = up_failed.notified() => break,
            };
            match frame {
                Ok(f) if f.opcode == frame::OPCODE_BINARY => {
                    // An empty frame is the relay's keepalive, not data.
                    down_status.count(f.payload.len());
                    if !f.payload.is_empty() {
                        // russh may not read while it waits on its own write.
                        let wrote = tokio::select! {
                            wrote = to_ssh.write_all(&f.payload) => wrote.is_ok(),
                            () = up_failed.notified() => false,
                        };
                        if !wrote {
                            break;
                        }
                    }
                }
                Ok(f) if f.opcode == frame::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    down_status.set_once(RelayEnd::Closed { code, reason });
                    break;
                }
                Ok(f) => {
                    down_status.set_once(RelayEnd::Failed(SessionError::Protocol(format!(
                        "unexpected frame (opcode {:#x}) on the forward path",
                        f.opcode
                    ))));
                    let _ = session.send_close(1002, "").await;
                    break;
                }
                Err(e) => {
                    down_status.set_once(RelayEnd::Failed(e));
                    break;
                }
            }
        }
        // End of stream for russh; the sending task stops too.
        down_ended.notify_one();
        let _ = to_ssh.shutdown().await;
    });

    (ours, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_close_needs_no_explanation() {
        assert_eq!(RelayEnd::Closed { code: Some(1000), reason: String::new() }.explain(), None);
        assert_eq!(RelayEnd::Closed { code: None, reason: String::new() }.explain(), None);
        let idle = RelayEnd::Closed { code: Some(1001), reason: "idle".into() };
        assert_eq!(idle.explain().unwrap(), "the relay closed the connection (code 1001): idle");
        let reset = SessionError::Io { kind: std::io::ErrorKind::ConnectionReset, text: "reset".into() };
        assert!(RelayEnd::Failed(reset).explain().unwrap().contains("reset"));
    }

    /// The relay counts its cap both ways together, and so does the status:
    /// each payload byte out and in, and no keepalive.
    #[tokio::test]
    async fn relay_count_sees_both_directions() {
        use podssh_ws::frame::{decode, encode, Frame, Role, OPCODE_BINARY};
        let (ours, mut relay) = tokio::io::duplex(1 << 20);
        let session = RelaySession::new(ours, Vec::new(), None, Duration::from_secs(5));
        let (mut ssh, status) = spawn(session);
        ssh.write_all(&[7u8; 1000]).await.expect("written");
        // What the relay reads: one masked frame of the 1000 bytes.
        let mut got = Vec::new();
        let mut buf = vec![0u8; 4096];
        let up = loop {
            let n = relay.read(&mut buf).await.expect("read");
            got.extend_from_slice(&buf[..n]);
            if let Some((frame, _)) = decode(&got, Role::Client).expect("a frame") {
                break frame;
            }
        };
        assert_eq!(up.payload, vec![7u8; 1000]);
        // A keepalive, then 500 bytes from the target.
        for payload in [Vec::new(), vec![9u8; 500]] {
            let frame = Frame { fin: true, opcode: OPCODE_BINARY, payload };
            relay.write_all(&encode(&frame, Role::Server, [0; 4])).await.expect("sent");
        }
        let mut back = vec![0u8; 500];
        ssh.read_exact(&mut back).await.expect("the target's bytes");
        assert_eq!(back, vec![9u8; 500]);
        assert_eq!(status.bytes(), 1500, "out and in together, no keepalive");
        assert!(status.age() < Duration::from_secs(60));
    }

    /// The link breaks while russh writes and does not read: the sending
    /// task fails, and the receiving task, which waits for russh to read what
    /// came before, must stop too, so that russh's write fails and does not
    /// wait for ever.
    #[tokio::test]
    async fn a_broken_link_ends_a_write_of_russh_that_nobody_reads() {
        use podssh_ws::frame::{encode, Frame, Role, OPCODE_BINARY};
        let (ours, mut relay) = tokio::io::duplex(1 << 20);
        let session = RelaySession::new(ours, Vec::new(), None, Duration::from_secs(30));
        let (ssh, status) = spawn(session);
        let (ssh_read, mut ssh_write) = tokio::io::split(ssh);
        // More than the pipe to russh holds: the receiving task waits.
        for _ in 0..8 {
            let frame = Frame { fin: true, opcode: OPCODE_BINARY, payload: vec![1u8; CHUNK] };
            relay.write_all(&encode(&frame, Role::Server, [0; 4])).await.expect("sent");
        }
        // More than the link and the pipe hold, which the relay does not read.
        let writer = tokio::spawn(async move {
            let chunk = vec![2u8; CHUNK];
            while ssh_write.write_all(&chunk).await.is_ok() {}
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!writer.is_finished(), "russh's write waits on the full link");
        drop(relay);
        tokio::time::timeout(Duration::from_secs(10), writer)
            .await
            .expect("russh's write ends once the link broke")
            .expect("the writer ended");
        assert!(matches!(status.get(), Some(RelayEnd::Failed(_))), "{:?}", status.get());
        drop(ssh_read);
    }
}
