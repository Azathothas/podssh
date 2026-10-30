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
//!
//! The status tells the relay's silence too (T-307): nothing below SSH
//! answers a key on this road, as the relay copies the bytes to the target,
//! so with SSH's bytes up, while no question waits, a Ping of podssh's
//! goes too; any frame of the relay answers it, a Pong or the target's
//! bytes. A notice in the terminal reads the silence while one waits.

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
/// The largest frame sent: one read of the pipe at most, so a burst of SSH
/// packets is cut where the relay's write to its socket stays safe.
const CHUNK: usize = frame::FORWARD_SEND_PAYLOAD;

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
    quiet: Arc<Quiet>,
}

impl Default for RelayStatus {
    fn default() -> Self {
        RelayStatus { end: Arc::default(), bytes: Arc::default(), started: Instant::now(), quiet: Arc::default() }
    }
}

/// The relay's frames so far, and when the last one came.
type Frames = dyn Fn() -> (u64, tokio::time::Instant) + Send + Sync;

/// What the status knows of the relay's silence: the question that waits,
/// when it was asked and the relay's frames until then; and the session's
/// count of frames, once the copying runs.
#[derive(Default)]
struct Quiet {
    asked: Mutex<Option<(tokio::time::Instant, u64)>>,
    frames: std::sync::OnceLock<Arc<Frames>>,
}

impl std::fmt::Debug for Quiet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Quiet").field("asked", &self.asked).finish()
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

    /// Whether to ask the relay, at `now`: when no question waits, or the
    /// one that did was answered; the question then starts.
    fn ask(&self, now: tokio::time::Instant) -> bool {
        let Some(frames) = self.quiet.frames.get() else { return false };
        let (heard, _) = frames();
        let mut asked = self.quiet.asked.lock().unwrap_or_else(|e| e.into_inner());
        match *asked {
            Some((_, before)) if heard <= before => false,
            _ => {
                *asked = Some((now, heard));
                true
            }
        }
    }

    /// How long the relay has said nothing, at `now`, when a question has
    /// waited `wait` or more for its answer; `None` while it answers, and
    /// before the copying runs.
    pub fn silent(&self, now: tokio::time::Instant, wait: Duration) -> Option<Duration> {
        let frames = self.quiet.frames.get()?;
        let (heard, last) = frames();
        let mut asked = self.quiet.asked.lock().unwrap_or_else(|e| e.into_inner());
        let (at, before) = (*asked)?;
        if heard > before {
            *asked = None;
            return None;
        }
        if now.saturating_duration_since(at) < wait {
            return None;
        }
        Some(now.saturating_duration_since(last))
    }
}

/// The payload of the Ping that asks: none of `podssh ping`'s, which are
/// eight bytes of a count.
const ASK: &[u8] = b"podssh-ask";

/// Start copying between `session` and a new pipe; returns russh's end of the
/// pipe. Must be called inside a tokio runtime.
pub fn spawn<S>(session: RelaySession<S>) -> (DuplexStream, RelayStatus)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let status = RelayStatus::default();
    let session = Arc::new(session);
    let counted = session.clone();
    let frames: Arc<Frames> = Arc::new(move || (counted.frames_received(), counted.last_heard()));
    let _ = status.quiet.frames.set(frames);
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
                    // A question that the relay answers at once (T-307);
                    // a send that fails is the next write's to find.
                    if up_status.ask(tokio::time::Instant::now()) {
                        let _ = up_session.send_ping(ASK).await;
                    }
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

    /// A burst from russh reaches the relay in frames of 32 KiB at most, with
    /// its bytes in order (T-323): a frame above 64 KiB can break the relay's
    /// socket (workerd issue 7074).
    #[tokio::test]
    async fn a_burst_reaches_the_relay_in_frames_that_stay_small() {
        use podssh_ws::frame::{decode, Role, FORWARD_SEND_PAYLOAD, OPCODE_BINARY, OPCODE_PING};
        let (ours, mut relay) = tokio::io::duplex(1 << 21);
        let session = RelaySession::new(ours, Vec::new(), None, Duration::from_secs(30));
        let (mut ssh, _status) = spawn(session);
        let sent: Vec<u8> = (0..1 << 20).map(|i: u32| (i * 7 % 251) as u8).collect();
        ssh.write_all(&sent).await.expect("written");
        let (mut wire, mut got, mut pings) = (Vec::new(), Vec::new(), 0);
        while got.len() < sent.len() {
            let mut buf = vec![0u8; 1 << 16];
            let n =
                tokio::time::timeout(Duration::from_secs(10), relay.read(&mut buf)).await.expect("in time").unwrap();
            wire.extend_from_slice(&buf[..n]);
            while let Some((frame, used)) = decode(&wire, Role::Client).expect("a frame") {
                assert!(frame.payload.len() <= FORWARD_SEND_PAYLOAD, "a frame of {} bytes", frame.payload.len());
                match frame.opcode {
                    OPCODE_BINARY => got.extend_from_slice(&frame.payload),
                    OPCODE_PING => pings += 1,
                    other => panic!("a frame of opcode {other:#x}"),
                }
                wire.drain(..used);
            }
        }
        assert_eq!(got, sent, "the bytes, in order");
        assert_eq!(pings, 1, "one question, which the relay here never answers (T-307)");
    }

    /// The frames that the relay reads, `n` of them, within a limit.
    async fn frames_up(relay: &mut tokio::io::DuplexStream, n: usize) -> Vec<podssh_ws::frame::Frame> {
        use podssh_ws::frame::{decode, Role};
        let (mut wire, mut frames) = (Vec::new(), Vec::new());
        while frames.len() < n {
            let mut buf = vec![0u8; 4096];
            let got = tokio::time::timeout(Duration::from_secs(5), relay.read(&mut buf)).await.expect("in time");
            wire.extend_from_slice(&buf[..got.expect("read")]);
            while let Some((frame, used)) = decode(&wire, Role::Client).expect("a frame") {
                frames.push(frame);
                wire.drain(..used);
            }
        }
        frames
    }

    /// The relay's silence (T-307): SSH's bytes up ask with a Ping while no
    /// question waits; once one waited `wait`, the silence counts from the
    /// relay's last frame; and any frame answers it, a Pong as the target's
    /// bytes.
    #[tokio::test]
    async fn the_relay_s_silence_shows_once_a_question_waits_and_any_frame_answers_it() {
        use podssh_ws::frame::{encode, Frame, Role, OPCODE_BINARY, OPCODE_PING, OPCODE_PONG};
        let (ours, mut relay) = tokio::io::duplex(1 << 20);
        let session = RelaySession::new(ours, Vec::new(), None, Duration::from_secs(5));
        let (mut ssh, status) = spawn(session);
        let wait = Duration::from_millis(300);
        let now = tokio::time::Instant::now;
        assert_eq!(status.silent(now(), wait), None, "no question yet");
        ssh.write_all(b"k").await.expect("a key");
        let up = frames_up(&mut relay, 2).await;
        assert_eq!((up[0].opcode, &up[0].payload[..]), (OPCODE_BINARY, &b"k"[..]));
        assert_eq!((up[1].opcode, &up[1].payload[..]), (OPCODE_PING, ASK));
        // A second key while the question waits asks nothing more.
        ssh.write_all(b"e").await.expect("a key");
        assert_eq!(frames_up(&mut relay, 1).await[0].payload, b"e");
        let mut buf = [0u8; 64];
        let more = tokio::time::timeout(Duration::from_millis(200), relay.read(&mut buf)).await;
        assert!(more.is_err(), "no second Ping while one waits");
        assert_eq!(status.silent(now(), Duration::from_secs(60)), None, "not yet: the question is young");
        tokio::time::sleep(wait).await;
        let silent = status.silent(now(), wait).expect("silent once the question waited");
        assert!(silent >= wait, "counted from the relay's last frame: {silent:?}");
        // The Pong answers it.
        let pong = Frame { fin: true, opcode: OPCODE_PONG, payload: ASK.to_vec() };
        relay.write_all(&encode(&pong, Role::Server, [0; 4])).await.expect("a Pong");
        let deadline = now() + Duration::from_secs(5);
        while status.silent(now(), wait).is_some() {
            assert!(now() < deadline, "the Pong did not answer the question");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // A new key asks again, and the target's bytes answer it.
        ssh.write_all(b"y").await.expect("a key");
        let up = frames_up(&mut relay, 2).await;
        assert_eq!((up[1].opcode, &up[1].payload[..]), (OPCODE_PING, ASK));
        let echo = Frame { fin: true, opcode: OPCODE_BINARY, payload: b"y".to_vec() };
        relay.write_all(&encode(&echo, Role::Server, [0; 4])).await.expect("the echo");
        let mut back = [0u8; 1];
        ssh.read_exact(&mut back).await.expect("the echo");
        tokio::time::sleep(wait).await;
        assert_eq!(status.silent(now(), wait), None, "the target's bytes answered it");
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
