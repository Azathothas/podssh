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
//! token).

use std::sync::{Arc, Mutex};

use podssh_ws::frame;
use podssh_ws::session::close_code_and_reason;
use podssh_ws::RelaySession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

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
    /// The connection failed without a Close.
    Failed(String),
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

/// Where the copying tasks leave the reason the relay leg ended. Cloneable;
/// all clones see the same value. The first reason recorded wins.
#[derive(Debug, Clone, Default)]
pub struct RelayStatus(Arc<Mutex<Option<RelayEnd>>>);

impl RelayStatus {
    pub fn get(&self) -> Option<RelayEnd> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_once(&self, end: RelayEnd) {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(end);
        }
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

    let up_session = session.clone();
    let up_status = status.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match from_ssh.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    // SSH is done with the connection: close it properly.
                    let _ = up_session.send_close(1000, "").await;
                    break;
                }
                Ok(n) => {
                    if let Err(e) = up_session.send_binary(&buf[..n]).await {
                        up_status.set_once(RelayEnd::Failed(format!("sending failed: {e}")));
                        break;
                    }
                }
            }
        }
    });

    let down_status = status.clone();
    tokio::spawn(async move {
        loop {
            match session.read_frame().await {
                Ok(f) if f.opcode == frame::OPCODE_BINARY => {
                    // An empty frame is the relay's keepalive, not data.
                    if !f.payload.is_empty() && to_ssh.write_all(&f.payload).await.is_err() {
                        break;
                    }
                }
                Ok(f) if f.opcode == frame::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    down_status.set_once(RelayEnd::Closed { code, reason });
                    break;
                }
                Ok(f) => {
                    down_status.set_once(RelayEnd::Failed(format!(
                        "unexpected frame (opcode {:#x}) on the forward path",
                        f.opcode
                    )));
                    let _ = session.send_close(1002, "").await;
                    break;
                }
                Err(e) => {
                    down_status.set_once(RelayEnd::Failed(e));
                    break;
                }
            }
        }
        // End of stream for russh.
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
        assert!(RelayEnd::Failed("reset".into()).explain().unwrap().contains("reset"));
    }
}
