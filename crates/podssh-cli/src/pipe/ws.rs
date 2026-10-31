//! The end of a WebSocket (T-368): `ws://` and `wss://` that the user
//! names, and each client of `ws-listen:`. Bytes go out in binary frames,
//! and text and binary frames come in as bytes. At the end of this side's
//! input a Close 1000 goes out, and what the other end sends before its own
//! Close still comes, as RFC 6455 section 5.5.1 lets it; the other end's
//! Close, answered at once, ends the pipe, as nothing more can come. A close
//! other than 1000 says its code and its reason on stderr, and the pipe
//! exits 69. `ws:` is in the clear, as `tcp:` is; no token goes on it.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use podssh_ws::session::close_code_and_reason;
use podssh_ws::url::WsUrl;
use podssh_ws::{frame, ConnectError, DialError, ProxyChoice, RelaySession, SessionError, Trust};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::pump::{End, Ending, Reader, Verdict, Writer};
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};

/// The pipe in memory, each way.
const PIPE: usize = 256 * 1024;
/// The largest frame sent, as the pump reads.
const CHUNK: usize = 32 * 1024;

/// Dial `url`: the end, or the exit code once `say` has the line.
pub async fn open(url: &WsUrl, trust: &Trust, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    if podssh_relay::open::offline() {
        say(&format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV));
        return Err(EX_UNAVAILABLE);
    }
    let (timeout, idle) = (podssh_relay::open::CONNECT_TIMEOUT, Some(podssh_ws::DEFAULT_IDLE_TIMEOUT));
    match podssh_ws::url::dial(url, trust, &ProxyChoice::FromEnvironment, timeout, idle).await {
        Ok(session) => Ok(carry(session, url.shown())),
        Err(e) => {
            say(&podssh_ws::url::failure(url, &e));
            Err(code(&e))
        }
    }
}

/// The exit code of a dial that failed: 77 for a refusal, 78 for a setting.
fn code(e: &ConnectError) -> i32 {
    match e {
        ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)) => EX_CONFIG,
        ConnectError::Refused { status: 401 | 403, .. } => EX_NOPERM,
        ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

/// How the session ended; the first word wins.
#[derive(Debug, Clone)]
enum Ended {
    Closed { code: Option<u16>, reason: String },
    Failed(String),
}

#[derive(Default)]
struct Status(Mutex<Option<Ended>>);

impl Status {
    fn set_once(&self, ended: Ended) {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(ended);
        }
    }

    fn get(&self) -> Option<Ended> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// The end of an open session; `shown` names the other end in its lines.
pub fn carry<S>(session: RelaySession<S>, shown: String) -> End
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let session = Arc::new(session);
    let status = Arc::new(Status::default());
    let up_failed = Arc::new(Notify::new());
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (mut from_pipe, mut to_pipe) = tokio::io::split(theirs);

    let (up_session, up_status, up_failed_tx) = (session.clone(), status.clone(), up_failed.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = from_pipe.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                // This side has no more to say; the other end's bytes still come.
                let _ = up_session.send_close(1000, "").await;
                return;
            }
            if let Err(e) = up_session.send_binary(&buf[..n]).await {
                up_status.set_once(Ended::Failed(format!("sending failed: {e}")));
                up_failed_tx.notify_one();
                return;
            }
        }
    });

    let (down_session, down_status) = (session.clone(), status.clone());
    let down = tokio::spawn(async move {
        let liveness = down_session.watch_liveness(podssh_ws::LIVENESS_EVERY, podssh_ws::LIVENESS_ALLOWED);
        tokio::pin!(liveness);
        loop {
            let read = tokio::select! {
                read = down_session.read_frame() => read,
                reason = &mut liveness => {
                    down_status.set_once(Ended::Failed(reason.to_string()));
                    break;
                }
                () = up_failed.notified() => break,
            };
            let f = match read {
                Ok(f) => f,
                // After this side's Close, an end with no Close is the end.
                Err(SessionError::ClosedWithoutClose(_)) if down_session.close_sent() => {
                    down_status.set_once(Ended::Closed { code: None, reason: String::new() });
                    break;
                }
                Err(e) => {
                    down_status.set_once(Ended::Failed(e.to_string()));
                    break;
                }
            };
            match f.opcode {
                frame::OPCODE_BINARY | frame::OPCODE_TEXT => {
                    let wrote = tokio::select! {
                        wrote = to_pipe.write_all(&f.payload) => wrote.is_ok(),
                        () = up_failed.notified() => false,
                    };
                    if !wrote {
                        break;
                    }
                }
                frame::OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    down_status.set_once(Ended::Closed { code, reason });
                    break;
                }
                other => {
                    down_status.set_once(Ended::Failed(format!("an unexpected frame (opcode {other:#x})")));
                    break;
                }
            }
        }
        let _ = to_pipe.shutdown().await;
    });

    let (read, write) = tokio::io::split(ours);
    End {
        read: Box::new(read),
        write: Box::new(write),
        child: None,
        last_word: true,
        ending: Some(Box::new(WsEnding { session, status, down, shown })),
    }
}

struct WsEnding<S> {
    session: Arc<RelaySession<S>>,
    status: Arc<Status>,
    down: JoinHandle<()>,
    shown: String,
}

impl<S> Ending for WsEnding<S>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        Box::pin(async move {
            let WsEnding { session, status, down, shown } = *self;
            match status.get() {
                Some(Ended::Closed { code: None | Some(1000), .. }) => None,
                Some(Ended::Closed { code: Some(code), reason }) => {
                    Some((EX_UNAVAILABLE, vec![format!("{shown} closed the WebSocket: {code} {reason}")]))
                }
                Some(Ended::Failed(why)) => Some((EX_UNAVAILABLE, vec![format!("{shown}: {why}")])),
                // The pipe ended first: its reader left, or the other side
                // had no more to say. A Close of its own, a clean end.
                None => {
                    down.abort();
                    let _ = session.send_close(1000, "").await;
                    None
                }
            }
        })
    }
}

/// A reader and a writer of a pipe's end as one stream, as a session takes
/// it: the client of a listener, whose halves the listener gave apart.
pub struct Joined {
    pub read: Reader,
    pub write: Writer,
}

impl AsyncRead for Joined {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for Joined {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}
