//! The relay's end of a pipe (T-175): `relay:HOST:PORT`, and the one road
//! of `podssh proxy`.
//!
//! The session carries the bytes in binary frames; the relay's keepalives,
//! the empty frames, are dropped. The end of what the pipe sends sends no
//! Close: the relay has no half-close, and a Close stops the target's bytes
//! after 15 s of silence (`docs/relay.md`), so the target's bytes come until
//! it closes. The ping watcher finds a link that died with no word. When
//! the relay ends the session, nothing more can come, and the pipe ends.
//!
//! Two tasks copy between the session and the pump's end of a pipe in
//! memory. When the task that sends fails, it stops the task that receives,
//! so that the pipe closes and the pump's write fails, as in T-269.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use podssh_relay::open::Request;
use podssh_relay::relay::RelayList;
use podssh_ws::session::close_code_and_reason;
use podssh_ws::{frame, RelaySession, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::pump::{End, Ending, Verdict};
use crate::exitmap::sysexits::EX_UNAVAILABLE;

/// The pipe in memory, each way.
const PIPE: usize = 256 * 1024;
/// The largest frame sent, as the pump reads.
const CHUNK: usize = 32 * 1024;

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

/// The relay hosts, and the trust of their TLS.
pub struct Road<'a> {
    pub relays: &'a RelayList,
    pub trust: &'a Trust,
}

/// A session to `host:port` through the relay, `path` already checked: the
/// end, or the exit code once `say` has the lines of the failure.
pub async fn open(road: &Road<'_>, host: &str, port: u16, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    let path = podssh_relay::relay::forward_path(host, port).map_err(|why| {
        say(&why);
        crate::exit_codes::EXIT_USAGE
    })?;
    let target = podssh_ws::dial::authority(host, port);
    let request = Request { relays: road.relays, path: &path, trust: road.trust, target: &target, rounds: 1 };
    match podssh_relay::open(&request, &mut |note: &str| say(note)).await {
        Ok(opened) => Ok(carry(opened.session, target, podssh_relay::relay::is_ipv6_literal(host))),
        Err(failure) => {
            for line in failure.lines(&target) {
                say(&line);
            }
            Err(crate::proxy::sysexit(failure.last()))
        }
    }
}

/// The end of an open session to `target` (`host:port`); `v6` for the note
/// on an IPv6 target that closes at once.
pub fn carry(session: RelaySession, target: String, v6: bool) -> End {
    let session = Arc::new(session);
    let status = Arc::new(Status::default());
    let up_failed = Arc::new(Notify::new());
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (mut from_pipe, mut to_pipe) = tokio::io::split(theirs);

    let (up_session, up_status, up_failed_tx) = (session.clone(), status.clone(), up_failed.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            // The end of what the pipe sends: no Close (see above).
            let n = from_pipe.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            if let Err(e) = up_session.send_binary(&buf[..n]).await {
                up_status.set_once(Ended::Failed(format!("sending to the relay failed: {e}")));
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
                Err(e) => {
                    down_status.set_once(Ended::Failed(e.to_string()));
                    break;
                }
            };
            match f.opcode {
                frame::OPCODE_BINARY if f.payload.is_empty() => {} // the relay's keepalive
                frame::OPCODE_BINARY => {
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
                frame::OPCODE_TEXT => {
                    down_status.set_once(Ended::Failed("the relay sent a text frame on the forward path".into()));
                    break;
                }
                other => {
                    let why = format!("the relay sent an unexpected frame (opcode {other:#x})");
                    down_status.set_once(Ended::Failed(why));
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
        ending: Some(Box::new(RelayEnding { session, status, down, target, v6 })),
    }
}

struct RelayEnding {
    session: Arc<RelaySession>,
    status: Arc<Status>,
    down: JoinHandle<()>,
    target: String,
    v6: bool,
}

impl Ending for RelayEnding {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        Box::pin(async move {
            let RelayEnding { session, status, down, target, v6 } = *self;
            match status.get() {
                // 1000 is a normal end (the target closed). The relay uses
                // 1001 for its own limits, which are not.
                Some(Ended::Closed { code: None | Some(1000), .. }) => None,
                Some(Ended::Closed { code: Some(code), reason }) => {
                    // The hop first; `CODE REASON` stays as the relay wrote it.
                    let leg = podssh_ws::session::forward_close(Some(code), &reason);
                    let mut lines = vec![format!("{}: {code} {reason}", leg.what(&target))];
                    lines.extend(leg.remedy(&reason).map(str::to_string));
                    lines.extend(podssh_relay::relay::ipv6_note(v6, &reason).map(str::to_string));
                    Some((EX_UNAVAILABLE, lines))
                }
                Some(Ended::Failed(why)) => Some((EX_UNAVAILABLE, vec![why])),
                // The pipe ended first (its reader left, or the other side
                // had no more to say): a Close of its own, a clean end.
                None => {
                    down.abort();
                    let _ = session.send_close(1000, "").await;
                    None
                }
            }
        })
    }
}
