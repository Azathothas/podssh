//! `podssh chat` (T-099): the run of either side, its ends from outside (the
//! `--timeout`, Ctrl-C), and its exit code. One side waits as the node of a
//! pair (`listen`), and the other reaches it (`reach`); while no peer is
//! there, the user's lines wait in memory (`lines`).

use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use serde_json::json;
use tokio::io::AsyncWrite;
use tokio::time::Instant;

use super::args::{self, ChatArgs, Input, Peer, Side};
use super::converse::{Ended, Once, Options};
use super::lines::Lines;
use super::output::{safe, Output};
use super::{iroh, listen, reach};
use crate::exitmap::sysexits::{EX_NOPERM, EX_SOFTWARE, EX_TEMPFAIL, EX_UNAVAILABLE};
use crate::exitmap::Fault;

/// How long the last session may take to close once the conversation ended.
pub(super) const CLOSE_WAIT: Duration = Duration::from_secs(10);

/// Run the verb; returns the process exit code.
pub fn run_chat(
    args: &ChatArgs,
    deadline: Option<Duration>,
    jsonl: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let args::Plan { side, opts, input } = match args::plan(args) {
        Ok(plan) => plan,
        Err(refusal) => return refusal.report("chat", err),
    };
    let ready = match side {
        Side::Listen { label, place, allow, iroh: false } => {
            listen::prepare(label, &place, allow, args).map(|ready| Ready::Listen(Box::new(ready)))
        }
        Side::Listen { label, place, allow, iroh: true } => {
            iroh::prepare_waiting(label, place, allow, args).map(|ready| Ready::Both(Box::new(ready)))
        }
        Side::Reach { peer: Peer::Pair(label), ask } => reach::prepare(label, &ask, args).map(Ready::Reach),
        Side::Reach { peer: Peer::Iroh(ticket), ask } => {
            iroh::prepare_reach(ticket, ask, args).map(|ready| Ready::Iroh(Box::new(ready)))
        }
    };
    let ready = match ready {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report("chat", err),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh chat: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    let until = Until { deadline: deadline.map(|d| Instant::now() + d) };
    // On the heap, as each large future here: Windows gives the main thread
    // 1 MiB of stack.
    let code = runtime.block_on(Box::pin(drive(ready, opts, input, until, jsonl, out, err)));
    // A read of stdin may still be blocked in its thread, and a session may
    // still be closing; the run has ended, so neither is waited for.
    runtime.shutdown_background();
    code
}

/// A side, once each check that needs no network passed.
enum Ready {
    Listen(Box<listen::Ready>),
    Reach(reach::Ready),
    /// `--listen --iroh`: both roads.
    Both(Box<iroh::Waiting>),
    /// `iroh:TICKET`.
    Iroh(Box<iroh::Reach>),
}

impl Ready {
    fn label(&self) -> &str {
        match self {
            Ready::Listen(ready) => &ready.label,
            Ready::Reach(ready) => &ready.label,
            Ready::Both(ready) => ready.label(),
            Ready::Iroh(ready) => ready.label(),
        }
    }
}

async fn drive(
    ready: Ready,
    opts: Options,
    input: Input,
    until: Until,
    jsonl: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let label = ready.label().to_string();
    let shown = label.clone();
    let say = move |line: String| eprintln!("podssh chat: {shown}: {line}");
    let read = match input {
        Input::Stdin => Lines::read(std::io::stdin(), say.clone()),
        Input::File(file) => Lines::read(file, say.clone()),
        Input::None => Ok(Lines::none()),
    };
    let mut lines = match read {
        Ok(lines) => lines,
        Err(e) => {
            let _ = writeln!(err, "podssh chat: {label}: the input could not be read: {e}");
            return EX_SOFTWARE;
        }
    };
    let mut output = Output::new(Plain(out), jsonl, say);
    match ready {
        Ready::Listen(ready) => listen::run(*ready, &mut lines, &mut output, opts, until).await,
        Ready::Reach(ready) => reach::run(ready, &mut lines, &mut output, opts, until).await,
        Ready::Both(ready) => iroh::run_waiting(*ready, &mut lines, &mut output, opts, until).await,
        Ready::Iroh(ready) => iroh::run_reach(*ready, &mut lines, &mut output, opts, until).await,
    }
}

/// The ends of a run that come from outside it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Until {
    deadline: Option<Instant>,
}

impl Until {
    /// The `--timeout`, or Ctrl-C (SIGTERM on Unix), whichever comes first.
    pub async fn wait(self) -> Ended {
        let timed_out = async move {
            match self.deadline {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = timed_out => Ended::TimedOut,
            () = crate::node::stop_signal() => Ended::Stopped,
        }
    }
}

/// Whether the run goes on after the peer left: a conversation of the one
/// thing goes on with the next peer, as it is not done; another goes on
/// while the user may still type, or lines wait.
pub(super) fn goes_on(lines: &Lines, opts: &Options) -> bool {
    !matches!(opts.once, Once::No) || !lines.done()
}

/// Say each message of a conversation that went with no acknowledgement.
pub(super) async fn undelivered<W: AsyncWrite + Unpin>(texts: &[String], out: &mut Output<W>) {
    for text in texts {
        out.notice("undelivered", json!({ "text": text }), format!("not delivered: {}", safe(text))).await;
    }
}

/// The end of the run: the lines that never went said, the end said, and
/// the exit code; `lost` counts the last conversation's messages with no
/// acknowledgement.
pub(super) async fn finish<W: AsyncWrite + Unpin>(
    ended: &Ended,
    lost: usize,
    lines: &mut Lines,
    out: &mut Output<W>,
) -> i32 {
    let left = unsent(lines, out).await;
    let code = code(ended, lost + left);
    let (name, words) = words(ended);
    out.notice("end", json!({ "ended": name, "code": code }), words).await;
    code
}

/// The end of a run that the road refused, or ended for good: its code and
/// why, and the lines that never went.
pub(super) async fn refused<W: AsyncWrite + Unpin>(
    code: i32,
    why: String,
    lines: &mut Lines,
    out: &mut Output<W>,
) -> i32 {
    unsent(lines, out).await;
    out.notice("end", json!({ "ended": "refused", "code": code }), why).await;
    code
}

/// Say each line that waits and never went; how many.
async fn unsent<W: AsyncWrite + Unpin>(lines: &mut Lines, out: &mut Output<W>) -> usize {
    let left = lines.left();
    for text in &left {
        out.notice("unsent", json!({ "text": text }), format!("not sent: {}", safe(text))).await;
    }
    left.len()
}

/// The exit code of an end: 0 only when each message was acknowledged and
/// what the run was for is done.
pub(super) fn code(ended: &Ended, lost: usize) -> i32 {
    match ended {
        Ended::Done | Ended::Stopped | Ended::PeerLeft if lost == 0 => 0,
        Ended::Done | Ended::Stopped | Ended::PeerLeft => EX_UNAVAILABLE,
        Ended::TimedOut | Ended::Busy => EX_TEMPFAIL,
        Ended::Declined => EX_NOPERM,
        Ended::Damaged | Ended::Failed(_) => EX_SOFTWARE,
    }
}

/// The name of an end for `--jsonl`, and its words for the user.
fn words(ended: &Ended) -> (&'static str, String) {
    match ended {
        Ended::Done => ("done", String::new()),
        Ended::Stopped => ("stopped", "stopped".into()),
        Ended::PeerLeft => ("peer-left", "the peer left".into()),
        Ended::TimedOut => ("timed-out", "the --timeout passed".into()),
        Ended::Busy => ("busy", "the peer talks with another peer; a later try can work".into()),
        Ended::Declined => ("declined", "the peer declined the file".into()),
        Ended::Damaged => ("damaged", "the file arrived with another SHA-256, and the peer did not keep it".into()),
        Ended::Failed(why) => ("failed", why.clone()),
    }
}

/// stdout as dispatch gives it, written at once: each write is the whole line
/// of a message or an event.
struct Plain<'a>(&'a mut dyn Write);

impl AsyncWrite for Plain<'_> {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Poll::Ready(self.get_mut().0.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.get_mut().0.flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
