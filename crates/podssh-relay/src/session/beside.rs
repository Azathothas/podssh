//! A new link beside the one that carries the session: a move before the
//! relay's limits (T-155), or a spare beside a link that went silent
//! (T-305).
//!
//! When the client's address changes, its TCP link through the proxy and
//! the relay often goes silent with no error, and the heartbeat finds it
//! dead only after 30 s. A spare link opens sooner: when a question of this
//! side (`DATA` that the far end acknowledges, a `PING`) has waited 3 s with
//! nothing from the far end, or when nothing at all came for two heartbeats.
//! It reads its far end's `GREETING` and sends nothing: when the old link's
//! bytes come first, the spare closes before its handshake, and the far end
//! never dialled a target for it; when the spare greets first, its resume
//! takes the session, as a resume after a loss does, and the far end lets
//! the newest resume win. One new link at a time, and one spare each 10 s
//! at most.
//!
//! The values are provisional, UNVERIFIED until the measurement of T-305
//! with the stand-in proxy's `--move`.

use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::sync::mpsc::UnboundedSender;
// tokio's clock, which a test can pause.
use tokio::time::Instant;

use super::client;
use super::hearing::Hearing;
use super::link::Link;
use super::pump::{End, Ended, Watch};
use super::resume::{greeted, Greeted, Next, Note};

/// How long a question of this side waits, with nothing from the far end,
/// before a spare link opens.
pub const SPARE_AFTER: Duration = Duration::from_secs(3);
/// How long nothing at all may come before a spare link opens: two
/// heartbeats (`pump::PING_EVERY`).
pub const SPARE_QUIET: Duration = Duration::from_secs(20);
/// At most one spare link each this long.
pub const SPARE_EVERY: Duration = Duration::from_secs(10);
/// How often the silence of the link is read.
const LOOK_EVERY: Duration = Duration::from_millis(250);

/// Why a new link opened beside the one that carries the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Beside {
    /// The link nears the relay's limits (T-155).
    Move,
    /// The link said nothing for this long (T-305).
    Spare(Duration),
}

/// What the driver gives to look for a new link beside the current one.
pub(super) struct Plan<'a> {
    /// Whether the session moves before the relay's limits.
    pub moves: bool,
    /// Whether a silent link gets a spare beside it.
    pub spares: bool,
    /// Whether the link answers `PING`s, so that a long quiet is silence.
    pub heartbeat: bool,
    /// When the link is old enough to move.
    pub move_at: Instant,
    /// Whether the session was closing already: no link opens beside it.
    pub closing: bool,
    pub watch: &'a Watch,
    pub state: &'a Mutex<Link>,
    pub hearing: &'a Hearing,
    /// Where the steps go, as they come, for the caller's lines.
    pub said: &'a UnboundedSender<Note>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The next new link beside the current one, once its far end greeted, and
/// why it opened. A move that fails says so and is not tried again on this
/// link; a spare that the old link outspeaks, or that fails, closes, and the
/// watch goes on. Never, while the session closes.
pub(super) async fn next<L, C, F>(plan: Plan<'_>, connect: &mut C) -> (Beside, Greeted<L>)
where
    L: AsyncRead + Unpin,
    C: FnMut(&Ended) -> F,
    F: Future<Output = Next<L>>,
{
    let mut moves = plan.moves;
    let mut last_spare: Option<Instant> = None;
    loop {
        let why = tokio::select! {
            // The pump tells when the link passes its bytes.
            _ = plan.watch.due.notified(), if moves => Beside::Move,
            () = tokio::time::sleep_until(plan.move_at), if moves => Beside::Move,
            quiet = silence(plan.hearing, plan.heartbeat, last_spare), if plan.spares => Beside::Spare(quiet),
            else => std::future::pending::<Beside>().await,
        };
        // A session whose application ended is closing: its `CLOSE` goes on
        // the link that it has.
        if plan.closing || plan.watch.app_ended.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        // One guard: a second lock in the same expression would wait for
        // the first, which lives to the end of the statement.
        let (received, sent) = {
            let link = lock(plan.state);
            (link.received(), link.sent())
        };
        if let Beside::Spare(quiet) = why {
            last_spare = Some(Instant::now());
            let _ = plan.said.send(Note::Spare { quiet });
        }
        let opened = Instant::now();
        let at = Ended { end: End::Moving, received, sent };
        let new = match connect(&at).await {
            Next::Link(new) => new,
            Next::Retry(why_not) | Next::Stop(why_not) => {
                let _ = plan.said.send(failure(why, why_not));
                moves &= why != Beside::Move;
                continue;
            }
        };
        let greeting = tokio::time::timeout(client::HANDSHAKE_LIMIT, greeted(new));
        let why_not = match why {
            Beside::Move => match greeting.await {
                Ok(Ok(greeted)) => return (why, greeted),
                Ok(Err(fault)) => fault.reason(),
                Err(_) => "the new link's far end did not greet in time".to_string(),
            },
            // The spare closes, with nothing sent, when the old link speaks
            // first.
            Beside::Spare(_) => tokio::select! {
                got = greeting => match got {
                    Ok(Ok(greeted)) => return (why, greeted),
                    Ok(Err(fault)) => fault.reason(),
                    Err(_) => "its far end did not greet in time".to_string(),
                },
                () = spoke_since(plan.hearing, opened) => "the link spoke again".to_string(),
            },
        };
        let _ = plan.said.send(failure(why, why_not));
        moves &= why != Beside::Move;
    }
}

/// The step that says that a new link beside the old one failed.
pub(super) fn failure(why: Beside, why_not: String) -> Note {
    match why {
        Beside::Move => Note::MoveFailed { why: why_not },
        Beside::Spare(_) => Note::SpareClosed { why: why_not },
    }
}

/// Until the link is silent: a question waited [`SPARE_AFTER`], or, with a
/// heartbeat, nothing came for [`SPARE_QUIET`]; and [`SPARE_EVERY`] after
/// the last spare. How long nothing came.
async fn silence(hearing: &Hearing, heartbeat: bool, last_spare: Option<Instant>) -> Duration {
    if let Some(last) = last_spare {
        tokio::time::sleep_until(last + SPARE_EVERY).await;
    }
    loop {
        let now = Instant::now();
        let quiet = hearing.quiet(now);
        if hearing.silent(now, SPARE_AFTER).is_some() || (heartbeat && quiet >= SPARE_QUIET) {
            return quiet;
        }
        tokio::time::sleep(LOOK_EVERY).await;
    }
}

/// Until bytes came from the far end after `since`.
async fn spoke_since(hearing: &Hearing, since: Instant) {
    while hearing.heard_at() <= since {
        tokio::time::sleep(LOOK_EVERY).await;
    }
}
