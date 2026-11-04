//! A new link beside the one that carries the session: a move before the
//! relay's limits (T-155), or a spare beside a link that went silent
//! (T-305).
//!
//! When the client's address changes, its TCP link through the proxy and
//! the relay often goes silent with no error, and the heartbeat finds it
//! dead only after 30 s. A spare link opens sooner: when a question of this
//! side (`DATA` that the far end acknowledges, a `PING`) has waited three
//! round trips of the link, 1 s to 3 s (T-663), with nothing from the far
//! end, or nothing at all came for two heartbeats. The old link is asked
//! too, so that one that only lagged closes the spare within a round trip.
//! The spare reads its far end's `GREETING` and sends nothing: when the old
//! link's bytes come first, it closes before its handshake, and the far end
//! never dialled a target for it; when it greets first, its resume takes the
//! session, as after a loss, and the far end lets the newest resume win. One
//! new link at a time, and one spare each 10 s at most. Measured through the
//! stand-in proxy's `--move` with a fixed 3 s (T-305): a resume 3.0 to 3.2 s
//! after a new address, where the heartbeat alone took 35 s.

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

/// The most that a question of this side waits, with nothing from the far
/// end, before a spare link opens; all of it before the round trip is known.
pub const SPARE_AFTER: Duration = Duration::from_secs(3);
/// How long nothing at all may come before a spare link opens: two
/// heartbeats (`pump::PING_EVERY`).
pub const SPARE_QUIET: Duration = Duration::from_secs(20);
/// At most one spare link each this long.
pub const SPARE_EVERY: Duration = Duration::from_secs(10);
/// The least that a question waits before a spare link opens, on a link of
/// any round trip: osewa's floor, under which a link that only lagged would
/// get a spare (T-663).
pub const SPARE_SOONEST: Duration = Duration::from_secs(1);
/// How many smoothed round trips of the link a question waits before a
/// spare link opens: osewa's three (T-663).
pub const SPARE_ROUND_TRIPS: u32 = 3;
/// The longest wait between two looks at the silence of the link.
const LOOK_EVERY: Duration = Duration::from_millis(250);
/// Why a spare closes when the old link's bytes came first.
const SPOKE: &str = "the link spoke again";

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
            // A `PING` on the old link: one that only lagged, as behind a
            // far end that holds its `ACK`, answers it within a round trip,
            // and the answer closes the spare before it greets.
            plan.hearing.ask_now();
        }
        // The far end's bytes after this mark close a spare, while it
        // connects too: the old link is back, and a spare costs a resume.
        let mark = plan.hearing.words();
        let at = Ended { end: End::Moving, received, sent };
        let next = match why {
            Beside::Move => connect(&at).await,
            Beside::Spare(_) => tokio::select! {
                biased;
                () = plan.hearing.spoke_after(mark) => {
                    let _ = plan.said.send(failure(why, SPOKE.to_string()));
                    continue;
                }
                next = connect(&at) => next,
            },
        };
        let new = match next {
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
            // first; when both came, the old link goes on.
            Beside::Spare(_) => tokio::select! {
                biased;
                () = plan.hearing.spoke_after(mark) => SPOKE.to_string(),
                got = greeting => match got {
                    Ok(Ok(greeted)) => return (why, greeted),
                    Ok(Err(fault)) => fault.reason(),
                    Err(_) => "its far end did not greet in time".to_string(),
                },
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

/// How long a question waits, with nothing from the far end, before a spare
/// link opens, on a link whose smoothed round trip is `round_trip`: three of
/// them, [`SPARE_SOONEST`] at least and [`SPARE_AFTER`] at most; all of
/// [`SPARE_AFTER`] until a question of the link was answered (T-663).
pub fn spare_after(round_trip: Option<Duration>) -> Duration {
    match round_trip {
        Some(round_trip) => round_trip.saturating_mul(SPARE_ROUND_TRIPS).clamp(SPARE_SOONEST, SPARE_AFTER),
        None => SPARE_AFTER,
    }
}

/// Until the link is silent: a question waited [`spare_after`] the link's
/// round trip, or, with a heartbeat, nothing came for [`SPARE_QUIET`]; and
/// [`SPARE_EVERY`] after the last spare. How long nothing came.
async fn silence(hearing: &Hearing, heartbeat: bool, last_spare: Option<Instant>) -> Duration {
    if let Some(last) = last_spare {
        tokio::time::sleep_until(last + SPARE_EVERY).await;
    }
    loop {
        let now = Instant::now();
        let quiet = hearing.quiet(now);
        let after = spare_after(hearing.round_trip());
        if hearing.silent(now, after).is_some() || (heartbeat && quiet >= SPARE_QUIET) {
            return quiet;
        }
        // The next look comes at the instant that a waiting question reaches
        // its bound, so the spare is not late by a look; the bound itself
        // moves with each answer, so it is read again at least each look.
        let mut next = now + LOOK_EVERY;
        if let Some(asked) = hearing.asked_at() {
            next = next.min(asked + after);
        }
        tokio::time::sleep_until(next.max(now + Duration::from_millis(1))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn a_question_waits_three_round_trips_of_the_link_1_s_at_least_and_3_s_at_most() {
        assert_eq!(spare_after(None), SPARE_AFTER, "no answer yet: the wait of before");
        assert_eq!(spare_after(Some(MS * 50)), SPARE_SOONEST, "a fast link: the floor");
        assert_eq!(spare_after(Some(MS * 250)), SPARE_SOONEST, "an ACK held 200 ms: still the floor");
        assert_eq!(spare_after(Some(MS * 500)), MS * 1500);
        assert_eq!(spare_after(Some(MS * 1100)), SPARE_AFTER, "a slow link: the ceiling");
        assert_eq!(spare_after(Some(Duration::MAX)), SPARE_AFTER, "no overflow");
    }
}
