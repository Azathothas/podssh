//! The race between two roads to one far end (T-164): the first road
//! starts at once, the second after a head start, or at once when the first
//! fails before it; the winner is the first link whose far end speaks. The
//! layer's handshake then goes on the winner alone (`client::Greeted`), so
//! the losing link never sends `OPEN`, and its far end never dials its
//! target. Each road keeps its own time limits and failover: the race only
//! orders them. [`in_turn`] orders more than two roads of one link (T-379):
//! each after a wait from the one before, or only when each one before it
//! failed, as a fallback.

use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use tokio::io::AsyncRead;
// tokio's clock, which a test can pause.
use tokio::time::Instant;

use super::client::{greeted, Greeted};

/// The head start of the first road, as Happy Eyeballs (RFC 8305) gives one
/// to IPv6: 250 ms more at most when the first road cannot run.
pub const HEAD_START: Duration = Duration::from_millis(250);

/// The link that won, and how long the race took.
pub enum Won<A, B> {
    First(Greeted<A>),
    Second(Greeted<B>),
}

/// Why neither road gave a link: each road's reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lost {
    pub first: String,
    pub second: String,
}

impl std::fmt::Display for Lost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the first road: {}; the second road: {}", self.first, self.second)
    }
}

/// A road's link, greeted: an error when the far end kept silent.
async fn greeting<L, F>(road: F) -> Result<Greeted<L>, String>
where
    L: AsyncRead + Unpin,
    F: Future<Output = Result<L, String>>,
{
    let link = road.await?;
    let greeted = greeted(link).await.map_err(|e| e.to_string())?;
    if greeted.spoke() {
        Ok(greeted)
    } else {
        Err(format!("the far end said nothing within {} s", super::client::FIRST_BYTE_WAIT.as_secs()))
    }
}

/// Race `first` and `second`, giving `first` the head start `ahead`: the
/// winner, and the time from the start to its far end's first bytes. The
/// loser is dropped where it stands, which ends its attempt or its link.
pub async fn race<A, B, FA, FB>(first: FA, second: FB, ahead: Duration) -> Result<(Won<A, B>, Duration), Lost>
where
    A: AsyncRead + Unpin,
    B: AsyncRead + Unpin,
    FA: Future<Output = Result<A, String>>,
    FB: Future<Output = Result<B, String>>,
{
    let started = Instant::now();
    let first = greeting(first);
    let second = greeting(second);
    tokio::pin!(first, second);
    // The head start: the first road alone, until it wins, fails, or the
    // head start ends.
    let mut first_failed = None;
    tokio::select! {
        won = &mut first => match won {
            Ok(link) => return Ok((Won::First(link), started.elapsed())),
            Err(why) => first_failed = Some(why),
        },
        () = tokio::time::sleep(ahead) => {}
    }
    let Some(first_why) = first_failed else {
        // Both roads run; the first to speak wins.
        tokio::select! {
            won = &mut first => match won {
                Ok(link) => return Ok((Won::First(link), started.elapsed())),
                Err(first_why) => {
                    return match second.await {
                        Ok(link) => Ok((Won::Second(link), started.elapsed())),
                        Err(second_why) => Err(Lost { first: first_why, second: second_why }),
                    }
                }
            },
            won = &mut second => match won {
                Ok(link) => return Ok((Won::Second(link), started.elapsed())),
                Err(second_why) => {
                    return match first.await {
                        Ok(link) => Ok((Won::First(link), started.elapsed())),
                        Err(first_why) => Err(Lost { first: first_why, second: second_why }),
                    }
                }
            },
        }
    };
    // The first road failed within its head start: the second at once.
    match second.await {
        Ok(link) => Ok((Won::Second(link), started.elapsed())),
        Err(second_why) => Err(Lost { first: first_why, second: second_why }),
    }
}

/// When a road of [`in_turn`] starts; the first road starts at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// This long after the road before it started, or at once when each
    /// road that started before it failed, as Happy Eyeballs staggers its
    /// attempts (RFC 8305, section 5).
    After(Duration),
    /// Only when each road before it failed: a fallback, which costs its
    /// carrier nothing while a road before it works.
    WhenAllFailed,
}

/// The road that won [`in_turn`]: its place in the list, and its link.
pub struct WonAt<L> {
    pub at: usize,
    pub link: Greeted<L>,
}

/// Race `roads` in their order, each starting as its [`Start`] says: the
/// winner, the first whose far end speaks, and the time from the start to
/// its first bytes; else each road's reason, in the order of the list. The
/// losers are dropped where they stand, as [`race`] drops its loser.
pub async fn in_turn<L, F>(roads: Vec<(Start, F)>) -> Result<(WonAt<L>, Duration), Vec<String>>
where
    L: AsyncRead + Unpin,
    F: Future<Output = Result<L, String>>,
{
    let started = Instant::now();
    let starts: Vec<Start> = roads.iter().map(|(start, _)| *start).collect();
    // An async fn starts nothing until it is polled: a road that has not
    // started is a future that no one polled yet.
    let mut slots: Vec<_> = roads.into_iter().map(|(_, road)| Some(Box::pin(greeting(road)))).collect();
    let mut why: Vec<Option<String>> = (0..slots.len()).map(|_| None).collect();
    // The roads started so far, and when the last of them started.
    let (mut running, mut last) = (usize::from(!slots.is_empty()), Instant::now());
    loop {
        if why[..running].iter().all(Option::is_some) {
            if running == slots.len() {
                return Err(why.into_iter().map(Option::unwrap_or_default).collect());
            }
            running += 1;
            last = Instant::now();
            continue;
        }
        let next = match starts.get(running) {
            Some(Start::After(wait)) => Some(last + *wait),
            Some(Start::WhenAllFailed) | None => None,
        };
        let mut timer = next.map(|at| Box::pin(tokio::time::sleep_until(at)));
        let event = std::future::poll_fn(|cx| {
            for (at, slot) in slots[..running].iter_mut().enumerate() {
                if let Some(road) = slot.as_mut() {
                    if let Poll::Ready(done) = road.as_mut().poll(cx) {
                        return Poll::Ready(Some((at, done)));
                    }
                }
            }
            if let Some(timer) = timer.as_mut() {
                if timer.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
            }
            Poll::Pending
        })
        .await;
        match event {
            Some((at, Ok(link))) => return Ok((WonAt { at, link }, started.elapsed())),
            Some((at, Err(reason))) => {
                slots[at] = None;
                why[at] = Some(reason);
            }
            // The next road's wait ended: it starts now.
            None => {
                running += 1;
                last = Instant::now();
            }
        }
    }
}
