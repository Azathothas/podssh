//! Keep a link up (podssh's patch 0019): dial it again after a drop, with a capped backoff and
//! jitter, and know a link that died with no close by its silence.
//!
//! A DERP region's runner ended at its first error and never dialled again, so the node lost its
//! path to its peers with no message, and the control runner stopped for good after five restarts
//! in 5 s. The loop here takes its steps from a [`Link`], so a test drives it with no network.

use core::future::Future;
use std::time::Duration;

use tokio::time::{Instant, MissedTickBehavior};

/// How a turn of a link ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The link closed with no fault: a region that is not home went quiet. The next turn waits
    /// for a reason to connect, with no backoff.
    Quiet,
    /// The link failed, or could not be made: it is dialled again after a wait.
    Failed(String),
    /// The far end refused this node's key, as a DERP close 1008 "not authorized" does: not
    /// dialled again, unless [`Reconnect::retry_refused`].
    Refused(String),
}

/// What a DERP error means for its link: the relay's close 1008 "not authorized" refuses this
/// node's key, and each other error is a drop.
pub fn ended_by(e: &ts_derp::Error) -> Ended {
    match e.ws_close() {
        Some(close) if close.code == Some(1008) && close.reason.contains("not authorized") => {
            Ended::Refused(e.to_string())
        }
        _ => Ended::Failed(e.to_string()),
    }
}

/// When to dial a link again: podssh's backoff, 1 s, 2 s, 4 s … capped at 30 s, each scaled by a
/// random factor in [0.5, 1.5) so that nodes that dropped together do not dial in step, and
/// counted from 1 again after a link that lasted [`Reconnect::stable_after`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reconnect {
    /// The first wait, before the random factor.
    pub first: Duration,
    /// The longest wait, before the random factor.
    pub max: Duration,
    /// A link up this long counts from the first wait again.
    pub stable_after: Duration,
    /// Dial again after a refusal too: the node waits for its key to be admitted.
    pub retry_refused: bool,
}

impl Default for Reconnect {
    fn default() -> Self {
        Self {
            first: Duration::from_secs(1),
            max: Duration::from_secs(30),
            stable_after: Duration::from_secs(60),
            retry_refused: false,
        }
    }
}

impl Reconnect {
    /// The wait before attempt `retry`, 1 for the first after a drop.
    pub fn wait(&self, retry: u32) -> Duration {
        let first = self.first.as_millis() as u64;
        let max = self.max.as_millis() as u64;
        let base = first
            .saturating_mul(1u64 << retry.saturating_sub(1).min(5))
            .min(max);
        let factor: f64 = rand::random_range(0.5..1.5);
        Duration::from_millis((base as f64 * factor) as u64)
    }
}

/// Which link of the node changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LinkKind {
    /// The connection to the control server.
    Control,
    /// The DERP connection of a region, by its number.
    Derp(u32),
}

/// How a link changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkChange {
    /// The link is up; `again` after a drop.
    Connected {
        /// Up again after a drop, not for the first time or after a quiet close.
        again: bool,
    },
    /// The link dropped, or could not be made; the next attempt comes after `retry_in`.
    Dropped {
        /// Why.
        reason: String,
        /// The wait before the next attempt.
        retry_in: Duration,
    },
    /// The far end refused this node's key; no attempt follows.
    Refused {
        /// Why, as the far end said it.
        reason: String,
    },
}

/// A change of one of the node's links, for whoever watches the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkEvent {
    /// Which link.
    pub link: LinkKind,
    /// How it changed.
    pub change: LinkChange,
}

/// The steps of a link that [`keep`] runs.
pub trait Link {
    /// What a wait gives the connect step: for a DERP region, a packet to send at once.
    type Pending: Send;
    /// A connected link.
    type Transport: Send;

    /// Wait for a reason to connect.
    fn wait(&mut self) -> impl Future<Output = Self::Pending> + Send;

    /// Connect.
    fn connect(
        &mut self,
        pending: Self::Pending,
    ) -> impl Future<Output = Result<Self::Transport, Ended>> + Send;

    /// Run the connected link until it ends.
    fn run(&mut self, transport: Self::Transport) -> impl Future<Output = Ended> + Send;

    /// The link changed: tell its watchers.
    fn changed(&mut self, change: LinkChange);
}

/// Run `link` for ever: wait for a reason to connect, connect, run until it ends, and again,
/// waiting after a failure as `policy` says. Returns only on a refusal that `policy` does not
/// retry, with its reason.
pub async fn keep(link: &mut impl Link, policy: &Reconnect) -> String {
    let mut retry = 0u32;
    let mut again = false;
    loop {
        let pending = link.wait().await;
        let ended = match link.connect(pending).await {
            Ok(transport) => {
                link.changed(LinkChange::Connected { again });
                let up = Instant::now();
                let ended = link.run(transport).await;
                if up.elapsed() >= policy.stable_after {
                    retry = 0;
                }
                ended
            }
            Err(ended) => ended,
        };
        match ended {
            Ended::Quiet => again = false,
            Ended::Refused(reason) if !policy.retry_refused => {
                link.changed(LinkChange::Refused {
                    reason: reason.clone(),
                });
                return reason;
            }
            Ended::Failed(reason) | Ended::Refused(reason) => {
                retry = retry.saturating_add(1);
                let retry_in = policy.wait(retry);
                link.changed(LinkChange::Dropped { reason, retry_in });
                tokio::time::sleep(retry_in).await;
                again = true;
            }
        }
    }
}

/// How often a connected link is pinged, and how many intervals of silence in a row mean it is
/// dead: podssh's rule for its own relay, 30 s of nothing at all.
pub const PING_EVERY: Duration = Duration::from_secs(10);
/// See [`PING_EVERY`].
pub const SILENT_ALLOWED: u32 = 3;

/// What [`until_silent`] reads of a connected link.
pub trait Heard: Sync {
    /// When the last frame of any kind came.
    fn last_heard(&self) -> Instant;

    /// How many answers to pings have come.
    fn pongs(&self) -> u64;

    /// Send a ping.
    fn ping(&self) -> impl Future<Output = Result<(), String>> + Send;
}

/// Ping `link` each `every`, and return why it is dead: nothing heard for `allowed` intervals in
/// a row once it has answered a ping, or a ping that could not go out within an interval. A far
/// end that never answered a ping is not declared dead here: its silence proves nothing.
pub async fn until_silent(link: &impl Heard, every: Duration, allowed: u32) -> String {
    let mut ticks = tokio::time::interval_at(Instant::now() + every, every);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last = link.last_heard();
    let mut silent = 0u32;
    loop {
        ticks.tick().await;
        let heard = link.last_heard();
        if heard > last {
            last = heard;
            silent = 0;
        } else if link.pongs() > 0 {
            silent += 1;
            if silent >= allowed {
                return format!(
                    "nothing came for {} s, though the far end answers pings",
                    (every * allowed).as_secs()
                );
            }
        }
        match tokio::time::timeout(every, link.ping()).await {
            Ok(Ok(())) => {}
            Ok(Err(why)) => return why,
            Err(_) => return format!("a ping could not go out in {} s", every.as_secs()),
        }
    }
}
