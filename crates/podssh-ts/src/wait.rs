//! The waits for the first network map, and the one deadline of a run.
//!
//! The fork answers `self_node`, `ipv4_addr` and `peer_by_name` only once the
//! control server has sent its first network map: until then each reply waits
//! in a queue, and with no map it waits for ever. So each such wait has a
//! limit, and a limit that passes is [`NodeError::NetmapPending`]. A reply
//! that the fork sends after the wait gave up goes nowhere: kameo's reply
//! sender drops a send to a closed channel, so it cannot panic.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use crate::node::NodeError;

/// How long a run with no `--timeout` and no `--ts-wait-allowlist` waits for
/// the first network map: a design constant, not a measurement. Long enough
/// for a control server that answers, short enough that a human who left a
/// terminal open is told why nothing came.
pub const FIRST_MAP_WAIT: Duration = Duration::from_secs(20);

/// `wait`, given `limit`: its answer, or [`NodeError::NetmapPending`] when the
/// limit passes first.
pub async fn within<T>(limit: Duration, wait: impl Future<Output = Result<T, NodeError>>) -> Result<T, NodeError> {
    match tokio::time::timeout(limit, wait).await {
        Ok(answer) => answer,
        Err(_) => Err(NodeError::NetmapPending),
    }
}

/// The one deadline of a run, from `--timeout`, made when the run starts:
/// each later wait gets only what remains of it, so the bound caps the whole
/// run and not each step.
#[derive(Clone, Copy, Debug)]
pub struct Deadline(Option<Instant>);

impl Deadline {
    /// `bound` from now; no bound gives no deadline.
    pub fn after(bound: Option<Duration>) -> Self {
        Deadline(bound.map(|b| Instant::now() + b))
    }

    /// What remains of the bound, or `None` with no bound.
    pub fn remaining(&self) -> Option<Duration> {
        self.0.map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// The limit of one wait whose own window is `window`: the window, and
    /// never past the deadline.
    pub fn limit(&self, window: Duration) -> Duration {
        self.remaining().map_or(window, |left| left.min(window))
    }
}
