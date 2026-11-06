//! The links of the pair's road and of the Piping Server road, each a place
//! of `super`'s race. Apart from `roads.rs`, for the length of that file.

use std::sync::atomic::{AtomicBool, Ordering};

use podssh_relay::reverse::{legs, OperatorConfig, Outcome as LegOutcome};
use tokio::task::JoinHandle;

use super::{Road, Roads, PIPE};
use crate::layered;

/// A new leg of the pair's road, unless the last one ended with a close
/// that a new leg would only get again.
pub(super) async fn pair_link(
    config: &OperatorConfig<'_>,
    roads: &Roads<'_>,
    previous: Option<JoinHandle<LegOutcome>>,
) -> Result<Road, String> {
    if let Some(handle) = previous {
        if let Ok(Ok(outcome)) = tokio::time::timeout(layered::LEG_WAIT, handle).await {
            if let Some(stop) = layered::stops(&outcome) {
                roads.pair_final.store(true, Ordering::SeqCst);
                return Err(stop);
            }
        }
    }
    if roads.pair_final.load(Ordering::SeqCst) {
        return Err("the pair's road ended for good".to_string());
    }
    let (link, leg_end) = tokio::io::duplex(PIPE);
    match legs::start(config, leg_end).await {
        Ok(handle) => {
            *layered::lock(&roads.legs) = Some(handle);
            Ok(Road::Pair(link))
        }
        Err(e) => {
            // A proxy's refusal of the upgrade is the Piping Server road's
            // cue, and no word of the relay's on the pair.
            if roads.piping.is_some() && podssh_relay::piping::probe::upgrade_refused(&e) {
                roads.refused.store(true, Ordering::SeqCst);
            } else if layered::is_final(&e) {
                roads.pair_final.store(true, Ordering::SeqCst);
            }
            Err(crate::pairs::connect_refusal(&e, roads.label).message)
        }
    }
}

/// A link of the Piping Server road: asked, or once a road found the
/// upgrade refused.
pub(super) async fn piping_link(
    dialer: &podssh_relay::piping::Dialer,
    asked: bool,
    refused: &AtomicBool,
) -> Result<Road, String> {
    if !asked && !refused.load(Ordering::SeqCst) {
        return Err("not tried: no road found the WebSocket upgrade refused, and PODSSH_PIPING did not ask".into());
    }
    dialer.link().await.map(Road::Piping)
}
