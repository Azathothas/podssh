//! The frp road of a client (T-498): with `PODSSH_FRP` naming the node's
//! file, a visit to the node's STCP service at the user's frps, with the
//! same secret (`podssh_ws::frp::node::visit`). The end-to-end channel and
//! the resumable layer run above it, as on the pair's road, so that frps
//! carries bytes it cannot read. The road races only when each road before
//! it failed: frps is the user's own fallback, and the ends' roads come first.

use podssh_relay::session::race::Start;
use podssh_ws::frp::node::Road as FrpRoad;
use podssh_ws::Trust;

use super::{Going, Kind, Road};
use crate::relay_settings::Refusal;

/// The road to the node's service through frps.
pub(crate) struct FrpRoads {
    road: FrpRoad,
    /// The service's name: the file's `name`, else the node's label.
    name: String,
}

impl FrpRoads {
    /// The road that `PODSSH_FRP` names, to the node `label`; none when the
    /// variable names no file. A file that does not read is refused, not
    /// passed over: the user asked for the road.
    pub(crate) fn new(label: &str, trust: &Trust) -> Result<Option<FrpRoads>, Refusal> {
        let Some(frp) = crate::frp_file::from_env(trust.clone())? else { return Ok(None) };
        let name = frp.name.unwrap_or_else(|| label.to_string());
        Ok(Some(FrpRoads { road: frp.road, name }))
    }

    /// The road's place in the race, after each road before it failed.
    pub(super) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Frp);
    }

    async fn link(&self) -> Result<Road, String> {
        let shown = self.road.server.shown();
        let stream = podssh_ws::frp::node::visit(&self.road, &self.name).await.map_err(|e| format!("{shown}: {e}"))?;
        Ok(Road::Pair(stream))
    }
}
