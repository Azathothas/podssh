//! The roads of `podssh ping node://NAME` (T-435): those of [`super::ride`],
//! made as it makes them and raced in its order with its starts, but each
//! road that starts runs on to its far end's first bytes, so that each has
//! its time (`podssh_relay::session::race::each_timed`). Each link then ends
//! before a byte is sent on it: the node opens no session and dials nothing
//! at its TARGET, and no end-to-end channel is made, as no session goes
//! above. The road that answered first, or the race that found none, is kept
//! for `podssh status --net` (`crate::net::reached`). A child of `roads`,
//! whose roads it makes.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::reverse::{OperatorConfig, OperatorLimits, Wire};
use podssh_relay::session::race::{each_timed, first_answered, Timed};
use podssh_ssh::Log;
use podssh_ws::{ProxyChoice, Trust};

use super::{Raced, Roads};
use crate::exitmap::sysexits;
use crate::ssh::transport::NotReached;

/// The bound of the whole measure: a road that has not answered by then
/// fails with it. Above each road's own limits, which end it first.
pub(crate) const BOUND: Duration = Duration::from_secs(45);

/// One road of the measure, in the order of the race.
pub(crate) struct Measured {
    /// The road, in the words of the race (`the pair's road`).
    pub(crate) road: &'static str,
    /// How it ended; `None` when it did not start: a fallback, as a road
    /// before it answered.
    pub(crate) timed: Option<Timed>,
}

/// What the measure found.
pub(crate) struct Measures {
    /// The node, as the lines name it: `node://NAME`.
    pub(crate) shown: String,
    pub(crate) roads: Vec<Measured>,
    /// The place of the road whose far end spoke first.
    pub(crate) won: Option<usize>,
}

impl Measures {
    /// Each road's end, for a race that no road won.
    pub(crate) fn why_none(&self) -> String {
        let each = self.roads.iter().map(|measured| match &measured.timed {
            Some(Timed { answered: Err(why), .. }) => format!("{}: {why}", measured.road),
            Some(_) => format!("{}: answered", measured.road),
            None => format!("{}: not started", measured.road),
        });
        format!("no road reached the node: {}", each.collect::<Vec<_>>().join("; "))
    }
}

/// The race of the roads to the node of `label`, measured: each road as
/// [`super::ride`] makes it, with no channel and no layer above it. A
/// refusal before anything connects is the one of `ride`.
pub(crate) async fn measure(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    raced: Raced<'_>,
    log: Arc<Log>,
) -> Result<Measures, NotReached> {
    let shown = format!("{}{label}", crate::ssh::node::SCHEME);
    let not_reached = |why: &str, code: i32| NotReached { lines: vec![format!("{shown}: {why}")], code };
    crate::pairs::online().map_err(|refusal| not_reached(&refusal.message, refusal.code))?;
    // The pair's road when this host has the pair; a node that the DERP road
    // or its record reaches may have none here, as `ride` takes it.
    let others = raced.derp.is_some() || raced.opentunnel.is_some() || raced.record.is_some();
    let part = match crate::pairs::operator_part(label, pair_file) {
        Ok(part) => Some(part),
        Err(refusal) if others && pair_file.is_none() => {
            log.verbose(&format!("{shown}: no pair's road: {}", refusal.message));
            None
        }
        Err(refusal) => return Err(not_reached(&refusal.message, refusal.code)),
    };
    let iroh = raced.iroh.map(|race| crate::ssh::iroh::IrohRoad::new(race, trust, &log)).transpose();
    let iroh = iroh.map_err(|why| not_reached(&why, sysexits::EX_USAGE))?;
    let derp = match &raced.derp {
        Some(road) => {
            let dialer = crate::ssh::derp::dialer(&road.ticket, &road.servers, trust, &log, &shown);
            Some((dialer.map_err(|why| not_reached(&why, sysexits::EX_CONFIG))?, road.asked))
        }
        None => None,
    };
    let opentunnel = raced.opentunnel.as_ref().map(|road| {
        let dialer = crate::ssh::opentunnel::dialer(road, label, trust, &log, &shown);
        (dialer, road.asked)
    });
    let piping = match (&raced.piping, &part) {
        (Some(race), Some(part)) => Some((crate::piping_road::dialer(part, race, trust, &log, &shown), race.asked)),
        _ => None,
    };
    let refused = AtomicBool::new(raced.piping.as_ref().is_some_and(|race| race.refused));
    let proxy = ProxyChoice::FromEnvironment;
    let config = part.as_ref().map(|part| OperatorConfig {
        relay: &part.relay,
        name: &part.name,
        connect_token: part.connect_token(),
        trust,
        proxy: &proxy,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        limits: OperatorLimits::default(),
        wire: Wire::Tls,
    });
    // The transit relay's token is the pair's, so it needs the pair.
    let transit = match (raced.transit, &part) {
        (Some(url), Some(part)) => crate::node_transit::dialer(url, part, trust, &log, &shown),
        _ => None,
    };
    let record = raced.record.map(|ask| crate::ssh::iroh::RecordRoads::new(ask, trust, &log, &shown));
    let (legs, pair_final) = (Mutex::new(None), AtomicBool::new(false));
    let pair = config.as_ref();
    // The legs at the net's relay members, as a run races them (T-434).
    let member = crate::ssh::roads::member::MemberRoads::new(label, trust);
    // The visit at the user's frps, as a run races it (T-498); a file that
    // does not read leaves the road out of the measure.
    let frp = crate::ssh::roads::frp::FrpRoads::new(label, trust).ok().flatten();
    let roads =
        Roads { iroh, pair, derp, opentunnel, transit, piping, record, member, frp, refused, label, legs, pair_final };
    let (list, kinds) = roads.race(None);
    let order = crate::ssh::road_link::order(&kinds, roads.unasked());
    log.verbose(&format!("measuring the roads to {shown}: {order}"));
    let timed = each_timed(list, BOUND).await;
    // Each link ended with the measure; the pair's last leg ends after it.
    let _ = crate::layered::last(&roads.legs).await;
    roads.close().await;
    let won = first_answered(&timed);
    let measured: Vec<Measured> =
        kinds.iter().zip(timed).map(|(kind, timed)| Measured { road: kind.name(), timed }).collect();
    let winner = won.and_then(|at| Some((measured[at].road, measured[at].timed.as_ref()?.ended())));
    let measures = Measures { shown: shown.clone(), roads: measured, won };
    match winner {
        Some((road, took)) => crate::net::reached::reached(label, road, took),
        None => crate::net::reached::missed(label, &measures.why_none()),
    }
    Ok(measures)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timed(started_ms: u64, took_ms: u64, answered: Result<(), String>) -> Option<Timed> {
        let ms = Duration::from_millis;
        Some(Timed { started: ms(started_ms), took: ms(took_ms), answered })
    }

    /// A race that no road won names each road's end, in its order.
    #[test]
    fn a_race_that_no_road_won_names_each_road_s_end() {
        let roads = vec![
            Measured { road: "the pair's road", timed: timed(0, 30, Err("the node is offline".into())) },
            Measured { road: "the Piping Server road", timed: None },
        ];
        let measures = Measures { shown: "node://gone".into(), roads, won: None };
        assert_eq!(
            measures.why_none(),
            "no road reached the node: the pair's road: the node is offline; the Piping Server road: not started"
        );
    }
}
