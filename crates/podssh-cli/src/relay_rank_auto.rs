//! The rank that a session of `podssh ssh` makes in its background (T-608),
//! only when the user asks for it with `RelayRank auto` or
//! `PODSSH_RELAY_RANK=auto` (Q89): when no rank holds for this egress, a
//! session that the default list carries probes the default host and the
//! hosts of its pool, one at a time, after it ran 60 s, one probe each 10 s
//! at most, 8 hosts in a day, and keeps what it measured after each probe,
//! as a rank of the source `background` that the default list takes as it
//! takes `relay rank`'s (T-607). A probe is `ping`'s relay leg with
//! `?dial=lazy` and three pings, so the relay dials no target, and its
//! figure is the client's leg alone. Never before the session opened, never
//! beside a race, never with `PODSSH_OFFLINE`; the session's end aborts it,
//! which drops a probe in flight.

use podssh_relay::rank::{self, Rank};
use podssh_relay::rank_auto;
use podssh_relay::relay::{RelayList, DEFAULT_RELAY_HOST};
use serde_json::json;

use crate::ping::relay::REFERENCE;
use crate::ssh::resolve::Transport;

/// The background rank of a session that `transport` reached, on a task of
/// its own: only on the default list of the relay (`through_relay`, not the
/// direct road after it, nor a forwarder), when the user asked for it and a
/// run is due today. The caller aborts it when the session ends.
pub(crate) fn spawn(transport: &Transport, through_relay: bool) -> Option<tokio::task::JoinHandle<()>> {
    let Transport::Relay { relays, trust, .. } = transport else { return None };
    if !through_relay || relays.explicit || !rank_auto::asked() || podssh_relay::open::offline() {
        return None;
    }
    // A cache that keeps no file keeps no rank: its probes would buy nothing.
    if podssh_relay::cache::candidate_dirs().is_empty() {
        return None;
    }
    let egress = podssh_relay::rank_list::egress_for(DEFAULT_RELAY_HOST);
    // A rank that holds for this egress: none is due today.
    if rank_auto::plan(rank::load().as_ref(), &rank_auto::hosts(), &egress, crate::pairs::now_ms()).is_none() {
        return None;
    }
    Some(tokio::spawn(run(trust.clone(), egress)))
}

/// The run: the session's delay, then one probe at a time, each after the
/// gap, after any race, and the rank kept after each.
async fn run(trust: podssh_ws::Trust, egress: String) {
    let pace = rank_auto::pace();
    tokio::time::sleep(pace.delay).await;
    let target = podssh_ws::dial::authority(REFERENCE.0, REFERENCE.1);
    let mut last: Option<tokio::time::Instant> = None;
    for _ in 0..rank_auto::MOST {
        if let Some(at) = last {
            tokio::time::sleep_until(at + pace.gap).await;
        }
        rank_auto::calm().await;
        if podssh_relay::open::offline() {
            return;
        }
        // The file again before each probe: another run may have made a
        // rank, or gone on with this one.
        let kept = rank::load();
        let Some(plan) = rank_auto::plan(kept.as_ref(), &rank_auto::hosts(), &egress, crate::pairs::now_ms()) else {
            return;
        };
        let Some(host) = plan.first() else {
            // Each host of the day's plan is measured: the rank is whole.
            if let Some(whole) = kept.map(|k| Rank { partial: false, ..k }) {
                let _ = rank::save(&whole);
            }
            return;
        };
        let Ok(relay) = podssh_relay::relay::parse_relay(host) else { return };
        last = Some(tokio::time::Instant::now());
        let leg = crate::ping::relay::leg_with(&relay, &trust, REFERENCE, rank_auto::LAZY, rank_auto::PINGS);
        let Some(leg) = rank_auto::unless_a_race(leg).await else { continue };
        let probe = crate::relay_rank::probe_of(&leg);
        let at = rank_auto::Run { egress: &egress, target: &target, now_ms: crate::pairs::now_ms() };
        let made = rank_auto::with_probe(rank::load(), &at, host, probe, plan.len() > 1);
        // A rank that is not kept stops the run: the next probe would
        // measure the same host again.
        if rank::save(&made).is_err() {
            return;
        }
    }
}

/// The background rank for `podssh status`, with no connection: whether a
/// setting asks for it and which, and when the last was made.
pub(crate) fn status_value() -> serde_json::Value {
    let kept = rank::load();
    let now = crate::pairs::now_ms();
    let made = kept.as_ref().map(|k| k.background_ms).filter(|ms| *ms > 0);
    json!({
        "asked": rank_auto::asked(),
        "by": rank_auto::asked_by(),
        "last_ms": made,
        "last_age_s": made.filter(|ms| *ms <= now).map(|ms| (now - ms) / 1000),
        "partial": kept.as_ref().is_some_and(|k| k.background() && k.partial),
    })
}

/// The doctor's line `rank` (T-607) with the background rank's words: whose
/// rank orders the list, then whether a session ranks in its background,
/// as which setting asks, and when it last did.
pub(crate) fn doctor_line(relays: &RelayList, order: &str, hosts: &[String]) -> String {
    let kept = rank::load();
    let ours = !relays.explicit
        && podssh_relay::rank_list::order_now(&relays.primary().host) == "rank"
        && kept.as_ref().is_some_and(Rank::background);
    let order =
        if ours { "the order of the rank that podssh made in a session's background for this egress" } else { order };
    let words = background_words(rank_auto::asked_by(), kept.as_ref(), crate::pairs::now_ms());
    format!("{order}: {}; {words}", hosts.join(", "))
}

/// Whether a session ranks in its background, as `by` asks, in words.
fn background_words(by: Option<&str>, kept: Option<&Rank>, now: i64) -> String {
    let Some(by) = by else {
        return "no rank in a session's background (RelayRank auto asks for one, Q89)".into();
    };
    let made = kept.map(|k| k.background_ms).filter(|ms| *ms > 0 && *ms <= now);
    let partial = kept.is_some_and(|k| k.background() && k.partial);
    match made {
        None => format!("a rank in a session's background, as {by} asks: none made yet"),
        Some(ms) => {
            let age = crate::relay_rank::ago(std::time::Duration::from_millis((now - ms) as u64));
            let part = if partial { ", of part of its hosts so far" } else { "" };
            format!("a rank in a session's background, as {by} asks: the last made {age}{part}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The words of the setting and of the last background rank.
    #[test]
    fn the_doctor_names_the_setting_and_the_last_background_rank() {
        let by = Some("RelayRank auto");
        let none = background_words(by, None, 10);
        assert_eq!(none, "a rank in a session's background, as RelayRank auto asks: none made yet");
        let kept = Rank { source: rank::BACKGROUND.into(), partial: true, background_ms: 1_000, ..Rank::default() };
        let said = background_words(by, Some(&kept), 7_201_000);
        assert!(said.ends_with("asks: the last made 2 h ago, of part of its hosts so far"), "{said}");
        let whole = Rank { partial: false, ..kept.clone() };
        assert!(background_words(by, Some(&whole), 61_000).ends_with("the last made 60 s ago"));
        // A rank of relay rank keeps when the last background one was made.
        let on_demand = Rank { source: rank::ON_DEMAND.into(), ..kept };
        assert!(background_words(by, Some(&on_demand), 61_000).ends_with("the last made 60 s ago"));
        assert!(background_words(None, Some(&whole), 61_000).starts_with("no rank in a session's background"));
    }
}
