//! What each relay host offered of the resumable layer, kept for a day
//! (T-173), so that a run that did not ask for the layer takes it where its
//! first host offered it, with no read of `/relays.json` of its own: each
//! read of a host's offer keeps it (a run that asked, the pool's refresh of
//! the same document, the once-a-day read of a host that the user named).
//!
//! A kept offer is a hint, never a promise: a host whose layer path then
//! answers 404 is forgotten, and the session takes the contract's road. The
//! name of the process that holds the sessions is kept as the host gave it,
//! and checked again by [`offer::named`] at each read of it, as at the read
//! of the document.

use serde::{Deserialize, Serialize};

use super::offer::{self, Offer};
use crate::cache;
use crate::relay::Relay;

/// How long a kept offer stands: a day, as a role's operator who turns the
/// layer on or off is heard by the next day's runs.
pub const FRESH_MS: i64 = 24 * 3600 * 1000;

#[derive(Serialize, Deserialize)]
struct KeptOffer {
    read_ms: i64,
    layer: bool,
    /// `forward.host` as the host gave it and as the client took it.
    #[serde(default)]
    at: Option<String>,
}

/// The cache file of `relay`'s offer.
pub fn file_name(relay: &Relay) -> String {
    format!("relay-offer-{}-{}.json", cache::safe_name(&relay.host), relay.port)
}

/// Keep `offered`, what `relay` offered at `now_ms`; a cache that takes no
/// file is no failure of the run, which reads the offer again next time.
pub fn keep(relay: &Relay, offered: &Offer, now_ms: i64) {
    let at = offered.at.as_ref().map(|at| podssh_ws::dial::authority(&at.host, at.port));
    let kept = KeptOffer { read_ms: now_ms, layer: offered.layer, at };
    if let Ok(body) = serde_json::to_vec(&kept) {
        let _ = cache::store_file(&file_name(relay), &body);
    }
}

/// What `relay` offered within [`FRESH_MS`] of `now_ms`; `None` when nothing
/// is kept, or what is kept is older, or a clock went back before it.
pub fn kept(relay: &Relay, now_ms: i64) -> Option<Offer> {
    let text = cache::load_file(&file_name(relay))?;
    of_text(&text, relay, now_ms)
}

/// [`kept`] of a file's text.
fn of_text(text: &str, relay: &Relay, now_ms: i64) -> Option<Offer> {
    let kept: KeptOffer = serde_json::from_str(text).ok()?;
    let age = now_ms.checked_sub(kept.read_ms)?;
    if !(0..=FRESH_MS).contains(&age) {
        return None;
    }
    let mut offered = Offer { layer: kept.layer, ..Offer::default() };
    if let Some(at) = &kept.at {
        match offer::named(relay, at) {
            Ok(holder) => offered.at = Some(holder),
            Err(why) => offered.refused = Some(why),
        }
    }
    Some(offered)
}

/// [`keep`], now.
pub fn keep_now(relay: &Relay, offered: &Offer) {
    keep(relay, offered, crate::pool::now_ms());
}

/// [`kept`], now.
pub fn kept_now(relay: &Relay) -> Option<Offer> {
    kept(relay, crate::pool::now_ms())
}

/// Forget what `relay` offered: its layer path refused a session.
pub fn forget(relay: &Relay) {
    cache::remove_named_from(&cache::candidate_dirs(), &file_name(relay));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(host: &str, port: u16) -> Relay {
        Relay { host: host.into(), port }
    }

    fn text(read_ms: i64, layer: bool, at: Option<&str>) -> String {
        serde_json::to_string(&KeptOffer { read_ms, layer, at: at.map(String::from) }).unwrap()
    }

    #[test]
    fn an_offer_stands_for_a_day_and_not_after_it_nor_before_it_was_read() {
        let asked = relay("relay.example.org", 443);
        let now = 1_793_577_600_000;
        let offered = of_text(&text(now - FRESH_MS, true, None), &asked, now).expect("a day old");
        assert!(offered.layer);
        assert_eq!(offered.holder(&asked), asked);
        assert!(of_text(&text(now - FRESH_MS - 1, true, None), &asked, now).is_none(), "older than a day");
        assert!(of_text(&text(now + 1, true, None), &asked, now).is_none(), "a clock that went back");
        assert!(!of_text(&text(now, false, None), &asked, now).unwrap().layer, "an offer of none is kept too");
        assert!(of_text("not json", &asked, now).is_none());
    }

    #[test]
    fn the_holder_is_checked_again_as_at_the_read_of_the_document() {
        let asked = relay("relay.example.org", 443);
        let now = 1_793_577_600_000;
        let same = of_text(&text(now, true, Some("b.example.org:8443")), &asked, now).unwrap();
        assert_eq!(same.at, Some(relay("b.example.org", 8443)));
        let foreign = of_text(&text(now, true, Some("elsewhere.test")), &asked, now).unwrap();
        assert_eq!(foreign.at, None);
        assert!(foreign.refused.unwrap().contains("is not of relay.example.org's deployment"));
    }

    #[test]
    fn each_host_and_port_has_a_file_of_its_own() {
        assert_eq!(file_name(&relay("Relay.Example.org", 443)), "relay-offer-relay.example.org-443.json");
        assert_ne!(file_name(&relay("a.test", 443)), file_name(&relay("a.test", 8443)));
    }
}
