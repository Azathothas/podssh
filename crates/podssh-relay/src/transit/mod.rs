//! The transit road (T-436): a carrier of a pair's road through a
//! magic-wormhole transit relay, by default Least Authority's at
//! `wss://relay.mw.leastauthority.com`, a WebSocket on port 443 that needs
//! no account (the operator's ruling Q65 lets podssh try it unasked; its
//! terms and limits are in docs/carriers.md). The relay pairs two
//! connections that name one token and two sides, says `ok` to both, and
//! copies the bytes ([`meet`]); it passes `HTTPS_PROXY` as the relay does
//! ([`far::dial`]), and it is pure Rust, as this crate must be.
//!
//! The token and the key of podssh's proof of the pair come from the pair's
//! connect token, which both ends hold ([`token`]); a node waits at the
//! relay ([`far`]), and a client meets it there for each link ([`client`]).
//! A link ([`link`]) is a byte stream: each session over it runs the
//! resumable layer and, above the layer, the end-to-end channel
//! (`crate::e2e`), so the relay is trusted for availability only: it sees
//! the token, the sizes and the times, and a change that it makes ends the
//! session.

pub mod client;
pub mod far;
pub mod link;
pub mod meet;
pub mod token;

use std::sync::Arc;

use podssh_ws::url::WsUrl;

pub use client::Dialer;
pub use far::Node;
pub use link::Link;
pub use meet::{Missed, Part};
pub use token::{Keys, Side};

/// Least Authority's transit relay, which its Winden and Destiny use, as a
/// WebSocket on port 443.
pub const DEFAULT_URL: &str = "wss://relay.mw.leastauthority.com";
/// `no` turns the road off; a `ws://` or `wss://` URL names another relay.
pub const ENV: &str = "PODSSH_TRANSIT";

/// Where the lines of the road go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// What [`ENV`] asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No transit road.
    Off,
    /// The road, through this relay.
    On(WsUrl),
}

/// [`ENV`]'s value: unset, empty or yes, Least Authority's relay; no, none;
/// a `ws://` or `wss://` URL, that relay. Another word is refused, and the
/// refusal does not echo it, as a URL's query may hold a secret.
pub fn setting(value: Option<&str>) -> Result<Setting, String> {
    let value = value.map(str::trim).unwrap_or_default();
    match value.to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => WsUrl::parse(DEFAULT_URL).map(Setting::On),
        "no" | "off" | "false" | "0" => Ok(Setting::Off),
        _ => WsUrl::parse(value).map(Setting::On).map_err(|why| format!("{ENV}: yes, no, or a relay's URL: {why}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variable_turns_the_road_off_names_a_relay_or_is_refused_without_its_text() {
        let least = WsUrl::parse(DEFAULT_URL).unwrap();
        assert_eq!((least.tls, least.host.as_str(), least.port), (true, "relay.mw.leastauthority.com", 443));
        for on in [None, Some(""), Some(" yes "), Some("On"), Some("1")] {
            assert_eq!(setting(on), Ok(Setting::On(least.clone())), "{on:?}");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting(Some(off)), Ok(Setting::Off), "{off}");
        }
        let own = setting(Some("ws://127.0.0.1:4002/")).unwrap();
        assert_eq!(own, Setting::On(WsUrl::parse("ws://127.0.0.1:4002/").unwrap()));
        let refused = setting(Some("maybe?key=SECRET")).unwrap_err();
        assert!(refused.starts_with("PODSSH_TRANSIT: ") && !refused.contains("SECRET"), "{refused}");
    }
}
