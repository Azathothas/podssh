//! Whether a relay host offers the resumable layer on its forward road: the
//! field `forward.layer` of its `/relays.json`, `true` (T-173). A relay of the
//! contract has no such field, and a document that cannot be read offers
//! nothing, so a client asks for the layer only where a host said so.
//!
//! Beside it, `forward.host` names the process that answered, where several
//! share one name: a resume must reach the process that holds its session,
//! so each link of a session goes to that name. A client takes it only when
//! it is the host that it asked, with another port, or a host of its
//! deployment, by the pool's rule (`crate::pool::same_deployment`): a token
//! goes where the user's relay sends it, and no further.

use std::time::Duration;

use podssh_ws::client::open_tls;
use podssh_ws::{dial, http, ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::relay::{parse_relay, Relay};

/// The longest name of a host that a refusal of it shows.
const SHOWN_MOST: usize = 80;

/// What a host's `/relays.json` offers of the layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Offer {
    /// Whether it offers the layer.
    pub layer: bool,
    /// The process that holds each session of it, when the host named one
    /// that a client takes.
    pub at: Option<Relay>,
    /// Why a name that the host gave is not taken, for a line: not a host,
    /// or not of its deployment.
    pub refused: Option<String>,
}

impl Offer {
    /// The host that each link of a session goes to: the one that the offer
    /// names, else `asked`, whose document made the offer.
    pub fn holder(&self, asked: &Relay) -> Relay {
        self.at.clone().unwrap_or_else(|| asked.clone())
    }
}

/// Whether the `/relays.json` body `body` offers the layer.
pub fn offered(body: &[u8]) -> bool {
    of(body, &Relay { host: String::new(), port: 443 }).layer
}

/// The offer of the `/relays.json` body `body` of `asked`.
pub fn of(body: &[u8], asked: &Relay) -> Offer {
    let doc: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let forward = doc.get("forward");
    let layer = forward.and_then(|forward| forward.get("layer")) == Some(&serde_json::Value::Bool(true));
    let mut offer = Offer { layer, ..Offer::default() };
    match forward.and_then(|forward| forward.get("host")) {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(name)) => match named(asked, name) {
            Ok(relay) => offer.at = Some(relay),
            Err(why) => offer.refused = Some(why),
        },
        Some(_) => offer.refused = Some("forward.host is not a host's name".into()),
    }
    offer
}

/// The host that `text` names for the sessions of `asked`, `HOST[:PORT]`:
/// `asked`'s host with any port, or another host of its deployment; an
/// address names its own host alone, as an address has no deployment.
pub fn named(asked: &Relay, text: &str) -> Result<Relay, String> {
    let shown: String = podssh_ws::text::one_line(text).chars().take(SHOWN_MOST).collect();
    let relay = parse_relay(text).map_err(|_| format!("{shown:?} is not a host's name"))?;
    let literal = asked.host.parse::<std::net::IpAddr>().is_ok();
    let same = relay.host.eq_ignore_ascii_case(&asked.host);
    if same || (!literal && crate::pool::same_deployment(&asked.host, &relay.host)) {
        return Ok(relay);
    }
    Err(format!("{shown:?} is not of {}'s deployment", asked.host))
}

/// Ask `relay`, over TLS through `proxy`, within `timeout` for each step:
/// what it offers of the layer. `Err` says why its document was not read.
pub async fn ask(relay: &Relay, trust: &Trust, proxy: &ProxyChoice, timeout: Duration) -> Result<Offer, String> {
    if crate::open::offline() {
        return Err(format!("{} is set, so podssh does not connect anywhere", crate::open::OFFLINE_ENV));
    }
    let mut tls =
        open_tls(&relay.host, relay.port, &relay.host, trust, proxy, timeout).await.map_err(|e| e.to_string())?;
    let host_header = if relay.port == 443 { relay.host.clone() } else { dial::authority(&relay.host, relay.port) };
    tokio::time::timeout(timeout, over(&mut tls, &host_header, relay))
        .await
        .map_err(|_| format!("/relays.json took more than {} s", timeout.as_secs()))?
}

/// Ask over `stream`, a connection to `asked`: its `/relays.json`, read up
/// to the pool's bound on the body. A status that is not 2xx is a relay with
/// no such document, which offers nothing.
pub async fn over<S>(stream: &mut S, host_header: &str, asked: &Relay) -> Result<Offer, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let accept = [("Accept", "application/json")];
    let response = http::exchange(stream, "GET", host_header, "/relays.json", &accept, b"", crate::pool::MAX_BODY)
        .await
        .map_err(|e| format!("/relays.json: {e}"))?;
    if !(200..300).contains(&response.status) {
        return Ok(Offer::default());
    }
    Ok(of(&response.body, asked))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(host: &str, port: u16) -> Relay {
        Relay { host: host.into(), port }
    }

    #[test]
    fn only_a_true_of_forward_layer_is_an_offer() {
        assert!(offered(br#"{"service":"tcp-ssh-relay","forward":{"layer":true}}"#));
        for body in [
            &br#"{"service":"tcp-ssh-relay","pool":[]}"#[..],
            br#"{"forward":{"layer":"yes"}}"#,
            br#"{"forward":{"layer":false}}"#,
            br#"{"forward":true}"#,
            br#"{"layer":true}"#,
            b"not json",
            b"",
        ] {
            assert!(!offered(body), "{}", String::from_utf8_lossy(body));
        }
    }

    /// Each link of a session goes to the process that named itself, where
    /// several share the name that the user gave (T-173).
    #[test]
    fn a_host_of_the_deployment_that_the_offer_names_holds_each_session() {
        let asked = relay("relay.example.org", 443);
        let body = br#"{"forward":{"layer":true,"host":"relay-1.relay.example.org"}}"#;
        let offer = of(body, &asked);
        assert_eq!((offer.layer, offer.at.clone()), (true, Some(relay("relay-1.relay.example.org", 443))));
        assert_eq!(offer.holder(&asked), relay("relay-1.relay.example.org", 443));
        let offer = of(br#"{"forward":{"layer":true,"host":"Relay.Example.org:8443"}}"#, &asked);
        assert_eq!(offer.at, Some(relay("relay.example.org", 8443)), "the same host, another port");
        let loopback = relay("127.0.0.1", 9000);
        let offer = of(br#"{"forward":{"layer":true,"host":"127.0.0.1:9001"}}"#, &loopback);
        assert_eq!(offer.holder(&loopback), relay("127.0.0.1", 9001), "an address names its own host");
        let none = of(br#"{"forward":{"layer":true,"host":null}}"#, &asked);
        assert_eq!(none.holder(&asked), asked);
        assert_eq!((none.at, none.refused), (None, None));
    }

    /// A name of another deployment, or no host at all, is not taken: the
    /// session goes to the host that the user named, and a line says why.
    #[test]
    fn a_name_of_another_deployment_or_no_host_is_not_taken() {
        let asked = relay("relay.example.org", 443);
        for (host, says) in [
            ("relay.example.com", "not of relay.example.org's deployment"),
            ("evil.org", "not of relay.example.org's deployment"),
            ("a/b", "is not a host's name"),
            ("relay-1.relay.example.org:0", "is not a host's name"),
        ] {
            let body = format!(r#"{{"forward":{{"layer":true,"host":"{host}"}}}}"#);
            let offer = of(body.as_bytes(), &asked);
            assert_eq!((offer.layer, offer.at.clone()), (true, None), "{host}");
            assert!(offer.refused.as_deref().is_some_and(|why| why.contains(says)), "{host}: {:?}", offer.refused);
            assert_eq!(offer.holder(&asked), asked, "{host}");
        }
        let literal = relay("127.0.0.1", 9000);
        let offer = of(br#"{"forward":{"layer":true,"host":"10.0.0.1:9000"}}"#, &literal);
        assert_eq!(offer.at, None, "an address has no deployment: {:?}", offer.refused);
        let offer = of(br#"{"forward":{"layer":true,"host":7}}"#, &asked);
        assert_eq!((offer.at, offer.refused.as_deref()), (None, Some("forward.host is not a host's name")));
        let long = format!(r#"{{"forward":{{"layer":true,"host":"x\u001b[2J{}.example.com"}}}}"#, "a".repeat(300));
        let refused = of(long.as_bytes(), &asked).refused.unwrap_or_default();
        assert!(refused.len() < 200 && !refused.contains('\u{1b}'), "a refusal shows a short line: {refused:?}");
    }
}
