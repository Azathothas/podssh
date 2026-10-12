//! The one line that `podssh node --temporary` gives `podssh ssh --upgrade`
//! (T-167), on the node's stdout, which the SSH channel of the first login
//! carries, encrypted: a mark, then JSON with the pair's relay, its name,
//! the connect token and its expiry, the node's key in the end-to-end
//! channel, and whether the node left its SSH session. The token is a
//! credential: it is on no argv, in no file and in no log.

use podssh_relay::identity::{KeyName, PublicKey};
use podssh_relay::pair::Pair;
use podssh_relay::relay::Relay;
use serde_json::Value;
use zeroize::Zeroizing;

/// The mark that starts the line: no other output of a login starts so.
pub(crate) const MARK: &str = "podssh-upgrade/1 ";

/// What the client reads of the line.
pub(crate) struct Offer {
    pub relay: Relay,
    pub name: String,
    connect_token: Zeroizing<String>,
    pub expires_ms: i64,
    /// The node's key, which the end-to-end channel must find.
    pub node_key: KeyName,
    /// Whether the node left the SSH session that started it: when it did
    /// not, that connection stays open while the session runs.
    pub detached: bool,
}

impl Offer {
    pub fn connect_token(&self) -> &str {
        &self.connect_token
    }
}

/// The line of `pair`, with the node's key and whether the node leaves its
/// session, and its line end.
pub(crate) fn line(pair: &Pair, node_key: &PublicKey, detached: bool) -> Zeroizing<String> {
    let text = |s: &str| Value::String(s.to_string()).to_string();
    let token = Zeroizing::new(serde_json::to_string(pair.connect_token()).unwrap_or_default());
    Zeroizing::new(format!(
        "{MARK}{{\"relay\":{},\"name\":{},\"connect_token\":{},\"expires\":{},\
         \"node_key\":{},\"detached\":{detached}}}\n",
        text(&podssh_relay::token::relay_name(&pair.relay)),
        text(&pair.name),
        token.as_str(),
        pair.expires_ms,
        text(&node_key.fingerprint()),
    ))
}

/// The offer in the rest of a line after [`MARK`]; each field checked as a
/// pair's operator file is.
pub(crate) fn read(rest: &str) -> Result<Offer, String> {
    let mut value: Value = serde_json::from_str(rest).map_err(|_| "not the expected JSON".to_string())?;
    let connect_token = match value.get_mut("connect_token").map(Value::take) {
        Some(Value::String(token)) => Zeroizing::new(token),
        _ => return Err("no connect token".into()),
    };
    if !podssh_relay::cache::valid_token(&connect_token) {
        return Err("a connect token with no token's shape".into());
    }
    let field = |name: &str| value.get(name).and_then(Value::as_str).ok_or_else(|| format!("no {name}"));
    let relay = podssh_relay::relay::parse_relay(field("relay")?)?;
    let name = field("name")?.to_string();
    podssh_ws::names::check_node_name(&name).map_err(|_| format!("{name:?} names no pair"))?;
    let node_key = KeyName::parse(field("node_key")?).ok_or("a node key that is no key")?;
    let expires_ms = value.get("expires").and_then(Value::as_i64).ok_or("no expiry")?;
    let detached = value.get("detached").and_then(Value::as_bool).unwrap_or(false);
    Ok(Offer { relay, name, connect_token, expires_ms, node_key, detached })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";

    fn rest(line: &str) -> &str {
        line.strip_prefix(MARK).expect("the mark").trim_end()
    }

    #[test]
    fn the_line_reads_back() {
        let line = format!(
            "{MARK}{{\"relay\":\"relay-a.test:8443\",\"name\":\"p-0123456789abcdef0123456789abcdef\",\
             \"connect_token\":\"{TOKEN}\",\"expires\":1900000000000,\
             \"node_key\":\"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\",\"detached\":true}}\n"
        );
        let offer = read(rest(&line)).expect("an offer");
        assert_eq!((offer.relay.host.as_str(), offer.relay.port), ("relay-a.test", 8443));
        assert_eq!(offer.name, "p-0123456789abcdef0123456789abcdef");
        assert_eq!(offer.connect_token(), TOKEN);
        assert_eq!(offer.expires_ms, 1_900_000_000_000);
        assert_eq!(offer.node_key.fingerprint(), "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU");
        assert!(offer.detached);
    }

    #[test]
    fn a_line_that_is_not_an_offer_is_refused_by_name() {
        let bad_name = format!("{{\"connect_token\":\"{TOKEN}\",\"relay\":\"r.test\",\"name\":\"../x\"}}");
        for (json, says) in [
            ("{", "JSON"),
            ("{\"relay\":\"r.test\"}", "no connect token"),
            ("{\"connect_token\":\"a b\"}", "token's shape"),
            (bad_name.as_str(), "names no pair"),
        ] {
            let why = read(json).err().unwrap_or_default();
            assert!(why.contains(says), "{json}: {why}");
        }
    }
}
