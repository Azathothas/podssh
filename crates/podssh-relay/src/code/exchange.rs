//! What two podssh ends say once the code made their key (T-086), each one
//! JSON object in a numbered phase, sealed (`super::wormhole`): the giver,
//! the node's host, offers its label, its node's key and, where it holds a
//! pair, the operator's part; the taker answers with its own key; the giver
//! says what it did with that key. The version phase names podssh's
//! pairing, so that a peer of another application with the same code is
//! told apart before either says a word of its own.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::identity::PublicKey;
use crate::pair::part::{PartRef, PartStored};
use crate::pair::OperatorPart;
use crate::relay::check_node_name;

/// podssh's pairing, in `app_versions`.
pub const PAIRING: &str = "podssh-pair";
/// The version of the words below.
pub const VERSION: u64 = 1;
/// The most of the giver's words that the taker shows.
const SAID_MOST: usize = 300;

/// What this podssh says in its version phase.
pub fn versions() -> Value {
    let mut versions = serde_json::Map::new();
    versions.insert(PAIRING.to_string(), Value::from(VERSION));
    Value::Object(versions)
}

/// Whether the other end's `app_versions` name podssh's pairing of this
/// version; the words to say when they do not.
pub fn ours(theirs: &Value) -> Result<(), String> {
    match theirs.get(PAIRING).and_then(Value::as_u64) {
        Some(VERSION) => Ok(()),
        Some(other) => Err(format!("the other end speaks podssh's pairing of version {other}, this podssh {VERSION}")),
        None => Err("the other end is no pairing of podssh's: another program had the same code".into()),
    }
}

/// The giver's offer: the label that it gives the node, the node's key, and
/// the operator's part of its pair.
pub struct Offer {
    pub label: String,
    pub node: PublicKey,
    pub part: Option<OperatorPart>,
}

#[derive(Serialize)]
struct OfferRef<'a> {
    label: &'a str,
    node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    part: Option<PartRef<'a>>,
}

#[derive(Deserialize)]
struct OfferIn {
    label: String,
    node: String,
    #[serde(default)]
    part: Option<PartStored>,
}

impl Offer {
    /// Its message. It holds a connect token, and is wiped on drop.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let part = self.part.as_ref().map(OperatorPart::wire);
        let offer = OfferRef { label: &self.label, node: self.node.hex(), part };
        Zeroizing::new(serde_json::to_vec(&offer).unwrap_or_default())
    }

    /// The offer of `bytes`, each part checked at `now_ms`: the label as a
    /// name, the key, and the pair as T-076 and T-078 check one.
    pub fn from_bytes(bytes: &[u8], now_ms: i64) -> Result<Offer, String> {
        let offer: OfferIn =
            serde_json::from_slice(bytes).map_err(|_| "the node's offer is not podssh's".to_string())?;
        let OfferIn { label, node, part } = offer;
        check_node_name(&label).map_err(|why| format!("the node's label {why}"))?;
        let node = PublicKey::parse(&node).ok_or("the node's key is not an Ed25519 key in hex")?;
        let part = match part {
            Some(part) => Some(OperatorPart::from_wire(part, now_ms).map_err(|e| format!("the node's pair: {e}"))?),
            None => None,
        };
        Ok(Offer { label, node, part })
    }
}

/// The taker's answer: its key, the one of its end-to-end channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub operator: PublicKey,
}

impl Answer {
    pub fn to_bytes(&self) -> Vec<u8> {
        json!({ "operator": self.operator.hex() }).to_string().into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Answer, String> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| "the operator's answer is not podssh's")?;
        let key = value["operator"].as_str().and_then(PublicKey::parse);
        Ok(Answer { operator: key.ok_or("the operator's key is not an Ed25519 key in hex")? })
    }
}

/// What the giver did with the taker's key: whether its node lets it in
/// now, and in what words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub admitted: bool,
    pub said: String,
}

impl Done {
    pub fn to_bytes(&self) -> Vec<u8> {
        json!({ "admitted": self.admitted, "said": self.said }).to_string().into_bytes()
    }

    /// The giver's words, on one line and cut short, as they are shown.
    pub fn from_bytes(bytes: &[u8]) -> Result<Done, String> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| "the node's last word is not podssh's")?;
        let admitted = value["admitted"].as_bool().ok_or("the node's last word says nothing of the key")?;
        let said = podssh_ws::text::one_line(value["said"].as_str().unwrap_or_default());
        Ok(Done { admitted, said: said.chars().take(SAID_MOST).collect() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "0123456789abcdef0123456789abcdef";
    const TOKEN: &str = "testonlyconnect0000000000000000000000000000000000000000000000000";
    const NOW: i64 = 1_800_000_000_000;

    fn part() -> OperatorPart {
        let token = Zeroizing::new(TOKEN.to_string());
        OperatorPart::checked("relay.example.org:8443", NAME.into(), token, NOW + 3_600_000, NOW).unwrap()
    }

    #[test]
    fn an_offer_goes_and_comes_back_checked() {
        let offer = Offer { label: "lab".into(), node: PublicKey([9; 32]), part: Some(part()) };
        let read = Offer::from_bytes(&offer.to_bytes(), NOW).unwrap();
        assert_eq!((read.label.as_str(), read.node), ("lab", PublicKey([9; 32])));
        let read = read.part.unwrap();
        assert_eq!((read.relay.host.as_str(), read.relay.port, read.name.as_str()), ("relay.example.org", 8443, NAME));
        assert_eq!(read.connect_token(), TOKEN);
        // Read an hour and more later, the pair has less than 10 minutes.
        let Err(late) = Offer::from_bytes(&offer.to_bytes(), NOW + 3_400_000) else { panic!("a late pair taken") };
        assert!(late.contains("the node's pair"), "{late}");
        let bare = Offer { label: "lab".into(), node: PublicKey([9; 32]), part: None };
        assert!(Offer::from_bytes(&bare.to_bytes(), NOW).unwrap().part.is_none());
        let bad = br#"{"label": "../lab", "node": "00"}"#;
        let Err(why) = Offer::from_bytes(bad, NOW) else { panic!("a bad label taken") };
        assert!(why.starts_with("the node's label"), "{why}");
    }

    #[test]
    fn the_answer_and_the_last_word_go_and_come_back() {
        let answer = Answer { operator: PublicKey([3; 32]) };
        assert_eq!(Answer::from_bytes(&answer.to_bytes()).unwrap(), answer);
        assert!(Answer::from_bytes(br#"{"operator": "nope"}"#).is_err());
        let done = Done { admitted: true, said: "in the allowlist\nof the node".into() };
        let read = Done::from_bytes(&done.to_bytes()).unwrap();
        assert_eq!((read.admitted, read.said.as_str()), (true, "in the allowlist of the node"));
    }

    #[test]
    fn the_version_phase_names_podssh_s_pairing() {
        assert_eq!(versions(), json!({ "podssh-pair": 1 }));
        assert!(ours(&versions()).is_ok());
        assert!(ours(&json!({ "podssh-pair": 2 })).unwrap_err().contains("of version 2"));
        assert!(ours(&json!({ "podssh-test": 1 })).unwrap_err().contains("no pairing of podssh's"));
        assert!(ours(&Value::Null).is_err());
    }
}
