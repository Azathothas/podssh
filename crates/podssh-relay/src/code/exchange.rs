//! What two podssh ends say once the code made their key (T-086), each one
//! JSON object in a numbered phase, sealed (`super::wormhole`): the giver,
//! the node's host, offers its label, its node's key and, where it holds a
//! pair, the operator's part; the taker answers with its own key; the giver
//! says what it did with that key. The version phase names podssh's
//! pairing, so that a peer of another application with the same code is
//! told apart before either says a word of its own; so is an end of the
//! net's invitation (T-616), another [`Kind`] of exchange over the same
//! code, whose words are the binary's.

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
    PAIR.versions()
}

/// Whether the other end's `app_versions` name podssh's pairing of this
/// version; the words to say when they do not.
pub fn ours(theirs: &Value) -> Result<(), String> {
    PAIR.ours(theirs)
}

/// One kind of exchange by a code, as its version phase names it. Both
/// kinds share podssh's AppID, so that a code given to the other kind's
/// command is told apart with the words of the command that takes it, not
/// as a code typed wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kind {
    /// Its name in `app_versions`.
    pub name: &'static str,
    /// The version of its words.
    pub version: u64,
    /// What it is, in a line.
    pub what: &'static str,
    /// The commands that give and take its code, for a line.
    pub giver: &'static str,
    pub taker: &'static str,
}

/// The pairing of a node's host and an operator (T-086).
pub const PAIR: Kind = Kind {
    name: PAIRING,
    version: VERSION,
    what: "pairing",
    giver: "podssh relay pair NAME --code",
    taker: "podssh relay join NAME",
};
/// A new device's join of its owner's net (T-616).
pub const NET_INVITE: Kind = Kind {
    name: "podssh-net-invite",
    version: 1,
    what: "invitation to a net",
    giver: "podssh net invite NAME",
    taker: "podssh net join",
};
/// Each kind that this podssh runs.
pub const KINDS: [Kind; 2] = [PAIR, NET_INVITE];

impl Kind {
    /// What this end of the kind says in its version phase.
    pub fn versions(self) -> Value {
        let mut versions = serde_json::Map::new();
        versions.insert(self.name.to_string(), Value::from(self.version));
        Value::Object(versions)
    }

    /// Whether the other end's `app_versions` name this kind of this
    /// version; the words to say when they do not, which name the command
    /// of the other kind when the other end runs one.
    pub fn ours(self, theirs: &Value) -> Result<(), String> {
        match theirs.get(self.name).and_then(Value::as_u64) {
            Some(version) if version == self.version => Ok(()),
            Some(other) => Err(format!(
                "the other end speaks podssh's {} of version {other}, this podssh {}",
                self.what, self.version
            )),
            None => match KINDS.iter().find(|kind| kind.name != self.name && theirs.get(kind.name).is_some()) {
                Some(kind) => Err(format!(
                    "the other end runs podssh's {}, not its {}: a code of {} is taken by {}, and one of {} by {}",
                    kind.what, self.what, self.giver, self.taker, kind.giver, kind.taker
                )),
                None => {
                    Err(format!("the other end is no {} of podssh's: another program had the same code", self.what))
                }
            },
        }
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

    #[test]
    fn each_kind_takes_its_own_and_names_the_command_of_the_other() {
        assert_eq!(NET_INVITE.versions(), json!({ "podssh-net-invite": 1 }));
        assert!(NET_INVITE.ours(&NET_INVITE.versions()).is_ok());
        let pair_at_invite = PAIR.ours(&NET_INVITE.versions()).unwrap_err();
        assert!(pair_at_invite.contains("runs podssh's invitation to a net, not its pairing"), "{pair_at_invite}");
        assert!(pair_at_invite.ends_with("one of podssh net invite NAME by podssh net join"), "{pair_at_invite}");
        let invite_at_pair = NET_INVITE.ours(&PAIR.versions()).unwrap_err();
        assert!(invite_at_pair.contains("one of podssh relay pair NAME --code by podssh relay join NAME"));
        assert!(NET_INVITE.ours(&json!({ "podssh-test": 1 })).unwrap_err().contains("no invitation to a net"));
        assert!(NET_INVITE.ours(&json!({ "podssh-net-invite": 2 })).unwrap_err().contains("of version 2"));
        assert_ne!(PAIR.name, NET_INVITE.name);
    }
}
