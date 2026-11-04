//! The words of the net's invitation by a short code (T-616), each one
//! message of the exchange of T-086 (`podssh_relay::code::run`, the kind
//! `NET_INVITE`), sealed under the code's key: the owner's host offers the
//! net's name, its owner's key, the name that the new device gets and its
//! roles; the device answers with its key, or with why it refuses; the
//! owner's host says what it did, then gives the signed document in parts,
//! as a mailbox bounds each message. The library carries bytes; the
//! document and its signature are read here, as each is the binary's.

use podssh_relay::code::run::Ends;
use podssh_relay::code::{self, Failed};
use podssh_relay::identity::PublicKey;
use serde_json::{json, Value};

use super::doc;
use super::sign;
use crate::exitmap::Fault;
use crate::relay_code;
use crate::relay_settings::Refusal;

/// The most bytes of one part of the document: with its seal and in hex, a
/// message of 12 KiB, below the 16 KiB of digits that podssh's relay role
/// takes for one body.
pub const PART: usize = 6 * 1024;
/// The most bytes of the signed document, as the cache keeps one file.
pub const SIGNED_MOST: usize = podssh_relay::cache::MAX_FILE as usize;
/// The most roles that an offer names.
const ROLES_MOST: usize = 16;
/// The most of the other end's words that a line shows.
const SAID_MOST: usize = 300;
/// The way left when `no` turns the code off.
const WAY: &str = "add the device's key on the owner's host with podssh net add NAME KEY, then take the document on \
                   the device with podssh net take FILE";

/// The owner's offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The net's name.
    pub net: String,
    /// The owner's public key, as an OpenSSH line, whose fingerprint the
    /// device makes and checks; never a fingerprint that the owner's host
    /// says.
    pub owner: String,
    /// The name that the device gets in the net.
    pub member: String,
    pub roles: Vec<String>,
    /// The serial held by the owner's host as it offers.
    pub serial: u64,
}

impl Offer {
    pub fn to_bytes(&self) -> Vec<u8> {
        let offer = json!({
            "net": self.net, "owner": self.owner, "member": self.member, "roles": self.roles, "serial": self.serial,
        });
        offer.to_string().into_bytes()
    }

    /// The offer of `bytes`, each part checked: the names, the owner's key
    /// and the roles, which this podssh shows as words and never runs.
    pub fn from_bytes(bytes: &[u8]) -> Result<Offer, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| "the owner's offer is not podssh's".to_string())?;
        let text = |field: &str| value[field].as_str().ok_or(format!("the owner's offer has no {field}"));
        let (net, owner, member) = (text("net")?, text("owner")?, text("member")?);
        doc::check_name(net).map_err(|why| format!("the net's name {why}"))?;
        doc::check_name(member).map_err(|why| format!("the device's name {why}"))?;
        if sign::owner_fingerprint(owner).is_empty() {
            return Err("the owner's key is not an OpenSSH public key".into());
        }
        let roles = value["roles"].as_array().ok_or("the owner's offer has no roles")?;
        let roles: Vec<String> = roles.iter().filter_map(Value::as_str).map(str::to_string).collect();
        if roles.is_empty() || roles.len() > ROLES_MOST || roles.iter().any(|r| doc::check_name(r).is_err()) {
            return Err("the owner's offer names roles that are not words".into());
        }
        let serial = value["serial"].as_u64().ok_or("the owner's offer has no serial")?;
        Ok(Offer { net: net.into(), owner: owner.into(), member: member.into(), roles, serial })
    }

    /// The owner key's fingerprint, made here from its key.
    pub fn fingerprint(&self) -> String {
        sign::owner_fingerprint(&self.owner)
    }
}

/// The device's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Its key, the member's.
    Key(PublicKey),
    /// Why it does not join; the owner's host signs nothing.
    Refused(String),
}

impl Answer {
    pub fn to_bytes(&self) -> Vec<u8> {
        let value = match self {
            Answer::Key(key) => json!({ "key": key.hex() }),
            Answer::Refused(why) => json!({ "refused": why }),
        };
        value.to_string().into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Answer, String> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| "the device's answer is not podssh's")?;
        if let Some(why) = value["refused"].as_str() {
            return Ok(Answer::Refused(shown(why)));
        }
        let key = value["key"].as_str().and_then(PublicKey::parse);
        Ok(Answer::Key(key.ok_or("the device's key is not an Ed25519 key in hex")?))
    }
}

/// The owner's host's first last word: whether the document names the
/// device's key, its words, and the parts of the signed document after it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Head {
    admitted: bool,
    said: String,
    parts: usize,
    bytes: usize,
}

/// The last words of the owner's host: the head, then each part of
/// `signed`, the document and its armoured signature, when it gives one.
pub fn last_words(admitted: bool, said: &str, signed: Option<&[u8]>) -> Vec<Vec<u8>> {
    let signed = signed.unwrap_or_default();
    let parts: Vec<Vec<u8>> = signed.chunks(PART).map(<[u8]>::to_vec).collect();
    let head = json!({ "admitted": admitted, "said": said, "parts": parts.len(), "bytes": signed.len() });
    std::iter::once(head.to_string().into_bytes()).chain(parts).collect()
}

/// What the device read of the last words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Got {
    /// The owner's host added no member: its words.
    NotAdmitted(String),
    /// Its words, and the signed document's bytes, not checked yet.
    Signed { said: String, bytes: Vec<u8> },
}

/// The device's reading of the last words, one at a time.
#[derive(Debug, Default)]
pub struct Reading {
    head: Option<Head>,
    bytes: Vec<u8>,
    parts: usize,
}

impl Reading {
    /// One last word: `None` while parts are to come.
    pub fn read(&mut self, word: &[u8]) -> Result<Option<Got>, String> {
        let Some((parts, bytes)) = self.head.as_ref().map(|head| (head.parts, head.bytes)) else {
            return self.first(word);
        };
        if self.bytes.len() + word.len() > bytes || word.len() > PART {
            return Err("the owner's host gave more of the document than it said".into());
        }
        self.bytes.extend_from_slice(word);
        self.parts += 1;
        if self.parts < parts {
            return Ok(None);
        }
        let Some(head) = self.head.take() else { return Err("the owner's host gave no head".into()) };
        if self.bytes.len() != head.bytes {
            let given = self.bytes.len();
            return Err(format!("the owner's host said {} bytes of the document, and gave {given}", head.bytes));
        }
        Ok(Some(Got::Signed { said: head.said, bytes: std::mem::take(&mut self.bytes) }))
    }

    /// The head: the end when the owner's host added no member, else the
    /// first of the parts to come, as an admitted head names one at least.
    fn first(&mut self, word: &[u8]) -> Result<Option<Got>, String> {
        let head = head_of(word)?;
        if !head.admitted {
            return Ok(Some(Got::NotAdmitted(head.said)));
        }
        self.head = Some(head);
        Ok(None)
    }
}

/// The head of `word`, checked against the bounds of a document.
fn head_of(word: &[u8]) -> Result<Head, String> {
    let value: Value = serde_json::from_slice(word).map_err(|_| "the owner's last word is not podssh's")?;
    let admitted = value["admitted"].as_bool().ok_or("the owner's last word says nothing of the key")?;
    let said = shown(value["said"].as_str().unwrap_or_default());
    let parts = value["parts"].as_u64().unwrap_or(0) as usize;
    let bytes = value["bytes"].as_u64().unwrap_or(0) as usize;
    if admitted && (bytes == 0 || bytes > SIGNED_MOST || parts != bytes.div_ceil(PART)) {
        return Err(format!("the owner's host gave a document of {bytes} bytes in {parts} parts"));
    }
    Ok(Head { admitted, said, parts, bytes })
}

/// The other end's words, on one line and cut short, as a line shows them.
fn shown(text: &str) -> String {
    podssh_ws::text::one_line(text).chars().take(SAID_MOST).collect()
}

/// The mailboxes of `--pair-mailbox`, else of `PODSSH_PAIR_MAILBOX`, else the
/// public ones, and how to reach them, as the pairing's (T-086).
pub fn ends(named: Option<&str>) -> Result<Ends, Refusal> {
    let value = std::env::var(code::ENV).ok();
    let mailboxes = code::mailboxes_for(named, value.as_deref(), WAY);
    relay_code::ends_of(mailboxes, named.is_some(), None, "podssh net")
}

/// A failure of the exchange, with its code and the way left: the
/// pairing's, in the words of the net.
pub fn refused(failed: Failed, way: &str) -> Refusal {
    match failed {
        Failed::Nobody => Refusal {
            message: format!(
                "no owner's host waits at this code: it expired, it was used, or it was typed wrong; {way}"
            ),
            code: Fault::Auth.code(),
        },
        other => relay_code::refusal(other, way),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = include_str!("testdata/owner.pub");

    fn offer() -> Offer {
        let owner = OWNER.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        Offer { net: "home".into(), owner, member: "lab".into(), roles: vec!["node".into()], serial: 3 }
    }

    #[test]
    fn an_offer_goes_and_comes_back_checked() {
        let offer = offer();
        assert_eq!(Offer::from_bytes(&offer.to_bytes()).unwrap(), offer);
        assert_eq!(offer.fingerprint(), "SHA256:zbnY6ML2GQd70sbSPxZeNAEroWGl/t+oaOhgQqrc/no");
        for (field, bad, says) in [
            ("net", json!("home.example"), "the net's name"),
            ("member", json!("../lab"), "the device's name"),
            ("owner", json!("ssh-ed25519 nope"), "not an OpenSSH public key"),
            ("roles", json!([]), "roles that are not words"),
            ("roles", json!(["node", "a b"]), "roles that are not words"),
            ("serial", json!("3"), "no serial"),
        ] {
            let mut value: Value = serde_json::from_slice(&offer.to_bytes()).unwrap();
            value[field] = bad;
            let why = Offer::from_bytes(value.to_string().as_bytes()).unwrap_err();
            assert!(why.contains(says), "{field}: {why}");
        }
        assert!(Offer::from_bytes(b"not json").is_err());
    }

    #[test]
    fn the_answer_is_a_key_or_a_refusal_on_one_short_line() {
        let key = Answer::Key(PublicKey([4; 32]));
        assert_eq!(Answer::from_bytes(&key.to_bytes()).unwrap(), key);
        let refused = Answer::Refused(format!("not\nthe owner{}", "x".repeat(400)));
        let Answer::Refused(read) = Answer::from_bytes(&refused.to_bytes()).unwrap() else { panic!("a key") };
        assert!(read.starts_with("not the owner") && read.chars().count() == SAID_MOST, "{read}");
        assert!(Answer::from_bytes(br#"{"key": "nope"}"#).is_err());
    }

    #[test]
    fn a_document_goes_in_parts_and_comes_back_whole() {
        let signed: Vec<u8> = (0..PART * 2 + 17).map(|i| (i % 251) as u8).collect();
        let words = last_words(true, "added", Some(signed.as_slice()));
        assert_eq!(words.len(), 4, "a head and three parts");
        assert!(words.iter().skip(1).all(|part| part.len() <= PART));
        let mut reading = Reading::default();
        let mut got = None;
        for (at, word) in words.iter().enumerate() {
            got = reading.read(word).unwrap();
            assert_eq!(got.is_some(), at == words.len() - 1, "{at}");
        }
        assert_eq!(got, Some(Got::Signed { said: "added".into(), bytes: signed }));
        let no = last_words(false, "a member with another key", None);
        assert_eq!(no.len(), 1);
        let got = Reading::default().read(&no[0]).unwrap();
        assert_eq!(got, Some(Got::NotAdmitted("a member with another key".into())));
    }

    #[test]
    fn a_head_or_a_part_out_of_its_bounds_is_refused() {
        let head = |admitted: bool, parts: usize, bytes: usize| {
            json!({ "admitted": admitted, "said": "", "parts": parts, "bytes": bytes }).to_string().into_bytes()
        };
        for (parts, bytes) in [(0, 0), (1, SIGNED_MOST + 1), (2, PART), (1, PART + 1)] {
            assert!(Reading::default().read(&head(true, parts, bytes)).is_err(), "{parts} {bytes}");
        }
        let mut reading = Reading::default();
        assert_eq!(reading.read(&head(true, 1, 10)).unwrap(), None);
        assert!(reading.read(&[0; 11]).unwrap_err().contains("more of the document"));
        let mut reading = Reading::default();
        assert_eq!(reading.read(&head(true, 1, 10)).unwrap(), None);
        assert!(reading.read(&[0; 9]).unwrap_err().contains("said 10 bytes"));
        assert!(Reading::default().read(b"{}").is_err(), "a head that says nothing of the key");
    }

    #[test]
    fn nobody_at_a_code_is_the_owner_s_host_and_77() {
        let nobody = refused(Failed::Nobody, "ask again");
        assert_eq!(nobody.code, 77);
        assert!(nobody.message.starts_with("no owner's host waits") && nobody.message.ends_with("; ask again"));
        assert_eq!(refused(Failed::WrongCode, "x").code, 77);
        assert_eq!(refused(Failed::Unreachable("m".into()), "x").code, 69);
    }
}
