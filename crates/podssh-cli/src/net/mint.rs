//! The relay role's mint for the members of the net (T-455): `podssh relay
//! serve --mint net` and `podssh node --quick-tunnel --relay --mint net`. A
//! member of the document that this host holds proves itself by its key's
//! signature of the role's challenge (T-448), and mints a token and makes a
//! pair as far as the net's policy (T-430) lets it reach `relay:NODE`, this
//! role's member by its name, or `relay:*`; with no policy each member
//! mints, as each member reaches each. The document is read, and its
//! owner's signature checked, for each request, so that a member that a
//! newer document removed is refused from that serial on; a token that it
//! minted before lives on, as the tokens of a list's key do (T-448).

use podssh_relay::identity::PublicKey;
use podssh_relay::serve::keys;

use super::doc::Doc;
use super::policy::{self, Want};
use super::store;

/// The net's members, as the relay role of this host mints for them.
pub struct Members {
    /// The key of the role's host: a node's, whose name in the net
    /// `relay:NODE` names; none for `podssh relay serve`, which has no key
    /// of its own and which `relay:*` alone names.
    me: Option<PublicKey>,
}

impl Members {
    pub fn new(me: Option<PublicKey>) -> Members {
        Members { me }
    }
}

impl keys::Members for Members {
    fn mints(&self, key: &PublicKey) -> Result<String, String> {
        // The client never hears the file, nor why it failed: `podssh net
        // ls` on the role's host says it.
        let Ok(held) = held() else {
            return Err("this relay holds no net that it can read now, so it mints for no member".into());
        };
        verdict(&held.signed.doc, super::now(), self.me.as_ref(), key)
    }

    fn shown(&self) -> Result<String, String> {
        let held = held()?;
        let doc = &held.signed.doc;
        if doc.expires <= super::now() {
            return Err(ended(doc));
        }
        let mine = self.me.as_ref().and_then(|me| doc.member_of_key(me));
        let reach = match mine {
            Some(member) => format!("relay:{} or relay:*", member.name),
            None => "relay:*".to_string(),
        };
        let how = match &doc.policy {
            None => "each of them, as the net has no policy".to_string(),
            Some(policy) => format!("those that the {} rules of its policy let reach {reach}", policy.rules.len()),
        };
        let count = match doc.members.len() {
            1 => "1 member".to_string(),
            n => format!("{n} members"),
        };
        Ok(format!(
            "the members of the net {} (serial {}, {count}, {}): {how}, the document read again for each request",
            doc.name,
            doc.serial,
            held.path.display()
        ))
    }
}

/// The document held, or why the role has none to mint by.
fn held() -> Result<store::Held, String> {
    match store::place() {
        Ok(store::Place::Off) => return Err(format!("{}=no turns the net off, so no member mints here", store::ENV)),
        Err(why) => return Err(why),
        Ok(_) => {}
    }
    match store::held() {
        Ok(Some(held)) => Ok(held),
        Ok(None) => Err("this host holds no net: its owner makes one with podssh net init NAME, or this host takes \
                         one with podssh net take FILE"
            .into()),
        Err(why) => Err(format!("the net's document cannot be trusted: {why}")),
    }
}

/// The verdict of `doc`, at `now` (seconds since 1970), on the key `peer`
/// at the relay role of the member `me` (none: a role that is no member):
/// the member's words, or why it may not mint. A key that is no member
/// hears neither the net's name nor its members.
pub(crate) fn verdict(doc: &Doc, now: i64, me: Option<&PublicKey>, peer: &PublicKey) -> Result<String, String> {
    let Some(member) = doc.member_of_key(peer) else {
        let print = peer.fingerprint();
        return Err(format!(
            "the key {print} is not a member of the net that this relay holds (serial {})",
            doc.serial
        ));
    };
    if doc.expires <= now {
        return Err(ended(doc));
    }
    let mine = me.and_then(|me| doc.member_of_key(me)).map(|m| m.name.as_str());
    policy::check(doc, member, Want::Relay(mine))?;
    Ok(format!("the member {} of the net {} (serial {})", member.name, doc.name, doc.serial))
}

/// The words of a document that ended.
fn ended(doc: &Doc) -> String {
    let at = crate::pairs::utc(doc.expires * 1000);
    format!(
        "the net {}'s document (serial {}) that this relay holds ended at {at}; its owner renews it with podssh \
         net renew",
        doc.name, doc.serial
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const OWNER: &str = include_str!("testdata/owner.pub");

    /// The key of `seed`, as the members of [`doc_with`] hold them.
    fn key(seed: u8) -> PublicKey {
        PublicKey::parse(&format!("{seed:02x}").repeat(32)).unwrap()
    }

    /// The net home, serial 2, of lab (the relay's node), laptop and phone,
    /// with `policy`, if one; it ends at `expires`.
    fn doc_with(policy: Option<Value>, expires: i64) -> Doc {
        let first = Doc::new("home", OWNER.trim(), 1_793_577_600, expires).unwrap();
        let member =
            |name: &str, seed: u8| json!({"name": name, "key": format!("{seed:02x}").repeat(32), "roles": ["node"]});
        let members = json!([member("lab", 0x21), member("laptop", 0x31), member("phone", 0x41)]);
        let next = first.next_whole(1_793_577_700, expires, |whole| {
            whole.insert("members".into(), members);
            if let Some(policy) = policy {
                whole.insert("policy".into(), policy);
            }
        });
        next.unwrap()
    }

    const LATER: i64 = 4_102_444_800;
    const NOW: i64 = 1_793_577_800;

    #[test]
    fn each_member_mints_with_no_policy_and_a_stranger_hears_no_name() {
        let doc = doc_with(None, LATER);
        let at_lab = |peer: u8| verdict(&doc, NOW, Some(&key(0x21)), &key(peer));
        assert_eq!(at_lab(0x31).unwrap(), "the member laptop of the net home (serial 2)");
        assert!(at_lab(0x41).is_ok() && verdict(&doc, NOW, None, &key(0x41)).is_ok(), "a role that is no member");
        let stranger = at_lab(0x51).unwrap_err();
        assert_eq!(
            stranger,
            format!("the key {} is not a member of the net that this relay holds (serial 2)", key(0x51).fingerprint())
        );
        assert!(!stranger.contains("home"), "{stranger}");
    }

    #[test]
    fn the_policy_names_the_relay_by_its_node_or_by_relay_star() {
        let doc = doc_with(
            Some(json!({"rules": [
                {"from": ["laptop"], "to": ["relay:lab"]},
                {"from": ["phone"], "to": ["relay:*"]},
            ]})),
            LATER,
        );
        assert!(verdict(&doc, NOW, Some(&key(0x21)), &key(0x31)).is_ok(), "laptop at lab's relay");
        let refused = verdict(&doc, NOW, None, &key(0x31)).unwrap_err();
        assert_eq!(refused, "no rule of the net home's policy (serial 2) lets laptop reach relay:*");
        assert!(verdict(&doc, NOW, None, &key(0x41)).is_ok(), "phone at a relay that is no member");
        assert!(verdict(&doc, NOW, Some(&key(0x21)), &key(0x41)).is_ok(), "phone at lab's relay");
        // The relay's own node, which no rule lets mint.
        let lab = verdict(&doc, NOW, Some(&key(0x21)), &key(0x21)).unwrap_err();
        assert!(
            lab.starts_with("no rule of the net home's policy") && lab.ends_with("lets lab reach relay:lab"),
            "{lab}"
        );
    }

    #[test]
    fn a_document_that_ended_lets_no_member_mint() {
        let doc = doc_with(None, NOW - 1);
        let why = verdict(&doc, NOW, None, &key(0x31)).unwrap_err();
        assert!(
            why.contains("(serial 2) that this relay holds ended at") && why.ends_with("podssh net renew"),
            "{why}"
        );
        assert!(verdict(&doc, NOW, None, &key(0x51)).unwrap_err().contains("is not a member"), "a stranger first");
    }
}
