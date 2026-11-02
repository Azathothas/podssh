//! The net at a node (T-429): who comes in, and the document that two ends
//! of the net give each other in the end-to-end channel.
//!
//! A node whose key is a member of the document held lets in each member of
//! it, read again for each session, so that a member removed by a newer
//! document is refused at its next session; the keys of `--allow` come in
//! beside them. A node that is no member keeps its door as before. A
//! document that ended lets nobody in by the net, as a node key that
//! expired leaves its tailnet: its owner signs a new one (`podssh net
//! renew`). The policy of T-430 narrows "each member" here.

use std::path::PathBuf;
use std::sync::Arc;

use podssh_relay::e2e::ends::Admit;
use podssh_relay::e2e::net::{self as channel_net, Docs, Held};
use podssh_relay::identity::PublicKey;
use podssh_relay::reverse::routes::Grant;

use super::store::{self, Taken};

/// What the net says of a peer at this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The peer is a member, and this node too, of a document in force.
    Member(String),
    /// This node is a member, and the net does not let the peer in: why.
    Refused(String),
    /// This node is in no net that it holds: the net says nothing.
    Outside,
}

/// The net's verdict on `peer` at the node `me`, now.
pub fn verdict(me: &PublicKey, peer: &PublicKey) -> Verdict {
    if !store::on() {
        return Verdict::Outside;
    }
    let held = match store::held() {
        Ok(Some(held)) => held,
        Ok(None) => return Verdict::Outside,
        // A document that is there and fails its check lets nobody in by the
        // net: a node that could not tell would let in a removed member.
        Err(why) => return Verdict::Refused(format!("the net's document cannot be trusted: {why}")),
    };
    let doc = &held.signed.doc;
    if doc.member_of_key(me).is_none() {
        return Verdict::Outside;
    }
    if doc.expires <= super::now() {
        let ended = crate::pairs::utc(doc.expires * 1000);
        return Verdict::Refused(format!(
            "the net {}'s document (serial {}) ended at {ended}; its owner renews it with podssh net renew",
            doc.name, doc.serial
        ));
    }
    match doc.member_of_key(peer) {
        Some(member) => Verdict::Member(member.name.clone()),
        None => Verdict::Refused(format!("it is not a member of the net {} (serial {})", doc.name, doc.serial)),
    }
}

/// Who may reach the node `me`: the members of its net, and the keys of
/// `allow`; with no net and no allowlist, each operator, as the relay's
/// connect token decided who reaches the node.
pub fn admit(allow: Option<PathBuf>, me: PublicKey) -> Arc<Admit> {
    install(true);
    let file = crate::channel::admit_of(allow.clone());
    Arc::new(move |peer: &PublicKey| match verdict(&me, peer) {
        Verdict::Member(_) => Ok(()),
        Verdict::Outside => file(peer),
        Verdict::Refused(why) if allow.is_some() => file(peer).map_err(|also| format!("{why}, and {also}")),
        Verdict::Refused(why) => Err(why),
    })
}

/// Which routes each operator may use at the node `me`: each route for a
/// member, until the policy of T-430 says less; else those of `allow`.
pub fn grant(allow: Option<PathBuf>, me: Option<PublicKey>) -> Arc<Grant> {
    let file = crate::channel::grant_of(allow.clone());
    let Some(me) = me else { return file };
    Arc::new(move |peer: &PublicKey, route: &str| match verdict(&me, peer) {
        Verdict::Member(_) => Ok(()),
        Verdict::Outside => file(peer, route),
        Verdict::Refused(why) if allow.is_some() => file(peer, route).map_err(|also| format!("{why}, and {also}")),
        Verdict::Refused(why) => Err(why),
    })
}

/// Whether the net lets `peer` in at the node `me`: the iroh road's door,
/// which has its own allowlist.
pub fn lets_in(me: &PublicKey, peer: &PublicKey) -> bool {
    matches!(verdict(me, peer), Verdict::Member(_))
}

/// The node's line of its net as it starts, when it is a member of one.
pub fn line(me: &PublicKey) -> Option<String> {
    if !store::on() {
        return None;
    }
    let held = match store::held() {
        Ok(held) => held?,
        Err(why) => return Some(format!("the net's document cannot be trusted, so it lets nobody in: {why}")),
    };
    let doc = &held.signed.doc;
    let mine = doc.member_of_key(me)?;
    let others = doc.members.len().saturating_sub(1);
    let until = crate::pairs::utc(doc.expires * 1000);
    Some(format!(
        "a member of the net {} as {} (serial {}, until {until}): its {others} other members may come in, read again \
         for each session",
        doc.name, mine.name, doc.serial
    ))
}

/// The net's documents of this process, for the end-to-end channel: the
/// first call wins. A node says what it takes; a client takes in silence,
/// as `podssh net ls` shows the serial.
pub fn install(say_lines: bool) {
    if store::on() {
        channel_net::install(Arc::new(Net { say_lines }));
    }
}

/// The document of this host, as the channel carries it.
struct Net {
    say_lines: bool,
}

impl Net {
    fn say(&self, line: String) {
        if self.say_lines {
            podssh_ssh::err_line!("podssh: the net: {line}");
        }
    }
}

impl Docs for Net {
    fn held(&self) -> Option<(Held, Vec<u8>)> {
        let held = store::held_or_none()?;
        let signed = &held.signed;
        Some((Held { owner: signed.owner_id(), serial: signed.doc.serial }, signed.to_bytes()))
    }

    fn shares_with(&self, peer: &PublicKey) -> bool {
        store::held_or_none().is_some_and(|held| held.signed.doc.member_of_key(peer).is_some())
    }

    fn take(&self, from: &PublicKey, bytes: &[u8]) -> Result<(), String> {
        // A document of the channel never starts a net here: the first one
        // is the user's to take.
        if store::held_or_none().is_none() {
            return Err("no net is held here".into());
        }
        let signed = match super::sign::verify_signed(bytes) {
            Ok(signed) => signed,
            Err(why) => {
                self.say(format!("refused a document from {from}: {why}"));
                return Err(why);
            }
        };
        match store::take(&signed, None, super::now()) {
            Ok(Taken::Kept { path, before }) => {
                let before = before.map(|serial| format!(", in place of serial {serial}")).unwrap_or_default();
                let doc = &signed.doc;
                self.say(format!("{}'s serial {} from {from}{before}, in {}", doc.name, doc.serial, path.display()));
                Ok(())
            }
            Ok(Taken::Same) => Ok(()),
            Err(why) => {
                self.say(format!("refused a document from {from}: {why}"));
                Err(why.to_string())
            }
        }
    }
}
