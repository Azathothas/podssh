//! The net at a node (T-429): who comes in, and the document that two ends
//! of the net give each other in the end-to-end channel.
//!
//! A node whose key is a member of the document held lets in each member of
//! it, read again for each session, so that a member removed by a newer
//! document is refused at its next session; the keys of `--allow` come in
//! beside them. A node that is no member keeps its door as before. A
//! document that ended lets nobody in by the net, as a node key that
//! expired leaves its tailnet: its owner signs a new one (`podssh net
//! renew`). The net's policy (T-430, `super::policy`) narrows "each member"
//! to what its rules let each reach: this node, with no route or with the
//! route that the operator named. An exit (T-431) lets a member out only
//! where the owner gave this node the role `exit`, and the policy lets it
//! reach the node's egress, for a public address, or the address's range.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use podssh_relay::e2e::ends::Admit;
use podssh_relay::e2e::net::{self as channel_net, Docs, Held};
use podssh_relay::e2e::Ask;
use podssh_relay::identity::PublicKey;
use podssh_relay::reverse::routes::Grant;

use super::policy::{self, Want};
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

/// What a peer asks of this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asks<'a> {
    /// Its target with no route, or a route, as the channel names it.
    Target(Option<&'a str>),
    /// Anything of it: the door of a road before the channel, which knows no
    /// route yet.
    Any,
    /// Its egress, or a range: an exit's door, before the name of the
    /// target resolves (T-431).
    Egress,
    /// One address that the exit would dial: a public one is its egress,
    /// another one an address of a range (T-431, T-432).
    Dial { addr: IpAddr, public: bool },
}

impl<'a> Asks<'a> {
    /// What the channel's ask asks of this node.
    pub fn of(ask: &'a Ask) -> Asks<'a> {
        match ask {
            Ask::Target => Asks::Target(None),
            Ask::Route(name) => Asks::Target(Some(name.as_str())),
            Ask::Exit { .. } => Asks::Egress,
        }
    }
}

/// The net's verdict on `peer` at the node `me`, now, for what it asks.
pub fn verdict(me: &PublicKey, peer: &PublicKey, asks: Asks<'_>) -> Verdict {
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
    let Some(mine) = doc.member_of_key(me) else { return Verdict::Outside };
    if doc.expires <= super::now() {
        let ended = crate::pairs::utc(doc.expires * 1000);
        return Verdict::Refused(format!(
            "the net {}'s document (serial {}) ended at {ended}; its owner renews it with podssh net renew",
            doc.name, doc.serial
        ));
    }
    let Some(member) = doc.member_of_key(peer) else {
        return Verdict::Refused(format!("it is not a member of the net {} (serial {})", doc.name, doc.serial));
    };
    let want = match asks {
        Asks::Target(route) => Want::Node { node: &mine.name, route },
        Asks::Any => Want::AnyOf(&mine.name),
        Asks::Egress => Want::Egress(&mine.name),
        Asks::Dial { public: true, .. } => Want::Exit(&mine.name),
        Asks::Dial { addr, public: false } => Want::Addr(addr),
    };
    // An exit lends this host's egress only with the owner's word for it.
    if matches!(asks, Asks::Egress | Asks::Dial { .. }) && !mine.has_role("exit") {
        return Verdict::Refused(no_role(doc, &mine.name));
    }
    match policy::check(doc, member, want) {
        Ok(_) => Verdict::Member(member.name.clone()),
        Err(why) => Verdict::Refused(why),
    }
}

/// Who may reach the node `me`, with the route that it names: the members
/// of its net that the policy lets, and the keys of `allow`, which the
/// policy does not narrow; with no net and no allowlist, each operator, as
/// the relay's connect token decided who reaches the node.
pub fn admit(allow: Option<PathBuf>, me: PublicKey) -> Arc<Admit> {
    install(true);
    let file = crate::channel::admit_of(allow.clone());
    Arc::new(move |peer: &PublicKey, ask: &Ask| match verdict(&me, peer, Asks::of(ask)) {
        Verdict::Member(_) => Ok(()),
        Verdict::Outside => file(peer, ask),
        Verdict::Refused(why) if allow.is_some() => file(peer, ask).map_err(|also| format!("{why}, and {also}")),
        Verdict::Refused(why) => Err(why),
    })
}

/// The words of a node that the owner gave no role `exit`.
fn no_role(doc: &super::doc::Doc, name: &str) -> String {
    format!(
        "the net {}'s document (serial {}) gives {name} no role exit, so its exit lets nobody out; its owner adds \
         it with podssh net add {name} KEY --roles node,exit",
        doc.name, doc.serial
    )
}

/// Whether the node `me` may lend its egress as it starts (T-431): a member
/// of a net in force with the role `exit`, its line; else why not.
pub fn exit_ready(me: &PublicKey) -> Result<String, String> {
    let held = match store::on().then(store::held) {
        Some(Ok(Some(held))) => held,
        Some(Err(why)) => return Err(format!("the net's document cannot be trusted: {why}")),
        _ => return Err("this node holds no net: an exit lends its egress to the members of its net alone".into()),
    };
    let doc = &held.signed.doc;
    let Some(mine) = doc.member_of_key(me) else {
        return Err(format!("this node's key {me} is no member of the net {}: its owner adds it first", doc.name));
    };
    if doc.expires <= super::now() {
        return Err(format!("the net {}'s document (serial {}) ended; its owner renews it", doc.name, doc.serial));
    }
    if !mine.has_role("exit") {
        return Err(no_role(doc, &mine.name));
    }
    let who = match &doc.policy {
        None => "each member, as the net has no policy".to_string(),
        Some(policy) => format!("the members that the {} rules of its policy let", policy.rules.len()),
    };
    Ok(format!("an exit of the net {} as {}: it lets out {who}, to public addresses", doc.name, mine.name))
}

/// Which routes each operator may use at the node `me`: those that the
/// policy lets a member use; else those of `allow`.
pub fn grant(allow: Option<PathBuf>, me: Option<PublicKey>) -> Arc<Grant> {
    let file = crate::channel::grant_of(allow.clone());
    let Some(me) = me else { return file };
    Arc::new(move |peer: &PublicKey, route: &str| match verdict(&me, peer, Asks::Target(Some(route))) {
        Verdict::Member(_) => Ok(()),
        Verdict::Outside => file(peer, route),
        Verdict::Refused(why) if allow.is_some() => file(peer, route).map_err(|also| format!("{why}, and {also}")),
        Verdict::Refused(why) => Err(why),
    })
}

/// Whether the net lets `peer` in at the node `me`: the iroh road's door,
/// which has its own allowlist, and which knows no route yet.
pub fn lets_in(me: &PublicKey, peer: &PublicKey) -> bool {
    matches!(verdict(me, peer, Asks::Any), Verdict::Member(_))
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
    let door = match &doc.policy {
        None => format!("its {others} other members may come in"),
        Some(policy) => {
            let rules = policy.rules.len();
            format!("its {others} other members may come in as the {rules} rules of its policy let")
        }
    };
    Some(format!(
        "a member of the net {} as {} (serial {}, until {until}): {door}, read again for each session",
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
