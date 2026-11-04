//! `podssh net invite NAME` (T-616), on the owner's host: a short code for
//! one new device, by the exchange of T-086 (`podssh_relay::code::run`, the
//! kind `NET_INVITE`). The offer is the net's name, its owner's key, NAME
//! and its roles; the device's answer is its key, which this host signs into
//! the net as the member NAME, keeps as `podssh net add NAME KEY` keeps a
//! change, and then gives whole in the last words. The code shows on this
//! run's terminal alone, lives 10 minutes and is spent by its first
//! exchange, so that a wrong code, a guess or a success signs at most once.
//!
//! The owner's key is found, and its passphrase asked, before the code is
//! made, never while a device waits. A name that is a member already goes
//! to that member's own key alone, with the document held: the way back
//! after a last word lost, which never hands a member's name to a new key.

use std::io::Write;
use std::path::{Path, PathBuf};

use podssh_relay::code::exchange::NET_INVITE;
use podssh_relay::code::run::{self, Waits};
use podssh_relay::code::{self, Code, Failed};
use podssh_relay::identity::{KeyName, PublicKey};

use super::doc::{self, Doc, Member};
use super::invitation::{self, Answer, Offer};
use super::sign::{self, Signed};
use super::{edit, held, now, store, NetArgs};
use crate::exitmap::sysexits::{self, EX_CONFIG};
use crate::keygen_sign::Signing;
use crate::relay_cmd::block_on;
use crate::relay_code::Terminal;
use crate::relay_settings::Refusal;

/// What this host did with the device's key.
enum Admitted {
    /// A new serial that names it, kept here in this file.
    Signed(Box<Signed>, PathBuf),
    /// The document held, which names it already as NAME.
    Held(Box<Signed>),
    /// Nothing: the words for the device, this host's line, and the exit.
    Not { said: String, here: String, code: i32 },
}

/// `invite NAME`: one device, by one code.
pub(super) fn run(args: &NetArgs, out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, Refusal> {
    let name = args.args[0].as_str();
    doc::check_name(name).map_err(|why| Refusal::usage(format!("the member's name {why}")))?;
    let roles = args.roles.as_deref().map(doc::parse_roles).transpose().map_err(Refusal::usage)?;
    let days = edit::days(args.days.as_deref())?;
    let ends = invitation::ends(args.pair_mailbox.as_deref())?;
    let held = held()?;
    let doc = &held.signed.doc;
    let roles = match (doc.member(name), roles) {
        (Some(_), Some(_)) => {
            return Err(Refusal::usage(format!(
                "{name} is a member of the net {} already: by a code its own key alone gets the document held; its \
                 roles change with podssh net add {name} KEY --roles",
                doc.name
            )));
        }
        (Some(member), None) => member.roles.clone(),
        (None, roles) => roles.unwrap_or_else(|| vec!["node".to_string()]),
    };
    // Before the owner's key is asked or anything is signed: a run with no
    // terminal could show the code nowhere.
    let Some(mut terminal) = Terminal::open() else {
        return Err(Refusal::usage(
            "podssh net invite shows the code on this run's terminal alone, and it has none: run it at a terminal, \
             or add the device's key with podssh net add NAME KEY",
        ));
    };
    // The passphrase now, not while the device waits a step for the answer.
    let signing = sign::signing_for(&doc.owner, args.owner_key.as_deref().map(Path::new)).map_err(Refusal::config)?;
    crate::pins::apply(None)?;
    crate::pairs::online()?;
    let offer = Offer {
        net: doc.name.clone(),
        owner: doc.owner.clone(),
        member: name.to_string(),
        roles: roles.clone(),
        serial: doc.serial,
    };
    let (net, print, minutes) = (doc.name.clone(), offer.fingerprint(), code::LIFETIME.as_secs() / 60);
    let mut show = |made: &Code, mailbox: &str| {
        terminal.line(&format!(
            "podssh net: the code for {name} to join the net {net} of the owner {print}, for one device, valid for \
             {minutes} minutes: {}",
            made.for_terminal()
        ));
        terminal.line(&format!(
            "podssh net: on the new device, podssh net join, then type it (they meet at {mailbox})"
        ));
    };
    let (mut refused, mut admitted) = (None, None);
    let mut answer = |bytes: &[u8]| -> Result<Vec<Vec<u8>>, Failed> {
        match Answer::from_bytes(bytes).map_err(Failed::Peer)? {
            Answer::Refused(why) => {
                refused = Some(why.clone());
                Err(Failed::Peer(format!("the device refused to join: {why}")))
            }
            Answer::Key(key) => {
                let done = admit(name, &roles, &key, days, &signing);
                let words = match &done {
                    Admitted::Signed(signed, _) => {
                        let said = format!("added as {name}, serial {}", signed.doc.serial);
                        invitation::last_words(true, &said, Some(signed.to_bytes().as_slice()))
                    }
                    Admitted::Held(signed) => {
                        let said = format!("{name} has this key already, serial {}", signed.doc.serial);
                        invitation::last_words(true, &said, Some(signed.to_bytes().as_slice()))
                    }
                    Admitted::Not { said, .. } => invitation::last_words(false, said, None),
                };
                admitted = Some((key, done));
                Ok(words)
            }
        }
    };
    let (waits, offered) = (Waits::default(), offer.to_bytes());
    let ran = block_on(run::give_with(&ends, &waits, NET_INVITE, &offered, &mut show, &mut answer))?;
    let way = "podssh net invite NAME makes a new code";
    if let Some(why) = refused {
        let message = format!("the device refused to join, and nothing is signed: {why}; {way}");
        return Err(Refusal { message, code: sysexits::EX_NOPERM });
    }
    let (key, done) = match (admitted, ran) {
        (Some((key, done)), Ok(_)) => (key, done),
        // Kept before it was sent: the member is in, and the device may
        // hold nothing.
        (Some((key, Admitted::Signed(signed, path))), Err(failed)) => {
            let lost = invitation::refused(failed, way);
            let message = format!(
                "added the member {name} with the key {key}, serial {}, in {}, but the device may not have its \
                 document: {}; podssh net invite {name} again gives that key the document held",
                signed.doc.serial,
                path.display(),
                lost.message
            );
            return Err(Refusal { message, code: lost.code });
        }
        (_, Err(failed)) => return Err(invitation::refused(failed, way)),
        (None, Ok(_)) => return Err(Refusal::config("the exchange ended with no answer")),
    };
    match done {
        Admitted::Signed(signed, path) => {
            let until = crate::pairs::utc(signed.doc.expires * 1000);
            let _ = writeln!(
                err,
                "podssh net: added the member {name} with the key {key}: the net {net}, serial {}, until {until}, in \
                 {}; the device holds it",
                signed.doc.serial,
                path.display()
            );
            let _ = writeln!(out, "{name}: joined the net {net} with the key {key}, serial {}", signed.doc.serial);
            Ok(0)
        }
        Admitted::Held(signed) => {
            let serial = signed.doc.serial;
            let _ = writeln!(err, "podssh net: {name} has the key {key} already; the device holds serial {serial}");
            let _ = writeln!(out, "{name}: joined the net {net} with the key {key}, serial {serial}");
            Ok(0)
        }
        Admitted::Not { here, code, .. } => Err(Refusal { message: format!("{here}; nothing is signed"), code }),
    }
}

/// What this host does with the device's `key` for the member `name`: the
/// document held, read again, with the member added and signed; or the held
/// one as it is, for the member's own key; or why not. No path of this host
/// goes into the words for the device.
fn admit(name: &str, roles: &[String], key: &PublicKey, days: i64, signing: &Signing) -> Admitted {
    let not = |said: &str, here: String, code: i32| Admitted::Not { said: said.to_string(), here, code };
    // Read again: another change may have come during the code's life.
    let held = match store::held() {
        Ok(Some(held)) => held,
        Ok(None) => return not("the owner's host holds no net now", "this host holds no net now".into(), EX_CONFIG),
        Err(why) => return not("the owner's host cannot read its net", why, sysexits::EX_DATAERR),
    };
    let doc = &held.signed.doc;
    // A name never goes to a new key by a code: a guess of one would be the
    // member that the others reach by its name.
    match doc.member(name) {
        Some(member) if member.key.matches(key) => return Admitted::Held(Box::new(held.signed.clone())),
        Some(member) => {
            let here = format!("{name} is a member of the net {} with the key {}, not {key}", doc.name, member.key);
            let said = format!("{name} is a member of the net already, with another key");
            return not(&said, here, sysexits::EX_NOPERM);
        }
        None => {}
    }
    if let Some(other) = doc.member_of_key(key) {
        let said = format!("this key is the member {} of the net already", other.name);
        return not(&said, format!("the key {key} is the member {} already", other.name), sysexits::EX_NOPERM);
    }
    let member =
        Member { name: name.to_string(), key: KeyName::Key(*key), roles: roles.to_vec(), tickets: Default::default() };
    let issued = now();
    let next = match edit::with_member(doc, &member, issued, issued + days * 86_400) {
        Ok((next, _)) => next,
        Err(refusal) => return not("the owner's host could not add the key", refusal.message, refusal.code),
    };
    let signed = match signed(&next, signing) {
        Ok(signed) => signed,
        Err(why) => return not("the owner's host could not sign the document", why, EX_CONFIG),
    };
    match store::keep_own(&signed) {
        Ok(path) => Admitted::Signed(Box::new(signed), path),
        Err(why) => not("the owner's host could not keep the document", why, sysexits::EX_CANTCREAT),
    }
}

/// `next`, signed on a thread of its own: the agent's signature runs a
/// runtime, which cannot start inside the exchange's.
fn signed(next: &Doc, signing: &Signing) -> Result<Signed, String> {
    let joined = std::thread::scope(|scope| scope.spawn(|| sign::sign_with(next, signing)).join());
    joined.unwrap_or_else(|_| Err("the signature's thread failed".to_string()))
}
