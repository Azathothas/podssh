//! `podssh net join` (T-616), on a new device: the code that `podssh net
//! invite NAME` shows on the owner's host, typed at a prompt or given on
//! one line of a pipe, never in argv; the owner's offer, whose owner this
//! device checks before it keeps anything; its key, made or read, as the
//! answer; then the document that the owner signed, taken as `podssh net
//! take` takes one.
//!
//! The owner is checked by `--owner KEY` when given, else by the net that
//! this host holds already, else by the person at the terminal, who sees
//! the owner key's fingerprint, made here from the key, and says yes. A run
//! that can ask nobody and names no owner is refused before the code is
//! read: a code from a stranger would make this host a member of the
//! stranger's net, and a node of it would let the stranger's members in.

use std::io::{BufRead, IsTerminal, Read, Write};

use podssh_relay::code::exchange::NET_INVITE;
use podssh_relay::code::run::{self, Reply, Waits};
use podssh_relay::code::Failed;
use podssh_relay::identity::{file, KeyName};
use podssh_relay::session::OsEntropy;

use super::invitation::{self, Answer, Got, Offer, Reading};
use super::store::{self, Held, Taken};
use super::{now, owner_named, sign, NetArgs};
use crate::exitmap::sysexits;
use crate::relay_cmd::block_on;
use crate::relay_settings::Refusal;

/// The longest answer to the question read.
const ANSWER_MOST: u64 = 64;

/// `join`: this device, into the net whose owner's host shows the code.
pub(super) fn run(args: &NetArgs, out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, Refusal> {
    let named = args.owner.as_deref().map(owner_named).transpose()?;
    let held = store::held().map_err(|why| Refusal { message: why, code: sysexits::EX_DATAERR })?;
    let asks = std::io::stdin().is_terminal();
    if named.is_none() && held.is_none() && !asks {
        return Err(Refusal::usage(
            "podssh net join reads its code from a pipe, where no question can show the net's owner: --owner KEY \
             names it, its fingerprint SHA256:... or its public key, as the owner's podssh net ls shows it",
        ));
    }
    let ends = invitation::ends(args.pair_mailbox.as_deref())?;
    let code = crate::relay_code::read_code(err, "podssh net: the code that the owner's host shows: ")?;
    crate::pins::apply(None)?;
    crate::pairs::online()?;
    let mut joining = None;
    let mut reply = |bytes: &[u8]| -> Result<Reply, Failed> {
        let offer = Offer::from_bytes(bytes).map_err(Failed::Peer)?;
        let roles = offer.roles.join(",");
        podssh_ssh::err_line!(
            "podssh net: the net {} of the owner {} names this device {}, with the roles {} (serial {})",
            offer.net,
            offer.fingerprint(),
            offer.member,
            roles,
            offer.serial
        );
        // Before anything is kept: the owner, then the key.
        if let Err((here, there)) = owner_checked(&offer, named.as_ref(), held.as_ref(), asks) {
            return Ok(refusal(here, there));
        }
        let key = match device_key(args.key.as_deref(), &offer.member) {
            Ok(key) => key,
            Err(why) => return Ok(refusal(why, "the device could not read or make its key".into())),
        };
        let answer = Answer::Key(key.identity.public()).to_bytes();
        joining = Some((offer, key));
        Ok(Reply::Answer(answer))
    };
    let mut reading = Reading::default();
    let mut last = |word: &[u8]| reading.read(word);
    let waits = Waits::default();
    let got = block_on(run::take_with(&ends, &waits, NET_INVITE, &code, &mut reply, &mut last))?;
    drop(code);
    let (got, _) = got.map_err(|failed| invitation::refused(failed, "ask the owner's host for a new code"))?;
    let Some((offer, key)) = joining else { return Err(Refusal::config("the exchange ended with no offer")) };
    let said = match got {
        Got::NotAdmitted(said) => {
            let message = format!("the owner's host added no member: {said}; this host keeps nothing of the net");
            return Err(Refusal { message, code: sysexits::EX_NOPERM });
        }
        Got::Signed { said, bytes } => {
            keep(&offer, &key, &bytes, err)?;
            said
        }
    };
    let me = key.identity.public();
    let place = key.path.as_ref().map(|path| path.display().to_string()).unwrap_or_default();
    let _ = writeln!(err, "podssh net: the owner's host says: {said}");
    let name = &offer.member;
    let _ = writeln!(
        err,
        "podssh net: this device is {name} in the net {}, its key {me} in {place}: podssh node {name} serves with \
         it, and --client-key {place} reaches the other members as {name}",
        offer.net
    );
    let _ = writeln!(out, "{}: joined the net {} of the owner {}", offer.member, offer.net, offer.fingerprint());
    Ok(0)
}

/// The refusal of this device: its line `here`, and the words `there` for
/// the owner's host, which name no path of this host.
fn refusal(here: String, there: String) -> Reply {
    Reply::Refused(Answer::Refused(there).to_bytes(), Failed::Mine(format!("{here}; nothing is kept")))
}

/// Whether this device takes the net of the offer's owner: the one that
/// `--owner` names, else the owner of the net held here, else the person's
/// yes; this host's line and the owner's words, when it does not.
fn owner_checked(
    offer: &Offer,
    named: Option<&KeyName>,
    held: Option<&Held>,
    asks: bool,
) -> Result<(), (String, String)> {
    let print = offer.fingerprint();
    if let Some(named) = named {
        if named.fingerprint() != print {
            let here = format!("the net's owner is {print}, not {named}, which --owner names");
            return Err((here, "the device expects another owner".into()));
        }
    }
    if let Some(held) = held {
        let mine = sign::owner_fingerprint(&held.signed.doc.owner);
        if mine != print {
            let here = format!(
                "this host holds the net {} of the owner {mine}, and a host keeps the net of one owner",
                held.signed.doc.name
            );
            return Err((here, "the device holds the net of another owner".into()));
        }
    }
    if named.is_some() || held.is_some() || !asks {
        return Ok(());
    }
    ask(offer)
}

/// The person's word at the terminal of stdin, the owner's fingerprint
/// before them: `yes` alone joins.
fn ask(offer: &Offer) -> Result<(), (String, String)> {
    let prompt = format!(
        "podssh net: join the net {} of the owner {}? The owner's host shows that fingerprint in its podssh net ls. \
         yes or no: ",
        offer.net,
        offer.fingerprint()
    );
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(prompt.as_bytes()).and_then(|()| stderr.flush());
    let mut line = String::new();
    let read = std::io::stdin().lock().take(ANSWER_MOST).read_line(&mut line);
    match read.map(|_| line.trim().to_ascii_lowercase()) {
        Ok(word) if word == "yes" || word == "y" => Ok(()),
        _ => Err(("not joined: the answer was not yes".into(), "the device's user did not confirm the owner".into())),
    }
}

/// This device's key for the member `name`: `--key FILE`, else the key of
/// `podssh node NAME` in the cache, made when missing.
fn device_key(named: Option<&str>, name: &str) -> Result<file::Key, String> {
    let place = match named {
        Some(path) => file::Place::File(path.into()),
        None => file::node_place(name),
    };
    file::load(&place, &mut OsEntropy).map_err(|why| format!("this device's key: {why}"))
}

/// The signed document, checked against the offer and this device's key,
/// then taken by the rule of `podssh net take`, its first owner the one
/// that the offer named and this device checked.
fn keep(offer: &Offer, key: &file::Key, bytes: &[u8], err: &mut dyn Write) -> Result<(), Refusal> {
    let signed = sign::verify_signed(bytes).map_err(data)?;
    let doc = &signed.doc;
    if sign::owner_fingerprint(&doc.owner) != offer.fingerprint() || doc.name != offer.net {
        return Err(data(format!("it is not of the net {} of the owner that the offer named", offer.net)));
    }
    let me = key.identity.public();
    if !doc.member(&offer.member).is_some_and(|member| member.key.matches(&me)) {
        return Err(data(format!("it does not name this device's key {me} as {}", offer.member)));
    }
    let owner = KeyName::parse(&offer.fingerprint());
    match store::take(&signed, owner.as_ref(), now()) {
        Ok(Taken::Kept { path, before }) => {
            let before = before.map(|serial| format!(", in place of serial {serial}")).unwrap_or_default();
            let (name, serial, path) = (&doc.name, doc.serial, path.display());
            let _ = writeln!(err, "podssh net: took the net {name}, serial {serial}{before}, in {path}");
            Ok(())
        }
        Ok(Taken::Same) => {
            let _ = writeln!(err, "podssh net: this host holds the net {}'s serial {} already", doc.name, doc.serial);
            Ok(())
        }
        Err(why) => Err(data(why.to_string())),
    }
}

/// A document of the owner's host that this device refuses.
fn data(why: String) -> Refusal {
    Refusal { message: format!("the owner's document: {why}; this host keeps no net"), code: sysexits::EX_DATAERR }
}
