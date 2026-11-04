//! The two runs of a pairing by code (T-086). The giver allocates a
//! nameplate at the first mailbox that answers, makes the code, and waits
//! for one taker within the code's life. The taker looks for its giver at
//! each mailbox in order: one that lists the code's nameplate has it, one
//! that lists others does not, and at one that lists none the giver's
//! `pake`, which the mailbox keeps, comes at once or not at all. Each end
//! makes the key, checks the other's version, and moves its part. The giver
//! leaves after one exchange, whatever its end, so that a wrong code, a
//! guess or a success spends the code.
//!
//! The runs are one for each [`Kind`] of exchange: [`give_with`] and
//! [`take_with`] move an offer, an answer and the giver's last words, as
//! bytes, and the kind's own words are its caller's. The pairing's
//! ([`give`], [`take`]) is one; the net's invitation (T-616), whose words
//! the binary reads, another.

use std::time::Duration;

use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use serde_json::Value;

use super::exchange::{self, Answer, Done, Kind, Offer};
use super::mailbox::{crowded, Mailbox, Mood};
use super::wormhole::Wormhole;
use super::{hex, Code, Failed, Say, LIFETIME};
use crate::identity::PublicKey;
use crate::session::secret::{Entropy, OsEntropy};

/// Where the ends meet, and how they are reached.
pub struct Ends {
    /// The mailboxes, in order.
    pub mailboxes: Vec<WsUrl>,
    pub trust: Trust,
    pub proxy: ProxyChoice,
    pub say: Say,
}

/// The bounds of a run; a test shortens them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waits {
    /// The code's life at the giver.
    pub life: Duration,
    /// The taker's wait for its giver's `pake`, which the mailbox keeps.
    pub giver: Duration,
    /// Each step of the exchange once the key is made.
    pub step: Duration,
}

impl Default for Waits {
    fn default() -> Self {
        Waits { life: LIFETIME, giver: Duration::from_secs(20), step: Duration::from_secs(60) }
    }
}

/// What the giver's run gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Given {
    /// The taker's key.
    pub operator: PublicKey,
    /// What the giver did with it.
    pub done: Done,
    /// The mailbox where they met, as lines show it.
    pub mailbox: String,
}

/// What the taker's run gave.
pub struct Taken {
    pub offer: Offer,
    pub done: Done,
    pub mailbox: String,
}

/// The most last words that a taker reads after its answer: a mailbox holds
/// 32 messages of one code, and the net's document goes in a dozen parts.
pub const LAST_MOST: usize = 24;

/// What a taker says to the giver's offer.
pub enum Reply {
    /// Its answer; the giver's last words follow.
    Answer(Vec<u8>),
    /// Its refusal, said to the giver so that it ends at once rather than
    /// wait out a step; the run then ends with this failure.
    Refused(Vec<u8>, Failed),
}

/// The giver's run: a new code at the first mailbox that answers, given to
/// `show` with that mailbox, for a terminal alone; then one taker within
/// `waits.life`, which gets `offer` and answers with its key, which `admit`
/// takes. The code is spent at the first exchange, whatever its end.
pub async fn give(
    ends: &Ends,
    waits: &Waits,
    offer: &Offer,
    show: &mut (dyn FnMut(&Code, &str) + Send),
    admit: &mut (dyn FnMut(&PublicKey) -> Done + Send),
) -> Result<Given, Failed> {
    let offered = offer.to_bytes();
    let mut taken = None;
    let mut answer = |bytes: &[u8]| -> Result<Vec<Vec<u8>>, Failed> {
        let theirs = Answer::from_bytes(bytes).map_err(Failed::Peer)?;
        let done = admit(&theirs.operator);
        let last = done.to_bytes();
        taken = Some((theirs.operator, done));
        Ok(vec![last])
    };
    let mailbox = give_with(ends, waits, exchange::PAIR, &offered, show, &mut answer).await?;
    let Some((operator, done)) = taken else { return Err(Failed::Broken("the exchange ended with no answer".into())) };
    Ok(Given { operator, done, mailbox })
}

/// The taker's run: the giver of `code`, its offer, which `check` takes or
/// refuses before this end says a word of its own, then `me`, this end's
/// key, and the giver's last word.
pub async fn take(
    ends: &Ends,
    waits: &Waits,
    code: &Code,
    me: &PublicKey,
    check: &mut (dyn FnMut(&Offer) -> Result<(), String> + Send),
) -> Result<Taken, Failed> {
    let mut offered = None;
    let mut reply = |bytes: &[u8]| -> Result<Reply, Failed> {
        let offer = Offer::from_bytes(bytes, now_ms()).map_err(Failed::Peer)?;
        check(&offer).map_err(Failed::Mine)?;
        offered = Some(offer);
        Ok(Reply::Answer(Answer { operator: *me }.to_bytes()))
    };
    let mut last = |bytes: &[u8]| -> Result<Option<Done>, String> { Done::from_bytes(bytes).map(Some) };
    let (done, mailbox) = take_with(ends, waits, exchange::PAIR, code, &mut reply, &mut last).await?;
    let Some(offer) = offered else { return Err(Failed::Broken("the exchange ended with no offer".into())) };
    Ok(Taken { offer, done, mailbox })
}

/// The giver's run of an exchange of `kind`: a new code, given to `show`
/// with its mailbox, for a terminal alone; then one taker within
/// `waits.life`, whose version must be of `kind`, which gets `offer`. Its
/// answer goes to `answer`, which gives the last words, sent in order, or
/// the failure that ends the run. The code is spent at the first exchange,
/// whatever its end. The mailbox where they met, as lines show it.
pub async fn give_with(
    ends: &Ends,
    waits: &Waits,
    kind: Kind,
    offer: &[u8],
    show: &mut (dyn FnMut(&Code, &str) + Send),
    answer: &mut (dyn FnMut(&[u8]) -> Result<Vec<Vec<u8>>, Failed> + Send),
) -> Result<String, Failed> {
    let (mut hole, code) = opened(ends, kind.versions()).await?;
    show(&code, hole.shown());
    drop(code);
    let mailbox = hole.shown().to_string();
    if !hole.agree(waits.life).await? {
        hole.close(Mood::Lonely).await;
        return Err(Failed::Expired(waits.life));
    }
    let theirs = hole.confirm(waits.step).await?;
    if let Err(why) = kind.ours(&theirs) {
        return Err(hole.fail(Mood::Errory, Failed::Peer(why)).await);
    }
    let sent = hole.send(offer).await;
    or_close(&mut hole, sent).await?;
    let theirs = hole.receive(waits.step).await?;
    let words = match answer(&theirs) {
        Ok(words) => words,
        Err(failed) => return Err(hole.fail(Mood::Errory, failed).await),
    };
    for word in &words {
        let sent = hole.send(word).await;
        or_close(&mut hole, sent).await?;
    }
    hole.close(Mood::Happy).await;
    Ok(mailbox)
}

/// The taker's run of an exchange of `kind`: the giver of `code`, whose
/// version must be of `kind`; its offer, which `reply` answers or refuses
/// before this end says a word of its own; then the giver's last words, each
/// to `last`, until one gives what the run gave, at most [`LAST_MOST`]. That,
/// and the mailbox where they met.
pub async fn take_with<T>(
    ends: &Ends,
    waits: &Waits,
    kind: Kind,
    code: &Code,
    reply: &mut (dyn FnMut(&[u8]) -> Result<Reply, Failed> + Send),
    last: &mut (dyn FnMut(&[u8]) -> Result<Option<T>, String> + Send),
) -> Result<(T, String), Failed> {
    let mut hole = joined(ends, code, kind.versions(), waits).await?;
    let mailbox = hole.shown().to_string();
    let theirs = hole.confirm(waits.step).await?;
    if let Err(why) = kind.ours(&theirs) {
        return Err(hole.fail(Mood::Errory, Failed::Peer(why)).await);
    }
    let offer = hole.receive(waits.step).await?;
    let said = match reply(&offer) {
        Ok(Reply::Answer(said)) => said,
        Ok(Reply::Refused(said, failed)) => {
            // The refusal is a courtesy to the giver: unsent, it waits a step.
            let _ = hole.send(&said).await;
            return Err(hole.fail(Mood::Errory, failed).await);
        }
        Err(failed) => return Err(hole.fail(Mood::Errory, failed).await),
    };
    let sent = hole.send(&said).await;
    or_close(&mut hole, sent).await?;
    for _ in 0..LAST_MOST {
        let word = hole.receive(waits.step).await?;
        match last(&word) {
            Ok(Some(done)) => {
                hole.close(Mood::Happy).await;
                return Ok((done, mailbox));
            }
            Ok(None) => {}
            Err(why) => return Err(hole.fail(Mood::Errory, Failed::Peer(why)).await),
        }
    }
    let why = format!("the other end said more than {LAST_MOST} last words");
    Err(hole.fail(Mood::Errory, Failed::Peer(why)).await)
}

/// A new code at the first mailbox of `ends` that answers, and its
/// wormhole, this end's `pake` added: what a giver shows. `versions` goes in
/// its version phase.
pub async fn opened(ends: &Ends, versions: Value) -> Result<(Wormhole, Code), Failed> {
    let side = new_side()?;
    let mut missed = Vec::new();
    for url in &ends.mailboxes {
        let mut mailbox = match Mailbox::connect(url, &ends.trust, &ends.proxy, &side).await {
            Ok(mailbox) => mailbox,
            Err(why) => {
                (ends.say)(reason(&why));
                missed.push(reason(&why));
                continue;
            }
        };
        say_motd(ends, &mailbox);
        let claimed = match mailbox.allocate().await {
            Ok(nameplate) => mailbox.claim(&nameplate).await.map(|id| (nameplate, id)),
            Err(why) => Err(why),
        };
        let (nameplate, id) = match claimed {
            Ok(claimed) => claimed,
            Err(why) => {
                mailbox.end().await;
                (ends.say)(reason(&why));
                missed.push(reason(&why));
                continue;
            }
        };
        let code = Code::make(&nameplate, &mut OsEntropy).map_err(|_| Failed::NoRandom)?;
        let hole = Wormhole::open(mailbox, side, nameplate, id, &code, versions).await?;
        return Ok((hole, code));
    }
    Err(Failed::Unreachable(missed.join("; ")))
}

/// The wormhole of `code` at the mailbox where its giver waits, the key
/// made: each mailbox of `ends` in order, by its list of nameplates, and
/// where it lists none, by the giver's `pake` within `waits.giver`.
pub async fn joined(ends: &Ends, code: &Code, versions: Value, waits: &Waits) -> Result<Wormhole, Failed> {
    let side = new_side()?;
    let (mut missed, mut reached) = (Vec::new(), false);
    for url in &ends.mailboxes {
        let mut mailbox = match Mailbox::connect(url, &ends.trust, &ends.proxy, &side).await {
            Ok(mailbox) => mailbox,
            Err(why) => {
                (ends.say)(reason(&why));
                missed.push(reason(&why));
                continue;
            }
        };
        say_motd(ends, &mailbox);
        let listed = match mailbox.list().await {
            Ok(listed) => listed,
            Err(why) => {
                mailbox.end().await;
                (ends.say)(reason(&why));
                missed.push(reason(&why));
                continue;
            }
        };
        reached = true;
        // A mailbox that lists others has no giver of this code: claiming
        // the nameplate there would spend a stranger's code.
        if !listed.is_empty() && !listed.iter().any(|nameplate| nameplate == code.nameplate()) {
            mailbox.end().await;
            continue;
        }
        let id = match mailbox.claim(code.nameplate()).await {
            Ok(id) => id,
            Err(why) if crowded(&why) => {
                mailbox.end().await;
                let shown = &mailbox.shown;
                return Err(Failed::Refused(format!("two ends hold this code at {shown} already: it was taken")));
            }
            Err(why) => {
                mailbox.end().await;
                (ends.say)(reason(&why));
                missed.push(reason(&why));
                continue;
            }
        };
        let nameplate = code.nameplate().to_string();
        let mut hole = Wormhole::open(mailbox, side.clone(), nameplate, id, code, versions.clone()).await?;
        if hole.agree(waits.giver).await? {
            return Ok(hole);
        }
        hole.close(Mood::Lonely).await;
    }
    if reached {
        Err(Failed::Nobody)
    } else {
        Err(Failed::Unreachable(missed.join("; ")))
    }
}

/// `done`, or its failure after the wormhole closed with `errory`.
async fn or_close<T>(hole: &mut Wormhole, done: Result<T, Failed>) -> Result<T, Failed> {
    match done {
        Ok(value) => Ok(value),
        Err(failed) => Err(hole.fail(Mood::Errory, failed).await),
    }
}

/// A side for a run: 10 hex digits, as magic-wormhole's own.
fn new_side() -> Result<String, Failed> {
    let mut bytes = [0u8; 5];
    OsEntropy.fill(&mut bytes).map_err(|_| Failed::NoRandom)?;
    Ok(hex(&bytes))
}

/// The words of a failure at one mailbox, with no prefix of the whole run.
fn reason(failed: &Failed) -> String {
    match failed {
        Failed::Unreachable(why) => why.clone(),
        other => other.to_string(),
    }
}

fn say_motd(ends: &Ends, mailbox: &Mailbox) {
    if let Some(motd) = &mailbox.motd {
        (ends.say)(format!("the mailbox {} says: {motd}", mailbox.shown));
    }
}

fn now_ms() -> i64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_lives_10_minutes_and_a_taker_waits_less_for_a_giver_that_is_there() {
        let waits = Waits::default();
        assert_eq!(waits.life, Duration::from_secs(600));
        assert!(waits.giver < waits.life && waits.step < waits.life);
    }

    #[test]
    fn a_side_is_10_hex_digits_of_its_own() {
        let (one, two) = (new_side().unwrap(), new_side().unwrap());
        assert!(one.len() == 10 && one.bytes().all(|b| b.is_ascii_hexdigit()), "{one}");
        assert_ne!(one, two);
    }

    #[test]
    fn a_failure_at_one_mailbox_is_said_with_no_prefix_of_the_run() {
        assert_eq!(reason(&Failed::Unreachable("wss://m/v1: refused".into())), "wss://m/v1: refused");
        assert_eq!(reason(&Failed::Broken("x".into())), "x");
    }
}
