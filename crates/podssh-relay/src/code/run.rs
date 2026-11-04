//! The two runs of a pairing by code (T-086). The giver allocates a
//! nameplate at the first mailbox that answers, makes the code, and waits
//! for one taker within the code's life. The taker looks for its giver at
//! each mailbox in order: one that lists the code's nameplate has it, one
//! that lists others does not, and at one that lists none the giver's
//! `pake`, which the mailbox keeps, comes at once or not at all. Each end
//! makes the key, checks the other's version, and moves its part. The giver
//! leaves after one exchange, whatever its end, so that a wrong code, a
//! guess or a success spends the code.

use std::time::Duration;

use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use serde_json::Value;

use super::exchange::{self, Answer, Done, Offer};
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
    let (mut hole, code) = opened(ends, exchange::versions()).await?;
    show(&code, hole.shown());
    drop(code);
    let mailbox = hole.shown().to_string();
    if !hole.agree(waits.life).await? {
        hole.close(Mood::Lonely).await;
        return Err(Failed::Expired(waits.life));
    }
    let theirs = hole.confirm(waits.step).await?;
    if let Err(why) = exchange::ours(&theirs) {
        return Err(hole.fail(Mood::Errory, Failed::Peer(why)).await);
    }
    let sent = hole.send(&offer.to_bytes()).await;
    or_close(&mut hole, sent).await?;
    let answer = hole.receive(waits.step).await?;
    let answer = match Answer::from_bytes(&answer) {
        Ok(answer) => answer,
        Err(why) => return Err(hole.fail(Mood::Errory, Failed::Peer(why)).await),
    };
    let done = admit(&answer.operator);
    let sent = hole.send(&done.to_bytes()).await;
    or_close(&mut hole, sent).await?;
    hole.close(Mood::Happy).await;
    Ok(Given { operator: answer.operator, done, mailbox })
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
    let mut hole = joined(ends, code, exchange::versions(), waits).await?;
    let mailbox = hole.shown().to_string();
    let theirs = hole.confirm(waits.step).await?;
    if let Err(why) = exchange::ours(&theirs) {
        return Err(hole.fail(Mood::Errory, Failed::Peer(why)).await);
    }
    let offer = hole.receive(waits.step).await?;
    let offer = match Offer::from_bytes(&offer, now_ms()) {
        Ok(offer) => offer,
        Err(why) => return Err(hole.fail(Mood::Errory, Failed::Peer(why)).await),
    };
    if let Err(why) = check(&offer) {
        return Err(hole.fail(Mood::Errory, Failed::Mine(why)).await);
    }
    let sent = hole.send(&Answer { operator: *me }.to_bytes()).await;
    or_close(&mut hole, sent).await?;
    let done = hole.receive(waits.step).await?;
    let done = match Done::from_bytes(&done) {
        Ok(done) => done,
        Err(why) => return Err(hole.fail(Mood::Errory, Failed::Peer(why)).await),
    };
    hole.close(Mood::Happy).await;
    Ok(Taken { offer, done, mailbox })
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
