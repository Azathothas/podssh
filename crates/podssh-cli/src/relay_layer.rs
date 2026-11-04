//! `podssh proxy HOST PORT` in the resumable layer at podssh's relay role
//! (T-173), where the user asks for it (`PODSSH_RELAY_LAYER=yes`) and the
//! first relay host offers it in its `/relays.json`: the role holds the
//! connection to HOST while this client's link to it is lost, and a new link
//! to the same host resumes the session, so that an OpenSSH session through
//! it outlives a drop of the client's network. Each other case takes the
//! contract's `/connect/` as before. `podssh ssh` takes it the same way
//! (`ssh`).
//!
//! Each link of a session goes to the process that holds it: the host whose
//! offer was read, or the name of its own that the process gave there,
//! where several share one name. A role with no room for a new session
//! refuses it in its first link's handshake, before any byte of it went:
//! the session takes the contract's road then, with one line.
//!
//! OpenSSH ends its ProxyCommand with SIGHUP as it exits: taken, the signal
//! is the end of the session's bytes, and the layer's `CLOSE` makes the role
//! forget the session and shut its target at once (T-586), not after the
//! layer's deadline.

pub(crate) mod ssh;

use std::io::Write;
use std::time::Duration;

use podssh_relay::forward_layer::{self, offer, Dialer, Missed};
use podssh_relay::relay::RelayList;
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::resume::Note;
use podssh_relay::session::{Ask, OsEntropy};
use podssh_ws::{ProxyChoice, Trust};

use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::layered::Line;
use crate::relay_settings::Refusal;

/// `yes`: ask for the layer where the first relay host offers it.
pub const ENV: &str = "PODSSH_RELAY_LAYER";
/// How long each step of the read of the host's offer may take.
const OFFER_WAIT: Duration = Duration::from_secs(10);
/// What follows when the layer is not there: the contract's road.
const WITHOUT: &str = "the session goes on with no resume";

/// Whether the user asked for the layer: `yes`; unset, empty or `no` is no,
/// and another word is a configuration error (78), which does not echo it.
pub fn asked(value: Option<&str>) -> Result<bool, Refusal> {
    match value.map(str::trim) {
        None | Some("") => Ok(false),
        Some(word) if word.eq_ignore_ascii_case("no") => Ok(false),
        Some(word) if word.eq_ignore_ascii_case("yes") => Ok(true),
        Some(_) => Err(Refusal::config(format!("{ENV}: yes or no"))),
    }
}

/// [`asked`], of this process's environment.
pub(crate) fn asked_here() -> Result<bool, Refusal> {
    asked(std::env::var(ENV).ok().as_deref())
}

/// The relay host as a user names it.
fn shown(relay: &podssh_relay::relay::Relay) -> String {
    if relay.port == 443 {
        relay.host.clone()
    } else {
        podssh_ws::dial::authority(&relay.host, relay.port)
    }
}

/// The links of a session to `host:port` in the layer, where the first host
/// of `relays` offers it: to the process that its offer names, else to that
/// host; with the host as shown. `None` for the contract's road, whose line
/// went to `say`.
pub(crate) async fn chosen(
    relays: &RelayList,
    trust: &Trust,
    (host, port): (&str, u16),
    say: &mut dyn FnMut(String),
) -> Option<(Dialer, String)> {
    let asked = relays.primary().clone();
    let at = shown(&asked);
    let offered = match offer::ask(&asked, trust, &ProxyChoice::FromEnvironment, OFFER_WAIT).await {
        Ok(offered) if offered.layer => offered,
        Ok(_) => {
            say(format!("{at} offers no resumable layer (forward.layer of /relays.json): {WITHOUT}"));
            return None;
        }
        Err(why) => {
            say(format!("{at}: its offer of the resumable layer was not read ({why}): {WITHOUT}"));
            return None;
        }
    };
    if let Some(why) = &offered.refused {
        say(format!("{at}: forward.host of its /relays.json is not taken ({why}): each link goes to {at}"));
    }
    let dialer = Dialer::for_offer(&asked, &offered, host, port, trust.clone()).ok()?;
    let held_at = shown(dialer.relay());
    Some((dialer, held_at))
}

/// The line of a session that the role had no room for, by its words.
pub(crate) fn no_room_line(at: &str, words: &str) -> String {
    let words = podssh_ws::text::one_line(words);
    format!("{at} has no room for a new resumable session ({words}): {WITHOUT}")
}

/// The session of `podssh proxy` to `host:port` in the layer at the first
/// host of `relays`: its exit code, or `None` for the contract's road (the
/// layer was not asked for, the host does not offer it or had no room for
/// the session, or its first link failed in a way that another host of the
/// list may not share).
pub async fn run(relays: &RelayList, trust: &Trust, (host, port): (&str, u16), err: &mut dyn Write) -> Option<i32> {
    match asked_here() {
        Ok(true) => {}
        Ok(false) => return None,
        Err(refusal) => return Some(refusal.report("proxy", err)),
    }
    // PODSSH_OFFLINE: no connection at all, which the contract's road says.
    if podssh_relay::open::offline() {
        return None;
    }
    let (dialer, at) = chosen(relays, trust, (host, port), &mut |line: String| say(err, &line)).await?;
    // Bound first, so that the notes' hold on `err` ends before a refusal
    // is said.
    let linked = dialer.link(&mut |note: &str| say(err, note)).await;
    let first = match linked {
        Ok(link) => link,
        Err(missed) => return refused(&missed, &dialer, &at, err),
    };
    crate::session_log::opened(Some(&dialer.relay().host));
    // OpenSSH's SIGHUP is the end of the bytes, which the role hears.
    let hangup = crate::hangup::take(crate::hangup::Which::All);
    let settings = crate::layered::settings().off_the_pair();
    let begun = async { client::start(first, Ask::New, settings, &mut OsEntropy).await };
    let client = match crate::hangup::unless(Some(&hangup), Box::pin(begun)).await {
        Some(Ok(client)) => client,
        Some(Err(e)) => {
            // No room at the role: nothing of the session went, so the
            // contract's road carries it.
            if let Some(words) = forward_layer::no_room(&e) {
                say(err, &no_room_line(&at, words));
                return None;
            }
            let _ = writeln!(err, "podssh: {at}: the resumable layer's handshake failed: {e}");
            return Some(EX_UNAVAILABLE);
        }
        None => {
            let _ = writeln!(err, "podssh: {at}: a signal ended the session before the relay took it");
            return Some(EX_UNAVAILABLE);
        }
    };
    let io = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    let app = crate::hangup::ending(io, Some(&hangup));
    // stdout carries the session's bytes alone: each line goes to stderr.
    let note = |note: Note| {
        if let Line::Always(text) = crate::layered::line_of(note) {
            let _ = writeln!(err, "podssh: {at}: {text}");
        }
    };
    let session = Box::pin(forward_layer::carry(&dialer, client, app, note));
    // A signal's end: the `CLOSE` went, and nobody reads the bytes any more.
    let Some(outcome) = crate::hangup::bounded(Some(&hangup), session).await else { return Some(0) };
    if let Outcome::Layer(ended) = &outcome {
        crate::session_log::carried(ended.sent, ended.received);
    }
    match crate::layered::why_ended(outcome) {
        None => Some(0),
        Some(why) => {
            let _ = writeln!(err, "podssh: {at}: {why}");
            Some(EX_UNAVAILABLE)
        }
    }
}

/// One line of the opener on stderr.
fn say(err: &mut dyn Write, note: &str) {
    let _ = writeln!(err, "podssh: {note}");
}

/// A first link that did not open: a refusal that the contract's road would
/// get again ends the run with its lines and code; another failure leaves
/// the session to the contract's road, which may try another host.
fn refused(missed: &Missed, dialer: &Dialer, at: &str, err: &mut dyn Write) -> Option<i32> {
    let lines = missed.lines(dialer.target());
    if missed.is_final() {
        for line in &lines {
            let _ = writeln!(err, "podssh: {line}");
        }
        return Some(missed.failure().map_or(EX_UNAVAILABLE, |failure| crate::proxy::sysexit(failure.last())));
    }
    let why = lines.first().cloned().unwrap_or_default();
    let _ = writeln!(err, "podssh: {at}: the resumable layer's first link failed ({why}): {WITHOUT}");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layer_is_asked_for_by_yes_alone_and_another_word_is_refused() {
        for value in [None, Some(""), Some(" "), Some("no"), Some("NO")] {
            assert!(!asked(value).unwrap(), "{value:?}");
        }
        for value in [Some("yes"), Some("Yes"), Some(" yes ")] {
            assert!(asked(value).unwrap(), "{value:?}");
        }
        let refusal = asked(Some("secret-ish")).unwrap_err();
        assert_eq!(refusal.code, 78);
        assert!(!refusal.message.contains("secret-ish"), "the value is not echoed: {}", refusal.message);
    }

    #[test]
    fn a_host_is_shown_with_its_port_unless_it_is_443() {
        let relay = |host: &str, port| podssh_relay::relay::Relay { host: host.into(), port };
        assert_eq!(shown(&relay("relay.example", 443)), "relay.example");
        assert_eq!(shown(&relay("relay.example", 8443)), "relay.example:8443");
    }

    /// The role's words of a full budget reach the user on one line, with
    /// the road that follows, and nothing of a terminal's controls.
    #[test]
    fn the_line_of_no_room_names_the_role_s_words_and_the_road_that_follows() {
        let line = no_room_line("relay.example", "this relay keeps 64 resumable sessions\x1b[2J\n(256 MiB)");
        assert_eq!(
            line,
            "relay.example has no room for a new resumable session (this relay keeps 64 resumable sessions[2J \
             (256 MiB)): the session goes on with no resume"
        );
    }
}
