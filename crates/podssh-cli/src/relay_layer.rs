//! `podssh proxy HOST PORT` in the resumable layer at podssh's relay role
//! (T-173), where the first relay host offers it in its `/relays.json`: read
//! at each run with `PODSSH_RELAY_LAYER=yes`; unset, as a host offered it
//! within a day (`podssh_relay::forward_layer::kept`), the offer of a host
//! that the user named read once a day before its session, a second at
//! most; never with `no`.
//! The role holds the
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
//!
//! The end of stdin is the layer's `END` where the role takes it (T-632): the
//! target gets the end of its input, and its answer still comes (`half`). A
//! signal still ends the whole session; one after the end of stdin finds the
//! `END` gone, and the session ends with the target, as an sshd ends at the
//! end of its input. A role of an older build takes no `END`, and the end of
//! stdin then stops sending and keeps receiving, as on the contract's road.

mod half;
pub(crate) mod ssh;

use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use podssh_relay::forward_layer::{self, kept, offer, Dialer, Missed};
use podssh_relay::relay::{Relay, RelayList};
use podssh_relay::session::client::{self, Client, Found, Outcome};
use podssh_relay::session::resume::Note;
use podssh_relay::session::{half_close, Ask, OsEntropy, Settings};
use podssh_relay::transit::link::Link;
use podssh_ws::{ProxyChoice, Trust};

use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::layered::Line;
use crate::relay_settings::Refusal;

/// `yes`: ask for the layer where the first relay host offers it; `no`:
/// never; unset: where it offered it within a day.
pub const ENV: &str = "PODSSH_RELAY_LAYER";
/// How long each step of the read of the host's offer may take.
const OFFER_WAIT: Duration = Duration::from_secs(10);
/// The whole read where the user did not ask, before the session: a silent
/// first host costs its failover this, once a day (T-220's bounds).
const UNASKED_WAIT: Duration = Duration::from_secs(1);
/// What follows when the layer is not there: the contract's road.
const WITHOUT: &str = "the session goes on with no resume";

/// What the user asked of the layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// `yes`: the first host's offer read at each run, and each case said.
    Yes,
    /// `no`: the contract's road alone.
    No,
    /// Unset or empty: the layer where the first host's kept offer says so,
    /// with no line where it is not there; for a host that the user named
    /// and whose offer is not kept, one read of it first, a second at most.
    Unset,
}

/// What the user asked: `yes` or `no`, else unset; another word is a
/// configuration error (78), which does not echo it.
pub fn asked(value: Option<&str>) -> Result<Asked, Refusal> {
    match value.map(str::trim) {
        None | Some("") => Ok(Asked::Unset),
        Some(word) if word.eq_ignore_ascii_case("no") => Ok(Asked::No),
        Some(word) if word.eq_ignore_ascii_case("yes") => Ok(Asked::Yes),
        Some(_) => Err(Refusal::config(format!("{ENV}: yes or no"))),
    }
}

/// [`asked`], of this process's environment.
pub(crate) fn asked_here() -> Result<Asked, Refusal> {
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
/// went to `say` where the user asked for the layer.
pub(crate) async fn chosen(
    relays: &RelayList,
    trust: &Trust,
    (host, port): (&str, u16),
    asked_for: Asked,
    say: &mut dyn FnMut(String),
) -> Option<(Dialer, String)> {
    let asked = relays.primary().clone();
    let at = shown(&asked);
    let loud = asked_for == Asked::Yes;
    let mut quiet = |line: String| {
        if loud {
            say(line);
        }
    };
    // Unset: a kept offer, else a read for a host that the user named; the
    // default deployment's offer comes with its pool's refresh alone.
    let kept = if loud { None } else { kept::kept_now(&asked) };
    let read = match kept {
        Some(offered) => Ok(offered),
        None if loud => {
            let read = offer::ask(&asked, trust, &ProxyChoice::FromEnvironment, OFFER_WAIT).await;
            // A read that failed is kept as no offer, so that a host whose
            // document hangs costs the wait once a day, not at each run.
            kept::keep_now(&asked, read.as_ref().unwrap_or(&offer::Offer::default()));
            read
        }
        None if relays.explicit => unasked(&asked, trust).await,
        None => return None,
    };
    let offered = match read {
        Ok(offered) if offered.layer => offered,
        Ok(_) => {
            quiet(format!("{at} offers no resumable layer (forward.layer of /relays.json): {WITHOUT}"));
            return None;
        }
        Err(why) => {
            quiet(format!("{at}: its offer of the resumable layer was not read ({why}): {WITHOUT}"));
            return None;
        }
    };
    if let Some(why) = &offered.refused {
        quiet(format!("{at}: forward.host of its /relays.json is not taken ({why}): each link goes to {at}"));
    }
    let dialer = Dialer::for_offer(&asked, &offered, host, port, trust.clone()).ok()?;
    let held_at = shown(dialer.relay());
    Some((dialer, held_at))
}

/// The read of the offer of `relay`, a host that the user named, where the
/// user did not ask for the layer: [`UNASKED_WAIT`] in all, its connection
/// closed before the session's opens, never beside it. What it found is
/// kept for a day; a read that failed or passed the wait as no offer, so
/// that a silent first host costs the wait once a day, not at each run.
async fn unasked(relay: &Relay, trust: &Trust) -> Result<offer::Offer, String> {
    let asking = offer::ask(relay, trust, &ProxyChoice::FromEnvironment, UNASKED_WAIT);
    let read = match tokio::time::timeout(UNASKED_WAIT, asking).await {
        Ok(read) => read,
        Err(_) => Err(format!("/relays.json took more than {} s", UNASKED_WAIT.as_secs())),
    };
    kept::keep_now(relay, read.as_ref().unwrap_or(&offer::Offer::default()));
    read
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
    let asked_for = match asked_here() {
        Ok(Asked::No) => return None,
        Ok(asked_for) => asked_for,
        Err(refusal) => return Some(refusal.report("proxy", err)),
    };
    // PODSSH_OFFLINE: no connection at all, which the contract's road says.
    if podssh_relay::open::offline() {
        return None;
    }
    let (dialer, at) = chosen(relays, trust, (host, port), asked_for, &mut |line: String| say(err, &line)).await?;
    // Bound first, so that the notes' hold on `err` ends before a refusal
    // is said.
    let linked = dialer.link(&mut |note: &str| say(err, note)).await;
    let first = match linked {
        Ok(link) => link,
        Err(missed) => {
            if let Some(line) = unserved(relays, &missed, &at) {
                say(err, &line);
                return None;
            }
            return refused(&missed, &dialer, &at, err);
        }
    };
    crate::session_log::opened(Some(&dialer.relay().host));
    // OpenSSH's SIGHUP is the end of the bytes, which the role hears.
    let hangup = crate::hangup::take(crate::hangup::Which::All);
    // The end of stdin ends its direction alone, where the role takes it.
    let settings = Settings { half_close: true, ..crate::layered::settings().off_the_pair() };
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
    let ends = matches!(client.found(), Found::Layer { features, .. } if half_close::agreed(features));
    if ends {
        // A signal fails the reads, so that it still ends the whole session.
        let io = half::EndsWithReply::new(tokio::io::stdin(), tokio::io::stdout());
        let app = crate::hangup::ending_wholly(io, Some(&hangup));
        return carried(&dialer, client, app, (&at, &hangup), err).await;
    }
    let io = tokio::io::join(KeepsReceiving { read: tokio::io::stdin(), ended: false }, tokio::io::stdout());
    let app = crate::hangup::ending(io, Some(&hangup));
    carried(&dialer, client, app, (&at, &hangup), err).await
}

/// `client`'s session with `app`, the session's stdin and stdout, to its end
/// or [`crate::hangup::AFTER_SIGNAL`] after a signal: the exit code.
async fn carried<A>(
    dialer: &Dialer,
    client: Client<Link>,
    app: A,
    (at, hangup): (&str, &crate::hangup::Hangup),
    err: &mut dyn Write,
) -> Option<i32>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
{
    // stdout carries the session's bytes alone: each line goes to stderr.
    let note = |note: Note| {
        if let Line::Always(text) = crate::layered::line_of(note) {
            let _ = writeln!(err, "podssh: {at}: {text}");
        }
    };
    let session = Box::pin(forward_layer::carry(dialer, client, app, note));
    // A signal's end: the `CLOSE` went, and nobody reads the bytes any more.
    let Some(outcome) = crate::hangup::bounded(Some(hangup), session).await else { return Some(0) };
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

/// stdin, whose end stops sending and keeps receiving, as on the contract's
/// road (`crate::proxy`), for a role that takes no `END` (T-632): its
/// layer's `CLOSE` ends the whole session, so an end of input that reached it
/// would cut off a reply still on its way (`echo QUERY | podssh proxy HOST
/// PORT`). The target's end ends the session; a signal still ends the input
/// (`crate::hangup::ending`).
struct KeepsReceiving<R> {
    read: R,
    ended: bool,
}

impl<R: AsyncRead + Unpin> AsyncRead for KeepsReceiving<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.ended {
            // The other ways of the session wake its task.
            return Poll::Pending;
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.read).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() > 0 => {
                self.ended = true;
                Poll::Pending
            }
            other => other,
        }
    }
}

/// A first link whose host answered 404 for the layer's path: it no longer
/// serves it, so its kept offer goes, and the contract's road carries the
/// session, with this line. A host that serves neither road refuses that
/// road too.
pub(crate) fn unserved(relays: &RelayList, missed: &Missed, at: &str) -> Option<String> {
    if !missed.not_served() {
        return None;
    }
    kept::forget(relays.primary());
    Some(format!("{at} no longer serves the resumable layer (404): {WITHOUT}"))
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
    fn the_layer_is_asked_for_by_yes_refused_by_no_and_another_word_is_refused() {
        for value in [None, Some(""), Some(" ")] {
            assert_eq!(asked(value).unwrap(), Asked::Unset, "{value:?}");
        }
        for value in [Some("no"), Some("NO")] {
            assert_eq!(asked(value).unwrap(), Asked::No, "{value:?}");
        }
        for value in [Some("yes"), Some("Yes"), Some(" yes ")] {
            assert_eq!(asked(value).unwrap(), Asked::Yes, "{value:?}");
        }
        let refusal = asked(Some("secret-ish")).unwrap_err();
        assert_eq!(refusal.code, 78);
        assert!(!refusal.message.contains("secret-ish"), "the value is not echoed: {}", refusal.message);
    }

    /// What came before the end of stdin is read; the read after it waits,
    /// so the end never reaches the layer as a `CLOSE`.
    #[tokio::test]
    async fn the_end_of_stdin_reads_as_a_wait_not_as_an_end() {
        use tokio::io::AsyncReadExt;
        let mut input = KeepsReceiving { read: &b"query"[..], ended: false };
        let mut buf = [0u8; 16];
        assert_eq!(input.read(&mut buf).await.unwrap(), 5);
        let next = tokio::time::timeout(Duration::from_millis(100), input.read(&mut buf)).await;
        assert!(next.is_err(), "the end of the input was read as one");
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
