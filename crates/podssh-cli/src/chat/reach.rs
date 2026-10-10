//! The side of `podssh chat` that reaches the peer (T-099): the operator of
//! the pair NAME, over the resumable layer and the end-to-end channel, as
//! `podssh operator` carries a session. While the node is not there, it
//! tries again each 5 s, and the user's lines wait.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::identity::Identity;
use podssh_relay::pair::OperatorPart;
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome as LegOutcome, Wire};
use podssh_ws::client::ConnectError;
use podssh_ws::{ProxyChoice, Trust};
use serde_json::json;
use tokio::io::{AsyncWrite, DuplexStream};
use tokio::task::JoinHandle;

use super::args::ChatArgs;
use super::converse::{converse_until, Ended, Options, Summary};
use super::lines::{Lines, MAX_LINES};
use super::output::Output;
use super::run::{self, Until, CLOSE_WAIT};
use crate::channel::{Ask, Expect, Operator};
use crate::layered::{Carried, Line};
use crate::relay_settings::Refusal;

/// Each direction of the pipe between the conversation and the session.
const PIPE: usize = 256 * 1024;
/// The wait between two tries while the peer is not there.
pub(super) const RETRY: Duration = Duration::from_secs(5);

/// The side that reaches, once each check that needs no network passed.
pub(super) struct Ready {
    pub label: String,
    part: OperatorPart,
    trust: Trust,
    identity: Arc<Identity>,
    expect: Expect,
}

/// The pins, the pair's operator part, and this side's key, loaded or made.
pub(super) fn prepare(label: String, ask: &Ask, args: &ChatArgs) -> Result<Ready, Refusal> {
    crate::pins::apply(args.relay_addr.as_deref())?;
    let part = crate::pairs::operator_part(&label, args.pair_file.as_deref())?;
    crate::pairs::online()?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    let shown = label.clone();
    let say = move |line: String| eprintln!("podssh chat: {shown}: {line}");
    let channel = ask.operator(Expect::Pinned(label.clone()), &say).map_err(Refusal::config)?;
    let Some(Operator { identity, expect }) = channel else {
        return Err(Refusal::usage("chat always runs the end-to-end channel"));
    };
    Ok(Ready { label, part, trust, identity, expect })
}

/// Why the run stops before a conversation.
enum Stop {
    Ended(Ended),
    Refused(Refusal),
}

/// Each conversation with the peer, until the run ends.
pub(super) async fn run<W: AsyncWrite + Unpin>(
    ready: Ready,
    lines: &mut Lines,
    out: &mut Output<W>,
    opts: Options,
    until: Until,
) -> i32 {
    let Ready { label, part, trust, identity, expect } = ready;
    let proxy = ProxyChoice::FromEnvironment;
    let config = OperatorConfig {
        relay: &part.relay,
        name: &part.name,
        connect_token: part.connect_token(),
        trust: &trust,
        proxy: &proxy,
        timeout: crate::pairs::REQUEST_LIMIT,
        limits: OperatorLimits::default(),
        wire: Wire::Tls,
    };
    // Whether "tries again" was said since the last peer.
    let mut said = false;
    loop {
        let (link, first) = match leg(&config, &label, until, &mut said, lines, out).await {
            Ok(leg) => leg,
            Err(Stop::Ended(ended)) => return run::finish(&ended, 0, lines, out).await,
            Err(Stop::Refused(refusal)) => return run::refused(refusal.code, refusal.message, lines, out).await,
        };
        let (app, chat) = tokio::io::duplex(PIPE);
        let channel = Some(Operator { identity: identity.clone(), expect: expect.clone() });
        let shown = label.clone();
        let say = move |line: Line| {
            if let Line::Always(text) = line {
                eprintln!("podssh chat: {shown}: {text}");
            }
        };
        let shown = label.clone();
        let pin_say = move |line: String| eprintln!("podssh chat: {shown}: {line}");
        let carried =
            crate::layered::carry_through(&config, link, first, app, Some(part.expires_ms), &say, channel, pin_say);
        let conversation = converse_until(chat, lines, out, opts.clone(), until.wait());
        let (summary, carried) = both(conversation, carried).await;
        run::undelivered(&summary.undelivered, out).await;
        if let Some((code, why)) = carried.as_ref().and_then(|c| final_end(&label, c)) {
            return run::refused(code, why, lines, out).await;
        }
        match summary.ended {
            Ended::PeerLeft if run::goes_on(lines, &opts) => {
                said = summary.peer.is_none() && said;
                if !said {
                    said = true;
                    let road = carried.as_ref().and_then(|c| crate::operator::judged(&label, c));
                    let why = road.map(|(_, why)| format!(" ({why})")).unwrap_or_default();
                    let gone = if summary.peer.is_some() { "the peer left" } else { "the peer is not there" };
                    let line = format!("{gone}{why}; podssh tries again each {} s", RETRY.as_secs());
                    out.notice("waiting", json!({ "peer": summary.peer }), line).await;
                }
                let stop = tokio::select! {
                    () = tokio::time::sleep(RETRY) => None,
                    ended = until.wait() => Some(ended),
                    () = lines.until_quit() => Some(Ended::Done),
                };
                if let Some(ended) = stop {
                    return run::finish(&ended, 0, lines, out).await;
                }
            }
            ended => return run::finish(&ended, summary.undelivered.len(), lines, out).await,
        }
    }
}

/// A leg to the node: again each 5 s while the relay says that no node
/// serves the pair, which is said once; `/quit` ends the wait.
async fn leg<W: AsyncWrite + Unpin>(
    config: &OperatorConfig<'_>,
    label: &str,
    until: Until,
    said: &mut bool,
    lines: &mut Lines,
    out: &mut Output<W>,
) -> Result<(DuplexStream, JoinHandle<LegOutcome>), Stop> {
    loop {
        let (link, leg_end) = tokio::io::duplex(PIPE);
        let started = tokio::select! {
            started = operator::start(config, leg_end) => started,
            ended = until.wait() => return Err(Stop::Ended(ended)),
            () = lines.until_quit() => return Err(Stop::Ended(Ended::Done)),
        };
        match started {
            Ok(first) => return Ok((link, first)),
            Err(e) if offline(&e) => {
                if !*said {
                    *said = true;
                    let line = format!(
                        "the peer is not there ({e}); podssh tries again each {} s, and the lines typed meanwhile \
                         wait, {MAX_LINES} lines or 1 MiB at most",
                        RETRY.as_secs()
                    );
                    out.notice("waiting", json!({ "why": e.to_string() }), line).await;
                }
                tokio::select! {
                    () = tokio::time::sleep(RETRY) => {}
                    ended = until.wait() => return Err(Stop::Ended(ended)),
                    () = lines.until_quit() => return Err(Stop::Ended(Ended::Done)),
                }
            }
            Err(e) => return Err(Stop::Refused(crate::pairs::connect_refusal(&e, label))),
        }
    }
}

/// The relay's word that no node serves the pair now: a later try can work.
fn offline(e: &ConnectError) -> bool {
    matches!(e, ConnectError::Refused { status: 503, body } if body.to_ascii_lowercase().contains("offline"))
}

/// The conversation and the session under it, until both ended; once the
/// conversation ended, the session gets a while to close. The iroh road's
/// side uses it too.
pub(super) async fn both<K>(
    conversation: impl Future<Output = Summary>,
    carried: impl Future<Output = K>,
) -> (Summary, Option<K>) {
    tokio::pin!(conversation, carried);
    tokio::select! {
        summary = &mut conversation => (summary, tokio::time::timeout(CLOSE_WAIT, carried).await.ok()),
        carried = &mut carried => (conversation.await, Some(carried)),
    }
}

/// An end of the road that a new try would only repeat: a key that the
/// channel refused, a pair stopped or expired, a fault of podssh's bytes.
fn final_end(label: &str, carried: &Carried) -> Option<(i32, String)> {
    if carried.channel.is_some() {
        return crate::operator::judged(label, carried);
    }
    let outcome = carried.leg.as_ref()?;
    crate::layered::stops(outcome)?;
    // The leg names the end: what the layer says of it says less.
    crate::operator::judged(label, &Carried { why: None, leg: Some(outcome.clone()), channel: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_relays_word_of_no_node_is_tried_again() {
        let refused = |status, body: &str| ConnectError::Refused { status, body: body.into() };
        assert!(offline(&refused(503, "reverse: node offline")));
        assert!(!offline(&refused(503, "reverse: unavailable")));
        assert!(!offline(&refused(403, "reverse: forbidden")));
    }
}
