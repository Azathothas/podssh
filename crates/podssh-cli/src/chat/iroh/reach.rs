//! The side of `podssh chat` that reaches a node of the iroh road (T-099):
//! the ticket names the node and its key, which the channel checks; the
//! session runs the resumable layer over the iroh road, as `podssh pipe
//! iroh:` carries one, and podssh tries again each 5 s while the node is not
//! there.

use std::time::Duration;

use podssh_iroh::Failure;
use podssh_relay::session::resume::Note;
use podssh_relay::session::Settings;
use podssh_ssh::{Log, LogLevel};
use podssh_ws::Trust;
use serde_json::json;
use tokio::io::AsyncWrite;

use crate::channel::{Ask, Expect};
use crate::chat::args::ChatArgs;
use crate::chat::converse::{converse_until, Ended, Options};
use crate::chat::lines::Lines;
use crate::chat::output::Output;
use crate::chat::reach::{both, RETRY};
use crate::chat::run::{self, Until};
use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};
use crate::layered::Line;
use crate::relay_settings::Refusal;
use crate::ssh::iroh::dial::{self, Prepared};

/// Each direction of the pipe between the conversation and the session.
const PIPE: usize = 256 * 1024;
/// How long the endpoint may take to close after the run.
const CLOSE_LIMIT: Duration = Duration::from_secs(3);

/// The side that reaches over the iroh road, once each check that needs no
/// network passed.
pub(in crate::chat) struct Ready {
    pub label: String,
    ticket: String,
    ask: Ask,
    relays: Vec<String>,
    trust: Trust,
}

impl Ready {
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// The ticket, read before any network; the relays and the trust.
pub(in crate::chat) fn prepare(ticket: String, ask: Ask, args: &ChatArgs) -> Result<Ready, Refusal> {
    let dest = crate::ssh::iroh::destination(&ticket)
        .map_err(Refusal::usage)?
        .ok_or_else(|| Refusal::usage(format!("{ticket:?} is not an iroh ticket")))?;
    if dest.user.is_some() {
        return Err(Refusal::usage(format!("{ticket:?}: a peer has no user name")));
    }
    let relays = crate::ssh::iroh::relays(args.iroh_relay.as_deref())?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    Ok(Ready { label: dest.shown, ticket: dest.ticket, ask, relays, trust })
}

/// Each conversation with the node of the ticket, until the run ends.
pub(in crate::chat) async fn run<W: AsyncWrite + Unpin>(
    ready: Ready,
    lines: &mut Lines,
    out: &mut Output<W>,
    opts: Options,
    until: Until,
) -> i32 {
    let Ready { label, ticket, ask, relays, trust } = ready;
    let log = Log::new(LogLevel::Info);
    let prepared = tokio::select! {
        prepared = dial::prepare(&ticket, ask.client_key.as_deref(), &relays, &trust, &log) => prepared,
        ended = until.wait() => return run::finish(&ended, 0, lines, out).await,
    };
    let Prepared { dialer, endpoint, fingerprint, identity, node, .. } = match prepared {
        Ok(prepared) => prepared,
        Err(why) => return run::refused(EX_UNAVAILABLE, why, lines, out).await,
    };
    let settings = Settings { features: podssh_iroh::FEATURES, ..crate::layered::settings() };
    // Whether "tries again" was said since the last peer.
    let mut said = false;
    let code = loop {
        let (app, chat) = tokio::io::duplex(PIPE);
        // The channel of T-088, to the node that the ticket names.
        let channel = ask.with(identity.clone(), Expect::Ticket(node));
        let shown = label.clone();
        let pin_say = move |line: String| eprintln!("podssh chat: {shown}: {line}");
        let (layer_app, session) = crate::channel::around(app, channel, pin_say);
        let shown = label.clone();
        let note = move |note: Note| {
            if let Line::Always(text) = crate::layered::line_of(note) {
                eprintln!("podssh chat: {shown}: {text}");
            }
        };
        let road = async {
            let session = async move {
                match session {
                    Some(session) => session.await.err(),
                    None => None,
                }
            };
            tokio::join!(podssh_iroh::carry(&dialer, layer_app, settings, note), session)
        };
        let conversation = converse_until(chat, lines, out, opts.clone(), until.wait());
        let (summary, road) = both(conversation, road).await;
        run::undelivered(&summary.undelivered, out).await;
        let mut why = None;
        if let Some((carried, failed)) = road {
            if let Some((fault, words)) = failed.as_ref().and_then(|e| crate::channel::judged(e, Some(&*identity))) {
                break run::refused(fault.code(), words, lines, out).await;
            }
            let refused = matches!(carried, Err(Failure::Refused));
            why = dial::why_failed(carried, &fingerprint);
            if refused {
                break run::refused(EX_NOPERM, why.unwrap_or_default(), lines, out).await;
            }
        }
        match summary.ended {
            Ended::PeerLeft if run::goes_on(lines, &opts) => {
                said = said && summary.peer.is_none();
                if !said {
                    said = true;
                    let gone = if summary.peer.is_some() { "the peer left" } else { "the peer is not there" };
                    let why = why.map(|w| format!(" ({w})")).unwrap_or_default();
                    let line = format!("{gone}{why}; podssh tries again each {} s", RETRY.as_secs());
                    out.notice("waiting", json!({ "peer": summary.peer }), line).await;
                }
                let stop = tokio::select! {
                    () = tokio::time::sleep(RETRY) => None,
                    ended = until.wait() => Some(ended),
                    () = lines.until_quit() => Some(Ended::Done),
                };
                if let Some(ended) = stop {
                    break run::finish(&ended, 0, lines, out).await;
                }
            }
            ended => break run::finish(&ended, summary.undelivered.len(), lines, out).await,
        }
    };
    dialer.close().await;
    let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
    code
}
