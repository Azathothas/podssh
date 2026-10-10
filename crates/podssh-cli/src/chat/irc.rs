//! `podssh chat --irc SERVER[:PORT] CHANNEL` (T-252): chat in a channel of
//! an IRC network, through the relay's forward road, with TLS inside the
//! relay stream unless `--irc-plaintext` asks for plain text, which the
//! relay and each server then read. A lost connection is made again each
//! 5 s, and the session rejoins the channel.

mod files;
pub mod plan;
mod talk;

use std::time::Duration;

use podssh_core::irc::{ReapPolicy, Server, Session};
use podssh_relay::open::Request;
use podssh_relay::relay::{self, RelayList};
use podssh_ws::Trust;
use serde_json::json;
use tokio::io::AsyncWrite;

pub use plan::IrcPlan;
pub use talk::{irc_converse, IrcOptions, IrcSummary};

use super::args::ChatArgs;
use super::converse::{Ended, Options};
use super::lines::Lines;
use super::output::Output;
use super::reach::RETRY;
use super::run::{self, Until};
use crate::channel::Bytes;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;

/// The bound on the TLS handshake with the server.
const TLS_LIMIT: Duration = Duration::from_secs(30);
/// The bound on a direct dial of the server.
const DIAL_LIMIT: Duration = Duration::from_secs(20);

/// The chat over IRC, once each check that needs no network passed.
pub(super) struct Ready {
    pub label: String,
    plan: IrcPlan,
    nick: String,
    relays: RelayList,
    path: String,
    trust: Trust,
    irc_trust: Trust,
}

/// The pins, the relay hosts, and the trust of the relay and of the server.
pub(super) fn prepare(plan: IrcPlan, nick: String, args: &ChatArgs) -> Result<Ready, Refusal> {
    crate::pins::apply(args.relay_addr.as_deref())?;
    let relays = crate::relay_settings::relays(None, std::env::var(relay::RELAY_ENV).ok())?;
    let path = relay::forward_path(&plan.server, plan.port).map_err(Refusal::usage)?;
    crate::pairs::online()?;
    let ca = args.ca_file.clone().or_else(|| std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty()));
    let trust = ca.map_or(Trust::Default, |file| Trust::File(file.into()));
    let irc_trust = args.irc_ca_file.as_ref().map_or(Trust::Default, |file| Trust::File(file.into()));
    let label = podssh_ws::dial::authority(&plan.server, plan.port);
    Ok(Ready { label, plan, nick, relays, path, trust, irc_trust })
}

/// Each connection to the server, until the run ends.
pub(super) async fn run<W: AsyncWrite + Unpin>(
    ready: Ready,
    lines: &mut Lines,
    out: &mut Output<W>,
    opts: Options,
    until: Until,
) -> i32 {
    if !ready.plan.tls {
        let line = "plain text (--irc-plaintext): the relay and each server read each line";
        out.notice("plaintext", json!({}), line.to_string()).await;
    }
    let user = Server {
        host: ready.plan.server.clone(),
        port: ready.plan.port,
        nick: ready.nick.clone(),
        username: ready.nick.to_ascii_lowercase(),
        realname: "podssh".into(),
    };
    let mut session = Session::new(user, ReapPolicy::default());
    let irc = IrcOptions {
        channel: ready.plan.channel.clone(),
        once: opts.once.clone(),
        accept_dir: opts.accept_dir.clone(),
        here: opts.here.clone(),
    };
    let mut first = true;
    // Whether "tries again" was said since the last connection that joined.
    let mut said = false;
    loop {
        let connected = tokio::select! {
            connected = connect(&ready) => connected,
            ended = until.wait() => return run::finish(&ended, 0, lines, out).await,
            () = lines.until_quit() => return run::finish(&Ended::Done, 0, lines, out).await,
        };
        let why = match connected {
            Ok(stream) => {
                let summary = irc_converse(stream, &mut session, first, lines, out, &irc, until.wait()).await;
                first = false;
                run::undelivered(&summary.undelivered, out).await;
                if summary.joined {
                    said = false;
                }
                match summary.ended {
                    Ended::PeerLeft if run::goes_on(lines, &opts) => format!("the connection to {} ended", ready.label),
                    ended => return run::finish(&ended, summary.undelivered.len(), lines, out).await,
                }
            }
            Err(Unreached::Final(code, why)) => return run::refused(code, why, lines, out).await,
            Err(Unreached::Again(why)) => why,
        };
        if !said {
            said = true;
            let line = format!("{why}; podssh connects again each {} s", RETRY.as_secs());
            out.notice("waiting", json!({ "why": why }), line).await;
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
}

/// Why no connection came: a try later can work, or it cannot.
enum Unreached {
    Again(String),
    Final(i32, String),
}

/// A relay session to the server (with `--direct`, TCP), and TLS inside it
/// unless plain text was asked for.
async fn connect(ready: &Ready) -> Result<Box<dyn Bytes>, Unreached> {
    let target = &ready.label;
    let stream: Box<dyn Bytes> = if ready.plan.direct {
        let proxy = podssh_ws::ProxyChoice::FromEnvironment;
        match podssh_ws::dial::dial(&ready.plan.server, ready.plan.port, &proxy, DIAL_LIMIT).await {
            Ok(tcp) => Box::new(tcp),
            Err(podssh_ws::DialError::BadProxy(why)) => return Err(Unreached::Final(EX_CONFIG, why)),
            Err(e) => return Err(Unreached::Again(format!("{target}: {e}"))),
        }
    } else {
        let request = Request { relays: &ready.relays, path: &ready.path, trust: &ready.trust, target, rounds: 1 };
        let opened = podssh_relay::open(&request, &mut |note: &str| eprintln!("podssh chat: {target}: {note}"))
            .await
            .map_err(|failure| {
            let code = crate::proxy::sysexit(failure.last());
            let why = failure.lines(target).join("; ");
            if code == EX_UNAVAILABLE {
                Unreached::Again(why)
            } else {
                Unreached::Final(code, why)
            }
        })?;
        Box::new(podssh_ssh::relay_stream::spawn(opened.session).0)
    };
    if !ready.plan.tls {
        return Ok(stream);
    }
    // A failed handshake is final: never a fall back to plain text. A
    // certificate that is not trusted is a refusal; another end is a port
    // with no TLS, or none that the relay reaches.
    match podssh_ws::tls::connect_over(stream, &ready.plan.server, &ready.irc_trust, TLS_LIMIT).await {
        Ok(tls) => Ok(Box::new(tls)),
        Err(why) if why.contains("certificate") => Err(Unreached::Final(EX_NOPERM, why)),
        Err(why) => Err(Unreached::Final(
            EX_UNAVAILABLE,
            format!(
                "{why}; the server may take no TLS on port {}: --irc SERVER:PORT names another, and \
                 --irc-plaintext takes plain text",
                ready.plan.port
            ),
        )),
    }
}
