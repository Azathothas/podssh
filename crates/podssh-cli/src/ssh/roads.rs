//! `podssh ssh node://NAME` over more roads than the pair's (T-164, T-379):
//! the iroh road of `--iroh-ticket` first, the pair's road 250 ms after,
//! then the DERP road of `--derp-ticket` 250 ms after that, each at once
//! when each road before it failed. A DERP ticket kept under NAME, which
//! the user did not give in this run, starts only when each road before it
//! failed: the fallback that the operator's ruling Q50 allows, which costs
//! tailcat's fleet nothing while the pair's road works. The first far end
//! that speaks carries the session, and the other links end before they
//! send a byte, so they open nothing at the node's TARGET; each resume races
//! the roads again. A node with no pair here has its other roads alone.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_relay::derp::Dialer;
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome as LegOutcome, Wire};
use podssh_relay::session::race::{in_turn, Start, WonAt, HEAD_START};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{client, Ask, End, Ended, OsEntropy};
use podssh_ssh::{Log, EXIT_FAILURE};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::task::JoinHandle;

use super::iroh::IrohRoad;
use crate::layered::{self, Line};

/// Each direction of the pipes between SSH, the layer and a leg.
const PIPE: usize = 256 * 1024;

/// A link on any road.
pub enum Road {
    #[cfg(feature = "iroh")]
    Iroh(podssh_iroh::Stream),
    Pair(DuplexStream),
    Derp(podssh_relay::derp::Link),
}

impl AsyncRead for Road {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_read(cx, buf),
            Road::Pair(link) => Pin::new(link).poll_read(cx, buf),
            Road::Derp(link) => Pin::new(link).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Road {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_write(cx, buf),
            Road::Pair(link) => Pin::new(link).poll_write(cx, buf),
            Road::Derp(link) => Pin::new(link).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_flush(cx),
            Road::Pair(link) => Pin::new(link).poll_flush(cx),
            Road::Derp(link) => Pin::new(link).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_shutdown(cx),
            Road::Pair(link) => Pin::new(link).poll_shutdown(cx),
            Road::Derp(link) => Pin::new(link).poll_shutdown(cx),
        }
    }
}

/// The roads of a run beside the pair's: the iroh road of `--iroh-ticket`,
/// and the DERP road of a ticket given or kept.
pub(super) struct Raced<'a> {
    pub iroh: Option<&'a super::iroh::Race>,
    pub derp: Option<super::derp::Road>,
}

/// Which road a place of the race is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Iroh,
    Pair,
    Derp,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Iroh => "the iroh road",
            Kind::Pair => "the pair's road",
            Kind::Derp => "the DERP road",
        }
    }
}

/// A road's attempt at a link.
type Going<'s> = Pin<Box<dyn Future<Output = Result<Road, String>> + 's>>;

/// The roads of one run, each made once: the iroh road's endpoint, the
/// pair's legs, the DERP road's dialer.
struct Roads<'a> {
    iroh: Option<IrohRoad<'a>>,
    pair: Option<&'a OperatorConfig<'a>>,
    /// The DERP road's dialer, and whether the user gave its ticket.
    derp: Option<(Dialer, bool)>,
    label: &'a str,
    legs: Mutex<Option<JoinHandle<LegOutcome>>>,
    /// The pair's road ended with a close that a new leg would only get again.
    pair_final: AtomicBool,
}

impl<'a> Roads<'a> {
    /// The attempts of one race, in their order, each with its start; and
    /// which road each is. `previous` is the pair's last leg, whose end
    /// tells whether a new one may work.
    fn race(&self, previous: Option<JoinHandle<LegOutcome>>) -> (Vec<(Start, Going<'_>)>, Vec<Kind>) {
        let (mut list, mut kinds): (Vec<(Start, Going<'_>)>, Vec<Kind>) = (Vec::new(), Vec::new());
        if let Some(iroh) = &self.iroh {
            list.push((Start::After(HEAD_START), Box::pin(iroh.link())));
            kinds.push(Kind::Iroh);
        }
        if let Some(config) = self.pair {
            list.push((Start::After(HEAD_START), Box::pin(pair_link(config, self, previous))));
            kinds.push(Kind::Pair);
        }
        if let Some((dialer, asked)) = &self.derp {
            // A kept ticket is the fallback: only when each road before it failed.
            let start = if *asked { Start::After(HEAD_START) } else { Start::WhenAllFailed };
            list.push((start, Box::pin(derp_link(dialer))));
            kinds.push(Kind::Derp);
        }
        (list, kinds)
    }

    /// Whether no road can give a link again: the pair's ended for good or
    /// is not there, the iroh road's node refused this client or it is not
    /// there, and there is no DERP road, whose node may come back.
    async fn ended_for_good(&self) -> bool {
        if self.derp.is_some() {
            return false;
        }
        let pair_done = self.pair.is_none() || self.pair_final.load(Ordering::SeqCst);
        let iroh_done = match &self.iroh {
            Some(iroh) => iroh.refused().await,
            None => true,
        };
        pair_done && iroh_done
    }

    async fn close(&self) {
        if let Some((dialer, _)) = &self.derp {
            dialer.close().await;
        }
        if let Some(iroh) = &self.iroh {
            iroh.close().await;
        }
    }
}

/// A new leg of the pair's road, unless the last one ended with a close
/// that a new leg would only get again.
async fn pair_link(
    config: &OperatorConfig<'_>,
    roads: &Roads<'_>,
    previous: Option<JoinHandle<LegOutcome>>,
) -> Result<Road, String> {
    if let Some(handle) = previous {
        if let Ok(Ok(outcome)) = tokio::time::timeout(layered::LEG_WAIT, handle).await {
            if let Some(stop) = layered::stops(&outcome) {
                roads.pair_final.store(true, Ordering::SeqCst);
                return Err(stop);
            }
        }
    }
    if roads.pair_final.load(Ordering::SeqCst) {
        return Err("the pair's road ended for good".to_string());
    }
    let (link, leg_end) = tokio::io::duplex(PIPE);
    match operator::start(config, leg_end).await {
        Ok(handle) => {
            *layered::lock(&roads.legs) = Some(handle);
            Ok(Road::Pair(link))
        }
        Err(e) => {
            if layered::is_final(&e) {
                roads.pair_final.store(true, Ordering::SeqCst);
            }
            Err(crate::pairs::connect_refusal(&e, roads.label).message)
        }
    }
}

async fn derp_link(dialer: &Dialer) -> Result<Road, String> {
    dialer.link().await.map(Road::Derp)
}

/// SSH to the node of the pair under `label`, over the first of its roads
/// that answers, again at each resume.
pub(super) async fn connect(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    raced: Raced<'_>,
    ask: &crate::channel::Ask,
    opts: &podssh_ssh::options::Options,
    log: Arc<Log>,
) -> i32 {
    let shown = format!("{}{label}", super::node::SCHEME);
    if let Err(refusal) = crate::pairs::online() {
        log.error(&format!("{shown}: {}", refusal.message));
        return EXIT_FAILURE;
    }
    // The pair's road, when this host has the pair; a node that the DERP
    // road reaches may have none here.
    let part = match crate::pairs::operator_part(label, pair_file) {
        Ok(part) => Some(part),
        Err(refusal) if raced.derp.is_some() && pair_file.is_none() => {
            log.verbose(&format!("{shown}: no pair's road: {}", refusal.message));
            None
        }
        Err(refusal) => {
            log.error(&format!("{shown}: {}", refusal.message));
            return EXIT_FAILURE;
        }
    };
    let iroh = match raced.iroh.map(|race| IrohRoad::new(race, trust, &log)).transpose() {
        Ok(iroh) => iroh,
        Err(why) => {
            log.error(&format!("{shown}: {why}"));
            return EXIT_FAILURE;
        }
    };
    // The channel of T-088, to the node that a ticket names, on whichever
    // road wins: the node has one key for each road.
    let expect = match (&iroh, &raced.derp) {
        (Some(iroh), _) => crate::channel::Expect::Ticket(iroh.node_key()),
        (None, Some(road)) => crate::channel::Expect::Ticket(road.ticket.node),
        (None, None) => crate::channel::Expect::Pinned(label.to_string()),
    };
    let say_line = |line: String| log.info(&format!("{shown}: {line}"));
    let channel = match ask.operator(expect, &say_line) {
        Ok(channel) => channel,
        Err(why) => {
            log.error(&format!("{shown}: {why}"));
            return EXIT_FAILURE;
        }
    };
    let derp = match &raced.derp {
        Some(road) => match super::derp::dialer(&road.ticket, &road.servers, trust, &log, &shown) {
            Ok(dialer) => Some((dialer, road.asked)),
            Err(why) => {
                log.error(&format!("{shown}: {why}"));
                return EXIT_FAILURE;
            }
        },
        None => None,
    };
    // A ticket that the user gave is kept under the label, for a later run
    // that names none (Q50).
    if let Some(road) = raced.derp.as_ref().filter(|road| road.asked) {
        match super::derp::keep(label, &road.ticket) {
            Ok(path) => log.verbose(&format!("{shown}: the DERP ticket is kept in {}", path.display())),
            Err(why) => log.verbose(&format!("{shown}: the DERP ticket could not be kept: {why}")),
        }
    }
    let proxy = ProxyChoice::FromEnvironment;
    let config = part.as_ref().map(|part| OperatorConfig {
        relay: &part.relay,
        name: &part.name,
        connect_token: part.connect_token(),
        trust,
        proxy: &proxy,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        limits: OperatorLimits::default(),
        wire: Wire::Tls,
    });
    let roads =
        Roads { iroh, pair: config.as_ref(), derp, label, legs: Mutex::new(None), pair_final: AtomicBool::new(false) };
    let (list, kinds) = roads.race(None);
    log.verbose(&format!("connecting to {shown}: {}", order(&kinds, &roads)));
    let first = match in_turn(list).await {
        Ok((won, took)) => winner(won, took, &kinds, &shown, &log),
        Err(lost) => {
            let refused = match &roads.iroh {
                Some(iroh) if iroh.refused().await => " (the node refused this client's key on the iroh road)",
                _ => "",
            };
            log.error(&format!("{shown}: no road reached the node: {}{refused}", lost_words(&kinds, &lost)));
            roads.close().await;
            return EXIT_FAILURE;
        }
    };
    // `podssh ssh` names `keep.v1`, for `~d` and `--attach` (T-158).
    let settings = layered::ssh_settings();
    let client = match Box::pin(client::start(first, Ask::New, settings, &mut OsEntropy)).await {
        Ok(client) => client,
        Err(e) => {
            log.error(&format!("{shown}: {e}"));
            roads.close().await;
            return EXIT_FAILURE;
        }
    };
    log.verbose(&format!("{shown}: {}", client.found()));
    layered::learn(client.found(), &opts.keep.offer);
    // The far end's silence, for a notice (T-302).
    let client = layered::heard(client, &opts.silence);
    let say = |line: Line| match line {
        Line::Always(text) => log.info(&format!("{shown}: {text}")),
        Line::Verbose(text) => log.verbose(&format!("{shown}: {text}")),
    };
    let (roads_ref, shown_ref, log_ref) = (&roads, &shown, &log);
    // Each resume races the roads again.
    let connect = |ended: &Ended| {
        let previous = if matches!(ended.end, End::Moving) { None } else { layered::lock(&roads_ref.legs).take() };
        async move {
            let (list, kinds) = roads_ref.race(previous);
            match in_turn(list).await {
                Ok((won, took)) => Next::Link(winner(won, took, &kinds, shown_ref, log_ref)),
                Err(lost) if roads_ref.ended_for_good().await => Next::Stop(lost_words(&kinds, &lost)),
                Err(lost) => Next::Retry(lost_words(&kinds, &lost)),
            }
        }
    };
    let note = |note: Note| {
        if !layered::folded(&note, Some(&opts.silence)) {
            say(layered::line_of(note));
        }
    };
    let (ssh_end, layer_end) = tokio::io::duplex(PIPE);
    let me = channel.as_ref().map(|c| c.identity.clone());
    let pin_say = {
        let (log, shown) = (log.clone(), shown.clone());
        move |line: String| log.info(&format!("{shown}: {line}"))
    };
    let (layer_app, session) = crate::channel::around(layer_end, channel, pin_say);
    let session = async move {
        match session {
            Some(session) => session.await.err(),
            None => None,
        }
    };
    let mut entropy = OsEntropy;
    let (code, outcome, failed) = tokio::join!(
        Box::pin(podssh_ssh::run(ssh_end, opts, None, log.clone())),
        Box::pin(resume::run(client, layer_app, connect, note, &mut entropy)),
        session
    );
    if let Some(path) = roads.iroh.as_ref().and_then(IrohRoad::path) {
        log.verbose(&format!("{shown}: the iroh road: {path}"));
    }
    if let Some((dialer, _)) = &roads.derp {
        if let Some(server) = dialer.server().await {
            log.verbose(&format!("{shown}: the DERP road's server: {server}"));
        }
    }
    if let Some((fault, why)) = failed.as_ref().and_then(|e| crate::channel::judged(e, me.as_deref())) {
        log.error(&format!("{shown}: {why}"));
        crate::ssh::result::channel_failed(&fault);
        let _ = layered::last(&roads.legs).await;
        roads.close().await;
        return EXIT_FAILURE;
    }
    if let (true, Some(why)) = (code == EXIT_FAILURE, layered::why_ended(outcome)) {
        log.error(&format!("{shown}: {why}"));
    }
    let _ = layered::last(&roads.legs).await;
    roads.close().await;
    code
}

/// The order of the roads, for `-v`.
fn order(kinds: &[Kind], roads: &Roads<'_>) -> String {
    let mut words = Vec::new();
    for (at, kind) in kinds.iter().enumerate() {
        let when = match (at, kind) {
            (0, _) => "first".to_string(),
            (_, Kind::Derp) if roads.derp.as_ref().is_some_and(|(_, asked)| !asked) => {
                "when each road before it failed (a kept ticket)".to_string()
            }
            _ => format!("{} ms after", HEAD_START.as_millis()),
        };
        words.push(format!("{} {when}", kind.name()));
    }
    words.join(", ")
}

/// Each road's reason, in the order of the race.
fn lost_words(kinds: &[Kind], lost: &[String]) -> String {
    let each: Vec<String> = kinds.iter().zip(lost).map(|(kind, why)| format!("{}: {why}", kind.name())).collect();
    each.join("; ")
}

/// The winner's link, with the bytes that the race read given back first,
/// and a line with `-v`.
fn winner(won: WonAt<Road>, took: Duration, kinds: &[Kind], shown: &str, log: &Log) -> client::Rewound<Road> {
    let road = kinds.get(won.at).map_or("a road", |kind| kind.name());
    log.verbose(&format!("{shown}: {road} answered first, in {} ms", took.as_millis()));
    won.link.rewound()
}
