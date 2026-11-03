//! `podssh ssh node://NAME` over more roads than the pair's (T-164, T-379):
//! the iroh road of `--iroh-ticket` first, the pair's road 250 ms after,
//! then the DERP road of `--derp-ticket` 250 ms after that, each at once
//! when each road before it failed. A DERP ticket kept under NAME, which
//! the user did not give in this run, starts only when each road before it
//! failed: the fallback that the operator's ruling Q50 allows, which costs
//! tailcat's fleet nothing while the pair's road works; so does the transit
//! relay of the pair (T-436), last, by the operator's ruling Q65. The first far end
//! that speaks carries the session, and the other links end before they
//! send a byte, so they open nothing at the node's TARGET; each resume races
//! the roads again. A node with no pair here has its other roads alone. The
//! Piping Server road of the pair (T-437) comes 250 ms after the pair's when
//! PODSSH_PIPING asks for it; else, by the operator's ruling Q65, only when
//! each road before it failed and one found the WebSocket upgrade refused.
//! A member of the net races the roads of its record of pkarr too (T-445),
//! after the roads of its tickets and before the transit relay's. The
//! OpenTunnel road of `--opentunnel-name` (T-531) comes 250 ms after the DERP
//! road; a name kept under NAME, only when each road before it failed (Q76).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use podssh_relay::derp::Dialer;
use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome as LegOutcome, Wire};
use podssh_relay::session::race::{in_turn, Start, HEAD_START};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{client, Ask, End, Ended, OsEntropy};
use podssh_ssh::{Log, EXIT_FAILURE};
use podssh_ws::{ProxyChoice, Trust};
use tokio::task::JoinHandle;

use super::iroh::IrohRoad;
use crate::layered::{self, Line};

/// Each direction of the pipes between SSH, the layer and a leg.
const PIPE: usize = 256 * 1024;

use super::road_link::Kind;
pub use super::road_link::Road;
use super::road_link::{lost_words, winner};

/// The roads of a run beside the pair's: the iroh road of `--iroh-ticket`,
/// the DERP road of a ticket given or kept, the transit relay's, and the
/// Piping Server road.
pub(super) struct Raced<'a> {
    pub iroh: Option<&'a super::iroh::Race>,
    pub derp: Option<super::derp::Road>,
    /// The OpenTunnel road of a name given or kept (T-531).
    pub opentunnel: Option<super::opentunnel::Road>,
    pub transit: Option<podssh_ws::url::WsUrl>,
    pub piping: Option<crate::piping_road::Race>,
    /// The member's record, for the roads that no ticket gave (T-445).
    pub record: Option<&'a super::iroh::RecordAsk>,
}

/// A road's attempt at a link.
pub(crate) type Going<'s> = Pin<Box<dyn Future<Output = Result<Road, String>> + 's>>;

/// The roads of one run, each made once: the iroh road's endpoint, the
/// pair's legs, the DERP road's dialer.
struct Roads<'a> {
    iroh: Option<IrohRoad<'a>>,
    pair: Option<&'a OperatorConfig<'a>>,
    /// The DERP road's dialer, and whether the user gave its ticket.
    derp: Option<(Dialer, bool)>,
    /// The OpenTunnel road's dialer, and whether the user gave its name.
    opentunnel: Option<(podssh_relay::opentunnel::Dialer, bool)>,
    /// The transit relay's dialer, under the pair's token (T-436).
    transit: Option<podssh_relay::transit::Dialer>,
    /// The Piping Server road's dialer, and whether the user asked for it.
    piping: Option<(podssh_relay::piping::Dialer, bool)>,
    /// The roads of the member's record (T-445).
    record: Option<super::iroh::RecordRoads<'a>>,
    /// A road found the WebSocket upgrade refused on the way: the Piping
    /// Server road's cue, when the user did not ask for it (Q65).
    refused: AtomicBool,
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
        if let Some((dialer, asked)) = &self.opentunnel {
            // A kept name is Q76's fallback: only when each road before it failed.
            let start = if *asked { Start::After(HEAD_START) } else { Start::WhenAllFailed };
            list.push((start, Box::pin(async move { dialer.link().await.map(Road::OpenTunnel) })));
            kinds.push(Kind::OpenTunnel);
        }
        // The Piping Server road that the user asked for comes 250 ms after
        // the roads before it, so before the transit relay's, whose start
        // waits for each road before it to fail; unasked, it comes last, as
        // a proxy that refuses the upgrade refuses the transit relay's too.
        let piping_asked = self.piping.as_ref().is_some_and(|(_, asked)| *asked);
        if piping_asked {
            self.push_piping(&mut list, &mut kinds);
        }
        // The record's roads, once each road with a ticket failed (T-445).
        for (start, going, name) in self.record.iter().flat_map(|record| record.race()) {
            list.push((start, going));
            kinds.push(Kind::Record(name));
        }
        if let Some(dialer) = &self.transit {
            // Q65's fallback: only when each road before it failed.
            list.push((Start::WhenAllFailed, Box::pin(transit_link(dialer))));
            kinds.push(Kind::Transit);
        }
        if !piping_asked {
            self.push_piping(&mut list, &mut kinds);
        }
        (list, kinds)
    }

    /// The Piping Server road's place in the race, when it has a dialer.
    fn push_piping<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        if let Some((dialer, asked)) = &self.piping {
            // Unasked, the fallback: only when each road before it failed.
            let start = if *asked { Start::After(HEAD_START) } else { Start::WhenAllFailed };
            list.push((start, Box::pin(piping_link(dialer, *asked, &self.refused))));
            kinds.push(Kind::Piping);
        }
    }

    /// Whether the Piping Server road may be tried: asked, or cued.
    fn piping_on(&self) -> bool {
        self.piping.as_ref().is_some_and(|(_, asked)| *asked || self.refused.load(Ordering::SeqCst))
    }

    /// Whether no road can give a link again: the pair's ended for good or
    /// is not there, the iroh road's node refused this client or it is not
    /// there, and there is no DERP road or Piping Server road, whose node
    /// may come back.
    async fn ended_for_good(&self) -> bool {
        if self.derp.is_some() || self.opentunnel.is_some() || self.piping_on() || self.record.is_some() {
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
        if let Some((dialer, _)) = &self.piping {
            dialer.close().await;
        }
        if let Some(iroh) = &self.iroh {
            iroh.close().await;
        }
        if let Some(record) = &self.record {
            record.close().await;
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
            // A proxy's refusal of the upgrade is the Piping Server road's
            // cue, and no word of the relay's on the pair.
            if roads.piping.is_some() && podssh_relay::piping::probe::upgrade_refused(&e) {
                roads.refused.store(true, Ordering::SeqCst);
            } else if layered::is_final(&e) {
                roads.pair_final.store(true, Ordering::SeqCst);
            }
            Err(crate::pairs::connect_refusal(&e, roads.label).message)
        }
    }
}

async fn derp_link(dialer: &Dialer) -> Result<Road, String> {
    dialer.link().await.map(Road::Derp)
}

async fn transit_link(dialer: &podssh_relay::transit::Dialer) -> Result<Road, String> {
    dialer.link().await.map(Road::Transit)
}

/// A link of the Piping Server road: asked, or once a road found the
/// upgrade refused.
async fn piping_link(dialer: &podssh_relay::piping::Dialer, asked: bool, refused: &AtomicBool) -> Result<Road, String> {
    if !asked && !refused.load(Ordering::SeqCst) {
        return Err("not tried: no road found the WebSocket upgrade refused, and PODSSH_PIPING did not ask".into());
    }
    dialer.link().await.map(Road::Piping)
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
    // road or its record reaches may have none here.
    let part = match crate::pairs::operator_part(label, pair_file) {
        Ok(part) => Some(part),
        Err(refusal)
            if (raced.derp.is_some() || raced.opentunnel.is_some() || raced.record.is_some())
                && pair_file.is_none() =>
        {
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
        // A member of the net: the key that the net names, on each road (T-429).
        _ if crate::net::lookup::member(label).is_some() => crate::channel::Expect::Pinned(label.to_string()),
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
    // What the layer and the channel carry, for the line of a handshake that
    // does not finish (T-588).
    let flow = Arc::new(podssh_ssh::handshake::Flow::default());
    let opts = &super::node::on_the_road(opts, &flow, channel.is_some());
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
    // The OpenTunnel road's name, kept under the label when it was given (Q76).
    let opentunnel =
        raced.opentunnel.as_ref().map(|road| (super::opentunnel::dialer(road, label, trust, &log, &shown), road.asked));
    // The Piping Server road's paths come from the pair's secret (T-437).
    let piping = match (&raced.piping, &part) {
        (Some(race), Some(part)) => Some((crate::piping_road::dialer(part, race, trust, &log, &shown), race.asked)),
        _ => None,
    };
    let refused = AtomicBool::new(raced.piping.as_ref().is_some_and(|race| race.refused));
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
    // The transit relay's road: its token is the pair's, so it needs the pair.
    let transit = match (raced.transit, &part) {
        (Some(url), Some(part)) => crate::node_transit::dialer(url, part, trust, &log, &shown),
        _ => None,
    };
    let (legs, pair_final) = (Mutex::new(None), AtomicBool::new(false));
    let record = raced.record.map(|ask| super::iroh::RecordRoads::new(ask, trust, &log, &shown));
    let pair = config.as_ref();
    let roads = Roads { iroh, pair, derp, opentunnel, transit, piping, record, refused, label, legs, pair_final };
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
    // `podssh ssh` names `keep.v1`, for `~d` and `--attach` (T-158). Each
    // resume races the roads again, so a session that the pair's road may
    // carry keeps that road's window on each (T-443).
    let settings = if roads.pair.is_some() { layered::ssh_settings() } else { layered::ssh_settings().off_the_pair() };
    let client = match Box::pin(client::start(first, Ask::New, settings, &mut OsEntropy)).await {
        Ok(client) => client,
        Err(e) => {
            log.error(&format!("{shown}: {e}"));
            roads.close().await;
            return EXIT_FAILURE;
        }
    };
    log.verbose(&format!("{shown}: {}", client.found()));
    match crate::no_resume::heard(client.found()) {
        Some((true, line)) => log.info(&format!("{shown}: {line}")),
        Some((false, line)) => log.verbose(&format!("{shown}: {line}")),
        None => {}
    }
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
    let layer_app = podssh_ssh::handshake::Counted::new(layer_app, Some(flow.clone()));
    let session = async move {
        match session {
            Some(session) => session.await.err(),
            None => None,
        }
    };
    let mut entropy = OsEntropy;
    // A line an hour before the pair expires, as on the pair's road alone
    // (T-155): the transit road brings each run with a pair here (T-436).
    let expires_ms = part.as_ref().map(|part| part.expires_ms);
    // SIGHUP and SIGTERM end the session with its `CLOSE`, as on the pair's
    // road alone; Ctrl-C stays the remote command's (T-586).
    let hangup = crate::hangup::take(crate::hangup::Which::Ends);
    let carried = async {
        let app = crate::hangup::ending(layer_app, Some(&hangup));
        let mut layer = Box::pin(resume::run(client, app, connect, note, &mut entropy));
        let run = async {
            tokio::select! {
                outcome = &mut layer => outcome,
                () = layered::warn_of_expiry(expires_ms, &say) => layer.await,
            }
        };
        crate::hangup::bounded(Some(&hangup), run).await
    };
    let (code, outcome, failed) =
        tokio::join!(Box::pin(podssh_ssh::run(ssh_end, opts, None, log.clone())), Box::pin(carried), session);
    if let Some(path) = roads.iroh.as_ref().and_then(IrohRoad::path) {
        log.verbose(&format!("{shown}: the iroh road: {path}"));
    }
    if let Some((dialer, _)) = &roads.derp {
        if let Some(server) = dialer.server().await {
            log.verbose(&format!("{shown}: the DERP road's server: {server}"));
        }
    }
    if let Some(carried) = roads.record.as_ref().map(|record| record.carried()) {
        if let Some(line) = carried.await {
            log.verbose(&format!("{shown}: {line}"));
        }
    }
    if let Some((dialer, proto)) = roads.piping.as_ref().and_then(|(dialer, _)| Some((dialer, dialer.proto()?))) {
        let form = if dialer.numbered() { "numbered pieces" } else { "streamed ways" };
        log.verbose(&format!("{shown}: the Piping Server road: {} over {proto}, in {form}", dialer.server()));
    }
    if let Some((fault, why)) = failed.as_ref().and_then(|e| crate::channel::judged(e, me.as_deref())) {
        log.error(&format!("{shown}: {why}"));
        crate::ssh::result::channel_failed(&fault);
        let _ = layered::last(&roads.legs).await;
        roads.close().await;
        return EXIT_FAILURE;
    }
    // A loss that --no-resume did not carry over (T-612).
    if let Some(line) = outcome.as_ref().and_then(crate::no_resume::ended) {
        log.info(&format!("{shown}: {line}"));
    }
    // A session cut after a signal says nothing more: its `CLOSE` went.
    if let (true, Some(why)) = (code == EXIT_FAILURE, outcome.and_then(layered::why_ended)) {
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
            (_, Kind::Transit) => "when each road before it failed (Q65)".to_string(),
            (_, Kind::OpenTunnel) if roads.opentunnel.as_ref().is_some_and(|(_, asked)| !asked) => {
                "when each road before it failed (a kept name, Q76)".to_string()
            }
            (_, Kind::Record(_)) if !matches!(kinds[at - 1], Kind::Record(_)) => {
                "when each road before it failed (the node's record of pkarr, T-445)".to_string()
            }
            (_, Kind::Piping) if roads.piping.as_ref().is_some_and(|(_, asked)| !asked) => {
                "when each road before it failed and one found the WebSocket upgrade refused (Q65)".to_string()
            }
            _ => format!("{} ms after", HEAD_START.as_millis()),
        };
        words.push(format!("{} {when}", kind.name()));
    }
    words.join(", ")
}
