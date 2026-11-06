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
//! A copy to the node races the same roads (T-551): [`ride`] runs the race
//! and the layer, and hands the layered stream to the SSH client of `podssh
//! ssh`, or to a copy's task (`super::node_roads`), whose SSH runs at its end.
//! [`probe`] times each road of the same race, with no session above it.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use podssh_relay::derp::Dialer;
use podssh_relay::reverse::{legs, OperatorConfig, OperatorLimits, Outcome as LegOutcome, Wire};
use podssh_relay::session::race::{in_turn, Start, HEAD_START};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{client, Ask, End, Ended, OsEntropy};
use podssh_ssh::{Log, EXIT_FAILURE};
use podssh_ws::{ProxyChoice, Trust};
use tokio::task::JoinHandle;

use super::iroh::IrohRoad;
use super::transport::NotReached;
use crate::exitmap::sysexits;
use crate::layered::{self, Line};

/// Each direction of the pipes between SSH, the layer and a leg.
const PIPE: usize = 256 * 1024;

use super::road_link::Kind;
pub use super::road_link::Road;
use super::road_link::{lost_words, order, winner, Handed, Rider, Unasked};

// The links of the pair's road and of the Piping Server road.
#[path = "road_pair.rs"]
mod pair_links;
use pair_links::{pair_link, piping_link};

// A member's relay role between two members (T-434).
#[path = "road_member.rs"]
pub(crate) mod member;

// Each road of the race timed for `podssh ping node://NAME` (T-435).
#[path = "road_probe.rs"]
pub(crate) mod probe;

/// The roads of a run beside the pair's: the iroh road of `--iroh-ticket`,
/// the DERP road of a ticket given or kept, the transit relay's, and the
/// Piping Server road.
pub(crate) struct Raced<'a> {
    pub iroh: Option<&'a super::iroh::Race>,
    pub derp: Option<super::derp::Road>,
    /// The OpenTunnel road of a name given or kept (T-531).
    pub opentunnel: Option<super::opentunnel::Road>,
    pub transit: Option<podssh_ws::url::WsUrl>,
    pub piping: Option<crate::piping_road::Race>,
    /// The member's record, for the roads that no ticket gave (T-445).
    pub record: Option<&'a super::iroh::RecordAsk>,
}

/// A road's attempt at a link: `Send`, as a copy races in a task (T-551).
pub(crate) type Going<'s> = Pin<Box<dyn Future<Output = Result<Road, String>> + Send + 's>>;

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
    /// The legs at the net's relay members (T-434).
    member: Option<member::MemberRoads>,
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
            list.push((start, Box::pin(async move { dialer.link().await.map(Road::Derp) })));
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
        if let Some(member) = &self.member {
            member.push(&mut list, &mut kinds);
        }
        if let Some(dialer) = &self.transit {
            // Q65's fallback: only when each road before it failed.
            list.push((Start::WhenAllFailed, Box::pin(async move { dialer.link().await.map(Road::Transit) })));
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

    /// The roads that race as fallbacks which nobody asked for, for `-v`.
    fn unasked(&self) -> Unasked {
        let unasked = |asked: Option<&bool>| asked == Some(&false);
        Unasked {
            derp: unasked(self.derp.as_ref().map(|(_, asked)| asked)),
            opentunnel: unasked(self.opentunnel.as_ref().map(|(_, asked)| asked)),
            piping: unasked(self.piping.as_ref().map(|(_, asked)| asked)),
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
        let others = self.opentunnel.is_some() || self.record.is_some() || self.member.is_some();
        if self.derp.is_some() || others || self.piping_on() {
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

/// The race of the node's roads, then the session in the layer over the
/// first that answered, again at each resume; `hand` takes the layered
/// stream in the place of SSH (T-551): the SSH client of `podssh ssh`, or a
/// copy's task, whose SSH runs at the stream's other end. A failure before
/// the layer is up goes to `hand` too, as its lines and its code. The code
/// of a ride here, or `None` for one elsewhere, whose each bad end of the
/// layer is said here.
#[allow(clippy::too_many_arguments)]
pub(super) async fn ride<F, R>(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    raced: Raced<'_>,
    ask: &crate::channel::Ask,
    rider: Rider<'_>,
    log: Arc<Log>,
    hand: F,
) -> Option<i32>
where
    F: FnOnce(Result<Handed, NotReached>) -> R,
    R: Future<Output = Option<i32>>,
{
    let shown = format!("{}{label}", super::node::SCHEME);
    let not_reached = |why: &str, code: i32| -> Result<Handed, NotReached> {
        Err(NotReached { lines: vec![format!("{shown}: {why}")], code })
    };
    if let Err(refusal) = crate::pairs::online() {
        return hand(not_reached(&refusal.message, refusal.code)).await;
    }
    // The legs at the net's relay members, which need no pair here (T-434).
    let member = member::MemberRoads::new(label, trust);
    // The pair's road, when this host has the pair; a node that the DERP
    // road, its record or a relay member reaches may have none here.
    let others = raced.opentunnel.is_some() || raced.record.is_some() || member.is_some();
    let part = match crate::pairs::operator_part(label, pair_file) {
        Ok(part) => Some(part),
        Err(refusal) if (raced.derp.is_some() || others) && pair_file.is_none() => {
            log.verbose(&format!("{shown}: no pair's road: {}", refusal.message));
            None
        }
        Err(refusal) => return hand(not_reached(&refusal.message, refusal.code)).await,
    };
    let iroh = match raced.iroh.map(|race| IrohRoad::new(race, trust, &log)).transpose() {
        Ok(iroh) => iroh,
        Err(why) => return hand(not_reached(&why, sysexits::EX_USAGE)).await,
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
        Err(why) => return hand(not_reached(&why, sysexits::EX_CONFIG)).await,
    };
    // Whether the channel runs above the layer, for SSH's line of a
    // handshake that does not finish (T-588).
    let channel_runs = channel.is_some();
    let member = member.map(|member| member.proving(channel.as_ref().map(|c| c.identity.clone())));
    let derp = match &raced.derp {
        Some(road) => match super::derp::dialer(&road.ticket, &road.servers, trust, &log, &shown) {
            Ok(dialer) => Some((dialer, road.asked)),
            Err(why) => return hand(not_reached(&why, sysexits::EX_CONFIG)).await,
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
    let roads =
        Roads { iroh, pair, derp, opentunnel, transit, piping, record, member, refused, label, legs, pair_final };
    let (list, kinds) = roads.race(None);
    log.verbose(&format!("connecting to {shown}: {}", order(&kinds, roads.unasked())));
    let first = match in_turn(list).await {
        Ok((won, took)) => winner(won, took, &kinds, &shown, &log),
        Err(lost) => {
            let refused = match &roads.iroh {
                Some(iroh) if iroh.refused().await => " (the node refused this client's key on the iroh road)",
                _ => "",
            };
            let why = format!("no road reached the node: {}{refused}", lost_words(&kinds, &lost));
            crate::net::reached::missed(label, &why);
            let code = hand(not_reached(&why, sysexits::EX_UNAVAILABLE)).await;
            roads.close().await;
            return code;
        }
    };
    // `podssh ssh` names `keep.v1`, for `~d` and `--attach` (T-158); a copy
    // keeps no shell. Each resume races the roads again, so a session that
    // the pair's road may carry keeps that road's window on each (T-443).
    let layer = if rider.shell.is_some() { layered::ssh_settings() } else { layered::settings() };
    let settings = if roads.pair.is_some() { layer } else { layer.off_the_pair() };
    let client = match Box::pin(client::start(first, Ask::New, settings, &mut OsEntropy)).await {
        Ok(client) => client,
        Err(e) => {
            let code = hand(not_reached(&e.to_string(), sysexits::EX_UNAVAILABLE)).await;
            roads.close().await;
            return code;
        }
    };
    log.verbose(&format!("{shown}: {}", client.found()));
    match crate::no_resume::heard(client.found()) {
        Some((true, line)) => log.info(&format!("{shown}: {line}")),
        Some((false, line)) => log.verbose(&format!("{shown}: {line}")),
        None => {}
    }
    // The far end's shells, and its silence for a notice (T-302).
    let client = match rider.shell {
        Some(shell) => {
            layered::learn(client.found(), shell.offer);
            layered::heard(client, shell.silence)
        }
        None => client,
    };
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
    let silence = rider.shell.map(|shell| shell.silence);
    let note = |note: Note| {
        if !layered::folded(&note, silence) {
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
    let layer_app = podssh_ssh::handshake::Counted::new(layer_app, rider.shell.and_then(|shell| shell.flow).cloned());
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
    // The signals that end the session with its `CLOSE`: those that `ssh`
    // takes here, or those that a copy's command took (T-586).
    let hangup = match rider.take {
        Some(which) => Some(crate::hangup::take(which)),
        None => crate::hangup::taken(),
    };
    let carried = async {
        let app = crate::hangup::ending(layer_app, hangup.as_ref());
        let mut layer = Box::pin(resume::run(client, app, connect, note, &mut entropy));
        let run = async {
            tokio::select! {
                outcome = &mut layer => outcome,
                () = layered::warn_of_expiry(expires_ms, &say) => layer.await,
            }
        };
        crate::hangup::bounded(hangup.as_ref(), run).await
    };
    let ridden = hand(Ok(Handed { stream: ssh_end, channel: channel_runs }));
    // The session's tokens of one leg (T-615), for its channel and its legs.
    let joined = async { tokio::join!(Box::pin(ridden), Box::pin(carried), session) };
    let (code, outcome, failed) = legs::during(joined).await;
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
        return Some(EXIT_FAILURE);
    }
    // A loss that --no-resume did not carry over (T-612).
    if let Some(line) = outcome.as_ref().and_then(crate::no_resume::ended) {
        log.info(&format!("{shown}: {line}"));
    }
    // A session cut after a signal says nothing more: its `CLOSE` went. A
    // copy's SSH gives no code here, so each bad end of the layer is said.
    let failing = code.is_none_or(|code| code == EXIT_FAILURE);
    if let (true, Some(why)) = (failing, outcome.and_then(layered::why_ended)) {
        log.error(&format!("{shown}: {why}"));
    }
    let _ = layered::last(&roads.legs).await;
    roads.close().await;
    code
}
