//! The roads of a `node://NAME` destination beside its pair's (T-551), chosen
//! once for `podssh ssh` and for the copies, so that the two cannot drift:
//! the iroh road of a ticket, the DERP and OpenTunnel roads of a ticket or a
//! name given, of the net or kept, the transit relay, the Piping Server road
//! and the member's record of pkarr. With one of them, `ssh` races them with
//! the pair's ([`connect`]), and so does a copy (`cp`, `mv`, `scp`, `sftp`
//! and `edit`, [`reach`]), in the same order with the same delays: the race
//! of `super::roads` runs in a task of its own, which owns what the roads
//! borrow, and hands the layered stream to the copy, whose SSH runs on it as
//! on the first hop of any road. With none, the pair's road alone, and the
//! Piping Server road once it found the WebSocket upgrade refused on the way
//! (T-437, Q65), for both.

use std::sync::Arc;

use podssh_ssh::handshake::Flow;
use podssh_ssh::{Log, Options, EXIT_FAILURE};
use podssh_ws::url::WsUrl;
use podssh_ws::Trust;
use tokio::io::DuplexStream;
use tokio::sync::oneshot;

use super::iroh::RecordAsk;
use super::resolve::Transport;
use super::road_link::{Handed, Rider};
use super::roads::Raced;
use super::transport::{NotReached, Reached};
use crate::exitmap::sysexits;
use crate::layered::Shell;
use crate::relay_settings::Refusal;

/// The parts of a `node://NAME` destination with no carrier that its roads
/// take.
#[derive(Clone, Copy)]
pub(super) struct Dest<'a> {
    pub label: &'a str,
    pub pair_file: Option<&'a str>,
    pub trust: &'a Trust,
    /// The iroh road of `--iroh-ticket`, or of the net (T-164, T-429).
    pub race: Option<&'a super::iroh::Race>,
    pub derp: &'a super::derp::Race,
    pub opentunnel: &'a super::opentunnel::Race,
    pub channel: &'a crate::channel::Ask,
}

impl<'a> Dest<'a> {
    /// The node of `transport` with no carrier; `None` for another road.
    pub(super) fn of(transport: &'a Transport) -> Option<Dest<'a>> {
        let Transport::Node { label, pair_file, trust, race, derp, opentunnel, channel, carrier: None } = transport
        else {
            return None;
        };
        let (pair_file, race) = (pair_file.as_deref(), race.as_ref());
        Some(Dest { label, pair_file, trust, race, derp, opentunnel, channel })
    }
}

/// The roads of one run beside the pair's and the iroh ticket's, each its
/// own, so that a copy's task can own them.
struct Chosen {
    /// The member's record of pkarr, for each road that no ticket gave (T-445).
    record: Option<RecordAsk>,
    derp: Option<super::derp::Road>,
    opentunnel: Option<super::opentunnel::Road>,
    transit: Option<WsUrl>,
    piping: Option<crate::piping_road::Race>,
    /// Whether a member of the net with the relay role carries a leg to the
    /// node (T-434): a client with no pair here races those legs alone.
    members: bool,
}

impl Chosen {
    /// Whether a road races beside the pair's: else the pair's road alone.
    /// The Piping Server road that nobody asked for waits for its cue there.
    fn races(&self, dest: &Dest<'_>) -> bool {
        let piping_asked = self.piping.as_ref().is_some_and(|road| road.asked);
        let others =
            self.derp.is_some() || self.opentunnel.is_some() || self.transit.is_some() || self.record.is_some();
        dest.race.is_some() || others || piping_asked || self.members
    }
}

/// The roads of a run to the node of `dest` beside the pair's, each checked
/// before anything connects: a bad variable is refused (78).
fn chosen(dest: &Dest<'_>) -> Result<Chosen, Refusal> {
    let Dest { label, pair_file, trust, race, derp, opentunnel, channel } = *dest;
    // The member's record of pkarr, for each road that no ticket gave
    // (T-445): a bad variable of it is said before anything connects.
    let record = super::iroh::record_ask(label, race.is_some(), derp, channel)?;
    // The DERP road: the ticket given, else the one kept under the label
    // (Q50); never with --no-e2e, as its node's door is the channel.
    let derp = derp.road(label).filter(|_| !channel.off);
    // The OpenTunnel road (T-531): the name given, else the one kept under
    // the label (Q76); never with --no-e2e, as its node's door is the channel.
    let opentunnel = opentunnel.road(label).filter(|_| !channel.off);
    // The transit relay of the pair (T-436, Q65): never with --no-e2e,
    // and only with a good pair here, whose token it is; with none, the
    // pair's road says why, as before.
    let good_pair = || crate::pairs::operator_part(label, pair_file).is_ok();
    let transit = crate::node_transit::url().filter(|_| !channel.off && good_pair());
    // The Piping Server road (T-437): asked, or the fallback of Q65 once
    // the upgrade is refused; never with --no-e2e, as its server would
    // see each byte.
    let piping = crate::piping_road::race()?.filter(|_| !channel.off);
    // The legs at the net's relay members, never with --no-e2e, as the
    // member would see each byte (T-434).
    let members = !channel.off && super::roads::member::MemberRoads::new(label, trust).is_some();
    Ok(Chosen { record, derp, opentunnel, transit, piping, members })
}

/// SSH to the node of `dest`: over the race of its roads beside the pair's,
/// when one is given, kept or on; else over the pair's road
/// (`super::node::connect`).
pub(super) async fn run(dest: Dest<'_>, opts: &Options, log: Arc<Log>) -> i32 {
    let chosen = match chosen(&dest) {
        Ok(chosen) => chosen,
        Err(refusal) => {
            log.error(&refusal.message);
            return refusal.code;
        }
    };
    let Dest { label, pair_file, trust, race, channel, .. } = dest;
    if !chosen.races(&dest) {
        let piping = chosen.piping.as_ref();
        return Box::pin(super::node::connect(label, pair_file, trust, piping, channel, opts, log)).await;
    }
    let Chosen { record, derp, opentunnel, transit, piping, .. } = chosen;
    let raced = Raced { iroh: race, derp, opentunnel, transit, piping, record: record.as_ref() };
    Box::pin(connect(label, pair_file, trust, raced, channel, opts, log)).await
}

/// SSH to the node of the pair under `label`, over the first of its roads
/// that answers, again at each resume.
pub(super) async fn connect(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    raced: Raced<'_>,
    ask: &crate::channel::Ask,
    opts: &Options,
    log: Arc<Log>,
) -> i32 {
    // What the layer and the channel carry, for the line of a handshake that
    // does not finish (T-588); the far end's shells (T-158) and its silence
    // (T-302). SIGHUP and SIGTERM end the session with its `CLOSE`, as on
    // the pair's road alone; Ctrl-C stays the remote command's (T-586).
    let flow = Arc::new(Flow::default());
    let shell = Shell { offer: &opts.keep.offer, silence: &opts.silence, flow: Some(&flow) };
    let rider = Rider { shell: Some(shell), take: Some(crate::hangup::Which::Ends) };
    let (road_flow, ssh_log) = (&flow, log.clone());
    let ssh = move |handed: Result<Handed, NotReached>| async move {
        match handed {
            Ok(Handed { stream, channel }) => {
                let opts = super::node::on_the_road(opts, road_flow, channel);
                Some(Box::pin(podssh_ssh::run(stream, &opts, None, ssh_log)).await)
            }
            Err(not) => {
                for line in &not.lines {
                    ssh_log.error(line);
                }
                Some(EXIT_FAILURE)
            }
        }
    };
    let ridden = super::roads::ride(label, pair_file, trust, raced, ask, rider, log, ssh);
    Box::pin(ridden).await.unwrap_or(EXIT_FAILURE)
}

/// The stream to the node of `transport` for a copy (T-296, T-551): over the
/// race of its roads beside the pair's, when one is given, kept or on, in a
/// task that carries the session in the layer and races the roads again at
/// each resume; else over the pair's road alone (`super::node::reach`). When
/// the carriage fails, the task says why, and SSH sees its stream end.
pub(crate) async fn reach(transport: &Transport, log: &Arc<Log>) -> Result<Reached, NotReached> {
    let Some(dest) = Dest::of(transport) else {
        let why = "the roads of a node were asked for another destination".to_string();
        return Err(NotReached { lines: vec![why], code: sysexits::EX_SOFTWARE });
    };
    let refused = |refusal: Refusal| NotReached { lines: vec![refusal.message], code: refusal.code };
    let mut chosen = chosen(&dest).map_err(refused)?;
    let Dest { label, pair_file, trust, race, channel, .. } = dest;
    if !chosen.races(&dest) {
        match super::node::reach(label, pair_file, trust, channel, log).await {
            Ok(reached) => return Ok(reached),
            // The upgrade refused on the way: the Piping Server road, as
            // `podssh ssh` takes it then (T-437, Q65).
            Err((not, true)) if chosen.piping.is_some() => {
                for line in &not.lines {
                    log.verbose(&format!("{line}: the upgrade was refused on the way; the Piping Server road"));
                }
                chosen.piping = chosen.piping.map(|race| race.refused());
            }
            Err((not, _)) => return Err(not),
        }
    }
    let shown = super::node::shown(label, None);
    let (give, given) = oneshot::channel::<Result<DuplexStream, NotReached>>();
    let (ended, done) = oneshot::channel();
    let (label, pair_file, trust) = (label.to_string(), pair_file.map(str::to_string), trust.clone());
    let (race, ask, log) = (race.cloned(), channel.clone(), log.clone());
    // A copy's streams go below a terminal's on a shared iroh connection (T-666).
    tokio::spawn(super::iroh::as_bulk(async move {
        let Chosen { record, derp, opentunnel, transit, piping, .. } = chosen;
        let raced = Raced { iroh: race.as_ref(), derp, opentunnel, transit, piping, record: record.as_ref() };
        // The copy's SSH runs at the other end of the stream: no code here.
        let hand = move |handed: Result<Handed, NotReached>| {
            let _ = give.send(handed.map(|handed| handed.stream));
            std::future::ready(None)
        };
        let rider = Rider { shell: None, take: None };
        Box::pin(super::roads::ride(&label, pair_file.as_deref(), &trust, raced, &ask, rider, log, hand)).await;
        let _ = ended.send(());
    }));
    match given.await {
        Ok(Ok(stream)) => Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: Some(done) }),
        Ok(Err(not)) => Err(not),
        Err(_) => Err(NotReached {
            lines: vec![format!("{shown}: the task of the race ended before it handed its stream")],
            code: sysexits::EX_SOFTWARE,
        }),
    }
}

/// The roads of the node of `transport`, each timed to its far end's first
/// bytes, for `podssh ping node://NAME` (T-435): the roads that `ssh` races,
/// chosen as it chooses them, in its order with its delays, and the pair's
/// road with them also where `ssh` takes it alone; no session above them.
pub(crate) async fn measure(
    transport: &Transport,
    log: &Arc<Log>,
) -> Result<super::roads::probe::Measures, super::transport::NotReached> {
    let Some(dest) = Dest::of(transport) else {
        let why = "the roads of a node were asked for another destination".to_string();
        return Err(NotReached { lines: vec![why], code: sysexits::EX_SOFTWARE });
    };
    let chosen = chosen(&dest).map_err(|refusal| NotReached { lines: vec![refusal.message], code: refusal.code })?;
    let Dest { label, pair_file, trust, race, .. } = dest;
    let Chosen { record, derp, opentunnel, transit, piping, .. } = chosen;
    let raced = Raced { iroh: race, derp, opentunnel, transit, piping, record: record.as_ref() };
    super::roads::probe::measure(label, pair_file, trust, raced, log.clone()).await
}
