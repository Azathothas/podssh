//! `podssh ssh node://[user@]NAME` (T-084): SSH to the TCP service of a
//! pair's node, through the operator's leg of the reverse road. The
//! destination's host is `node://NAME`, so the messages and the known hosts
//! name the node so: a name that no DNS name can be. `node://NAME/ROUTE`
//! names a route of the node (T-089), and its own name in the known hosts.
//! `cp`, `scp` and `sftp` reach a node too (T-296), on the stream of
//! [`reach`]. With `--carrier ADDR`, the node's one road is a stream that
//! exists already (T-595, `super::carried`), whose session [`run_on`] runs.

use std::sync::Arc;

use podssh_relay::reverse::{operator, OperatorConfig, OperatorLimits, Outcome as LegOutcome, Wire};
use podssh_ssh::handshake::{Flow, Road};
use podssh_ssh::{Log, Options, EXIT_FAILURE};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::DuplexStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::exitmap::sysexits;
use crate::layered::{carry_keeping, carry_through, Line, Shell};
use crate::relay_settings::Refusal;

use super::args::SshArgs;
use super::resolve::{Env, Transport};
use super::transport::{NotReached, Reached};

/// The form of a node's destination.
pub const SCHEME: &str = "node://";

/// Each direction of the pipe between the SSH client and the leg.
const PIPE: usize = 256 * 1024;

/// A node that a destination names: its user, the label of its pair, and
/// the route of the node (T-089).
pub type Named = (Option<String>, String, Option<String>);

/// `node://[user@]NAME[/ROUTE]` as the user, NAME and the route; `None` for
/// each other destination. `node:NAME`, with no slashes, is a host named
/// `node`.
pub fn destination(text: &str) -> Result<Option<Named>, String> {
    // A member of the net by its name alone, as MagicDNS names one (T-429).
    let Some(rest) = text.strip_prefix(SCHEME) else {
        return Ok(crate::net::lookup::bare(text).map(|(u, n)| (u, n, None)));
    };
    let rest = rest.trim_end_matches('/');
    let (user, name) = match rest.rsplit_once('@') {
        Some((user, name)) if !user.is_empty() => (Some(user.to_string()), name),
        Some(_) => return Err(format!("{text:?}: empty user name")),
        None => (None, rest),
    };
    if name.is_empty() {
        return Err(format!("{text:?}: no NAME after {SCHEME}"));
    }
    if name.contains(':') {
        return Err(format!("{text:?}: a node has no port; NAME is the label of a pair"));
    }
    let (label, route) =
        crate::node::label_and_route(name).map_err(|refusal| format!("{text:?}: {}", refusal.message))?;
    Ok(Some((user, label, route)))
}

/// The name of a node, and of its route, in the messages and the known
/// hosts: `node://NAME`, or `node://NAME/ROUTE`.
pub fn shown(label: &str, route: Option<&str>) -> String {
    route.map_or_else(|| format!("{SCHEME}{label}"), |r| format!("{SCHEME}{label}/{r}"))
}

/// What a node can be reached with: the relay, alone, with no `-J`, `-W` or
/// `-p`, which T-084 leaves for later.
pub(super) struct Ask<'a> {
    pub label: &'a str,
    /// The route of the node (T-089).
    pub route: Option<&'a str>,
    pub args: &'a SshArgs,
    pub host_name: bool,
    pub port: bool,
    pub jumps: usize,
    pub family: Option<u8>,
    pub forward: bool,
}

/// The roads of a `node://NAME` destination, each checked before anything
/// connects: the iroh road's ticket, the DERP road's, the transit relay's
/// variable and OpenTunnel's name (T-531); then its transport. Apart from
/// `resolve.rs`, for the length of that file.
pub(super) fn resolved(r: &Ask<'_>, env: &Env) -> Result<Transport, Refusal> {
    let race = super::iroh::race(r.args, r.label)?;
    // The DERP road of the node (T-379): one node, one key for each road.
    let derp = super::derp::race(r.args)?;
    crate::node_transit::check()?; // PODSSH_TRANSIT (T-436), before anything connects
    let opentunnel = super::opentunnel::race(r.args)?;
    if let (Some(iroh), Some(ticket)) = (&race, &derp.ticket) {
        super::iroh::same_node(&iroh.ticket, ticket)?;
    }
    transport(r, env, race, derp, opentunnel).map_err(Refusal::from)
}

pub(super) fn transport(
    r: &Ask<'_>,
    env: &Env,
    race: Option<super::iroh::Race>,
    derp: super::derp::Race,
    opentunnel: super::opentunnel::Race,
) -> Result<Transport, String> {
    // A carrier is the node's one road (T-595): a flag of another road is
    // refused in its words first.
    super::carried::flags(r.args).map_err(|why| format!("{SCHEME}{}: {why}", r.label))?;
    let why = if r.args.direct {
        Some("--direct cannot reach a node: only the relay can")
    } else if r.jumps > 0 {
        Some("a node cannot be reached through a -J hop yet")
    } else if r.forward {
        Some("-W through a node is not implemented yet")
    } else if r.port {
        Some("a node has no port: its TARGET is set where the node runs")
    } else if r.host_name {
        Some("-o HostName cannot apply to a node")
    } else if r.family.is_some() {
        Some("-4 and -6 choose the family that the relay dials; a node dials its own TARGET")
    } else {
        None
    };
    if let Some(why) = why {
        return Err(format!("{SCHEME}{}: {why}", r.label));
    }
    let trust = match super::resolve::ca_file(r.args, env) {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    let channel = super::iroh::channel_ask(r.args)
        .and_then(|ask| ask.to_route(r.route))
        .map_err(|why| format!("{SCHEME}{}: {why}", r.label))?;
    // The DERP road's channel is the node's only door (T-379).
    if channel.off && opentunnel.name.is_some() {
        return Err(format!(
            "{SCHEME}{}: --no-e2e cannot go with --opentunnel-name: anyone may connect to a tunnel's name, so the \
             node lets in the key that the end-to-end channel proves",
            r.label
        ));
    }
    if channel.off && derp.ticket.is_some() {
        return Err(format!(
            "{SCHEME}{}: --no-e2e cannot go with --derp-ticket: the node of the DERP road lets in the key that the \
             end-to-end channel proves",
            r.label
        ));
    }
    let (label, pair_file, carrier) = (r.label.to_string(), r.args.pair_file.clone(), r.args.carrier.clone());
    Ok(Transport::Node { label, pair_file, trust, race, derp, opentunnel, channel, carrier })
}

/// SSH to the node of a `node://NAME` destination: over its carrier alone
/// (T-595); else over the race of its roads beside the pair's, when one is
/// given, kept or asked; else over the pair's road. None for another
/// destination. Apart from `super`'s `mod.rs`, for the length of that file.
pub(super) async fn run(transport: &Transport, opts: &Options, log: Arc<Log>) -> Option<i32> {
    let Transport::Node { label, pair_file, trust, race, derp, opentunnel, channel, carrier } = transport else {
        return None;
    };
    // A carrier is the node's one road: no other races it (T-595).
    if let Some(text) = carrier {
        return Some(Box::pin(super::carried::connect(label, text, channel, opts, log)).await);
    }
    // The member's record of pkarr, for each road that no ticket gave
    // (T-445): a bad variable of it is said before anything connects.
    let record = match super::iroh::record_ask(label, race.is_some(), derp, channel) {
        Ok(record) => record,
        Err(refusal) => {
            log.error(&refusal.message);
            return Some(refusal.code);
        }
    };
    // The DERP road: the ticket given, else the one kept under the label
    // (Q50); never with --no-e2e, as its node's door is the channel.
    let derp = derp.road(label).filter(|_| !channel.off);
    // The OpenTunnel road (T-531): the name given, else the one kept under
    // the label (Q76); never with --no-e2e, as its node's door is the channel.
    let opentunnel = opentunnel.road(label).filter(|_| !channel.off);
    // The transit relay of the pair (T-436, Q65): never with --no-e2e,
    // and only with a good pair here, whose token it is; with none, the
    // pair's road says why, as before.
    let good_pair = || crate::pairs::operator_part(label, pair_file.as_deref()).is_ok();
    let transit = crate::node_transit::url().filter(|_| !channel.off && good_pair());
    // The Piping Server road (T-437): asked, or the fallback of Q65 once
    // the upgrade is refused; never with --no-e2e, as its server would
    // see each byte.
    let piping = match crate::piping_road::race() {
        Ok(piping) => piping.filter(|_| !channel.off),
        Err(refusal) => {
            log.error(&refusal.message);
            return Some(refusal.code);
        }
    };
    let piping_asked = piping.as_ref().is_some_and(|road| road.asked);
    let others = derp.is_some() || opentunnel.is_some() || transit.is_some() || piping_asked || record.is_some();
    if race.is_some() || others {
        let record = record.as_ref();
        let raced = super::roads::Raced { iroh: race.as_ref(), derp, opentunnel, transit, piping, record };
        return Some(
            Box::pin(super::roads::connect(label, pair_file.as_deref(), trust, raced, channel, opts, log)).await,
        );
    }
    let piping = piping.as_ref();
    Some(Box::pin(connect(label, pair_file.as_deref(), trust, piping, channel, opts, log)).await)
}

/// SSH over the operator's leg to the node of the pair under `label`; over
/// the Piping Server road of `piping` when the leg's upgrade is refused on
/// the way (T-437, Q65).
pub(super) async fn connect(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    piping: Option<&crate::piping_road::Race>,
    ask: &crate::channel::Ask,
    opts: &podssh_ssh::options::Options,
    log: Arc<Log>,
) -> i32 {
    let shown = format!("{SCHEME}{label}");
    // The channel of T-088: this client's key, and the node's by the pins of
    // the label or by --node-key.
    let say_line = |line: String| log.info(&format!("{shown}: {line}"));
    let channel = match ask.operator(crate::channel::Expect::Pinned(label.to_string()), &say_line) {
        Ok(channel) => channel,
        Err(why) => {
            log.error(&format!("{shown}: {why}"));
            return EXIT_FAILURE;
        }
    };
    let part = match crate::pairs::operator_part(label, pair_file).and_then(|part| {
        crate::pairs::online()?;
        Ok(part)
    }) {
        Ok(part) => part,
        Err(refusal) => {
            log.error(&format!("{shown}: {}", refusal.message));
            return EXIT_FAILURE;
        }
    };
    let proxy = ProxyChoice::FromEnvironment;
    let config = OperatorConfig {
        relay: &part.relay,
        name: &part.name,
        connect_token: part.connect_token(),
        trust,
        proxy: &proxy,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        limits: OperatorLimits::default(),
        wire: Wire::Tls,
    };
    log.verbose(&format!("connecting to {shown} through the relay {}", part.relay.host));
    // SSH <-> the resumable layer <-> the operator's leg, a new leg after
    // each lost one when the node offers the layer (T-153).
    let (link_end, leg_end) = tokio::io::duplex(PIPE);
    let leg = match operator::start(&config, leg_end).await {
        Ok(leg) => leg,
        Err(e) => {
            let why = crate::pairs::connect_refusal(&e, label).message;
            if let Some(race) = piping.filter(|_| podssh_relay::piping::probe::upgrade_refused(&e)) {
                log.verbose(&format!("{shown}: {why}: the upgrade was refused on the way; the Piping Server road"));
                let piping = Some(race.refused());
                let raced = super::roads::Raced {
                    iroh: None,
                    derp: None,
                    opentunnel: None,
                    transit: None,
                    piping,
                    record: None,
                };
                return Box::pin(super::roads::connect(label, pair_file, trust, raced, ask, opts, log)).await;
            }
            log.error(&format!("{shown}: {why}"));
            podssh_ssh::outcome::failed("relay");
            return EXIT_FAILURE;
        }
    };
    let leg = Leg { config: &config, link_end, leg, expires_ms: Some(part.expires_ms) };
    run_on(leg, channel, opts, log, &shown, explain).await
}

/// The first leg of a session to a node, open: its legs' config, the pipe to
/// it, its task, and the pair's expiry when a pair carries it.
pub(super) struct Leg<'c> {
    pub config: &'c OperatorConfig<'c>,
    pub link_end: DuplexStream,
    pub leg: JoinHandle<LegOutcome>,
    pub expires_ms: Option<i64>,
}

/// SSH over the first leg, in the layer when the node offers it, a new leg
/// after each lost one; `explain` says what a leg's end failed. The pair's
/// road and a carrier's (T-595) run it, so that the two cannot drift.
pub(super) async fn run_on(
    first: Leg<'_>,
    channel: Option<crate::channel::Operator>,
    opts: &Options,
    log: Arc<Log>,
    shown: &str,
    explain: fn(&LegOutcome) -> Option<String>,
) -> i32 {
    let Leg { config, link_end, leg, expires_ms } = first;
    let say = |line: Line| match line {
        Line::Always(text) => log.info(&format!("{shown}: {text}")),
        Line::Verbose(text) => log.verbose(&format!("{shown}: {text}")),
    };
    // The SSH client and the layer in one task: when the client closes its
    // end, the layer sends `CLOSE`, and the last leg its Close.
    let pin_say = {
        let (log, shown) = (log.clone(), shown.to_string());
        move |line: String| log.info(&format!("{shown}: {line}"))
    };
    // The layer learns whether the far end keeps shells, before the SSH
    // login, for `~d` and `--attach` (T-158), tells the far end's silence for
    // a notice (T-302), and counts what it carries for the line of a
    // handshake that does not finish (T-588).
    let flow = Arc::new(Flow::default());
    let opts = &on_the_road(opts, &flow, channel.is_some());
    let shell = Some(Shell { offer: &opts.keep.offer, silence: &opts.silence, flow: Some(&flow) });
    // SIGHUP and SIGTERM end the session with its `CLOSE`, which the node
    // keeps nothing of; Ctrl-C stays the remote command's (T-586).
    crate::hangup::take(crate::hangup::Which::Ends);
    let (ssh_end, layer_end) = tokio::io::duplex(PIPE);
    let (code, carried) = tokio::join!(
        podssh_ssh::run(ssh_end, opts, None, log.clone()),
        carry_keeping(config, link_end, leg, layer_end, expires_ms, &say, channel, pin_say, shell)
    );
    // A refused key, or a changed node key, is the session's end whatever
    // the SSH client saw after it.
    if let Some((fault, why)) = &carried.channel {
        log.error(&format!("{shown}: {why}"));
        super::result::channel_failed(fault);
        return EXIT_FAILURE;
    }
    if code == EXIT_FAILURE {
        let why = carried.why.or_else(|| carried.leg.as_ref().and_then(explain));
        if let Some(why) = why {
            log.error(&format!("{shown}: {why}"));
        }
    }
    code
}

/// The stream to the node of the pair under `label`, for a copy (T-296): a
/// task carries it over the operator's leg, in the resumable layer when the
/// node offers it, a new leg after each lost one, as `connect` carries a
/// session, and SSH runs on it as on the first hop of any road. When the
/// carriage fails, the task says why, and SSH sees its stream end. A copy
/// names no iroh ticket: the pair's road is its only one.
pub async fn reach(
    label: &str,
    pair_file: Option<&str>,
    trust: &Trust,
    ask: &crate::channel::Ask,
    log: &Arc<Log>,
) -> Result<Reached, NotReached> {
    let shown = format!("{SCHEME}{label}");
    let refused =
        |refusal: Refusal| NotReached { lines: vec![format!("{shown}: {}", refusal.message)], code: refusal.code };
    // The pair, then the channel of T-088, as `pipe node:` takes them: a
    // copy that cannot go makes no key of this client.
    let part = crate::pairs::operator_part(label, pair_file)
        .and_then(|part| {
            crate::pairs::online()?;
            Ok(part)
        })
        .map_err(refused)?;
    let say_line = |line: String| log.info(&format!("{shown}: {line}"));
    let channel = ask
        .operator(crate::channel::Expect::Pinned(label.to_string()), &say_line)
        .map_err(|why| refused(Refusal::config(why)))?;
    log.verbose(&format!("connecting to {shown} through the relay {}", part.relay.host));
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (started, has_started) = oneshot::channel();
    let (ended, done) = oneshot::channel();
    let (task_label, task_shown, task_trust, task_log) = (label.to_string(), shown.clone(), trust.clone(), log.clone());
    tokio::spawn(async move {
        let proxy = ProxyChoice::FromEnvironment;
        let config = OperatorConfig {
            relay: &part.relay,
            name: &part.name,
            connect_token: part.connect_token(),
            trust: &task_trust,
            proxy: &proxy,
            timeout: podssh_relay::open::CONNECT_TIMEOUT,
            limits: OperatorLimits::default(),
            wire: Wire::Tls,
        };
        let (link, leg_end) = tokio::io::duplex(PIPE);
        let leg = match operator::start(&config, leg_end).await {
            Ok(leg) => {
                let _ = started.send(Ok(()));
                leg
            }
            Err(e) => {
                let _ = started.send(Err(crate::pairs::connect_refusal(&e, &task_label)));
                return;
            }
        };
        let say = |line: Line| match line {
            Line::Always(text) => task_log.info(&format!("{task_shown}: {text}")),
            Line::Verbose(text) => task_log.verbose(&format!("{task_shown}: {text}")),
        };
        let pin_say = {
            let (log, shown) = (task_log.clone(), task_shown.clone());
            move |line: String| log.info(&format!("{shown}: {line}"))
        };
        let carried = carry_through(&config, link, leg, theirs, Some(part.expires_ms), &say, channel, pin_say).await;
        // A clean end says nothing: the copy closed its connection.
        if let Some((_, why)) = crate::operator::judged(&task_label, &carried) {
            task_log.error(&format!("{task_shown}: {why}"));
        }
        let _ = ended.send(());
    });
    match has_started.await {
        Ok(Ok(())) => Ok(Reached { stream: Box::new(ours), relay: None, direct_proxy: None, layer: Some(done) }),
        Ok(Err(refusal)) => Err(refused(refusal)),
        Err(_) => Err(NotReached {
            lines: vec![format!("{shown}: the leg's task ended before it started")],
            code: sysexits::EX_SOFTWARE,
        }),
    }
}

/// `opts` with the node's road under its handshake (T-588): its far end, the
/// node's TARGET, what its layer carries into `flow`, and whether the
/// end-to-end channel runs above the layer.
pub(super) fn on_the_road(opts: &Options, flow: &Arc<Flow>, channel: bool) -> Options {
    let mut opts = opts.clone();
    let (far, end) = ("the node's TARGET".to_string(), "the node".to_string());
    opts.road = Some(Road { far, end, flow: flow.clone(), channel });
    opts
}

/// What the leg says of a session that failed; nothing for a normal end.
pub(super) fn explain(outcome: &LegOutcome) -> Option<String> {
    match outcome {
        LegOutcome::NeverReady { code: Some(code), reason } => {
            Some(format!("the node did not take the session (relay close {code}): {reason}"))
        }
        LegOutcome::NeverReady { code: None, reason } => Some(format!("the node did not take the session: {reason}")),
        LegOutcome::Ended { code: 1000, .. } | LegOutcome::LocalEnd => None,
        LegOutcome::Ended { code, reason } => Some(crate::pairs::session_end(*code, reason)),
    }
}
