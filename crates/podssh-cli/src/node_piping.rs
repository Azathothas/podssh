//! The Piping Server road of `podssh node NAME TARGET` (T-437): the node of
//! the pair NAME waits at a door of a Piping Server, `https://ppng.io`
//! unless PODSSH_PIPING names another, on a path that the pair's secret
//! gives, so that a client of the pair reaches it with plain HTTPS where a
//! proxy refuses the WebSocket upgrade. Asked by PODSSH_PIPING, the node
//! serves it beside the pair's road, with one keeper for both, so that a
//! session resumes on either. Unasked (the operator's ruling Q65), once the
//! node of the pair's road checked TARGET (`crate::node`), a probe asks the
//! relay for the node's socket with no token: where something on the way
//! refuses the upgrade, the node serves this road alone, as the pair's road
//! cannot pass and a proxy's 403 must not read as a stopped pair, until the
//! pair expires; where the relay answers, the node is the pair's road's, as
//! before. A TARGET that fails its check so never costs the relay a
//! connection. Beside the pair's road, the
//! node waits at the transit relay of Q65 too (T-436, `node_transit`), as
//! the node of the pair's road does. The road needs the resumable layer and
//! the end-to-end channel, as the server would see each byte else. stdout
//! stays empty: the lines are on stderr.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::pair::Pair;
use podssh_relay::piping::probe::{self, Probe};
use podssh_relay::piping::{self, Secret, Server};
use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::{self, Layered, NodeConfig, TcpHandler, Wire};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::Settings;
use podssh_ws::{ProxyChoice, Trust};
use tokio::sync::watch;

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::piping_road::{self, Want, ENV};
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The bound of each step of the probe of the upgrade: short, as a relay
/// that does not answer leaves the node to the pair's road, which says so.
const PROBE_LIMIT: Duration = Duration::from_secs(5);

/// Why the road cannot go with these flags, when it cannot.
fn unfit(args: &NodeArgs) -> Option<&'static str> {
    if args.plain {
        Some("--plain carries the bytes with no resumable layer, which the road needs")
    } else if args.no_e2e {
        Some("--no-e2e turns the end-to-end channel off, and the Piping Server would see each byte")
    } else if args.targets.iter().any(|t| t.starts_with("udp:") || t.contains("=udp:")) {
        Some("a udp: TARGET goes on the pair's road: the Piping Server road carries TCP only")
    } else {
        None
    }
}

/// The node with the Piping Server road that `PODSSH_PIPING` asks for: the
/// process exit code. `None` when the road is not asked, as the node of the
/// pair's road decides on the unasked one once it checked TARGET
/// ([`unasked`]), and says each refusal.
pub fn run(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    let server = match piping_road::want() {
        Ok(Want::Off | Want::Unasked(_)) => return None,
        Ok(Want::Asked(server)) => server,
        Err(refusal) => return Some(refusal.report("node", err)),
    };
    if let Some(why) = unfit(args) {
        return Some(Refusal::usage(format!("{ENV} asks for the Piping Server road, but {why}")).report("node", err));
    }
    let label = args.name.clone()?;
    let (pair, stored) = match pair_of(args, &label) {
        Ok(found) => found,
        Err(refusal) => return Some(refusal.report("node", err)),
    };
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh node: could not start the async runtime: {e}");
            return Some(Fault::SessionFault.code());
        }
    };
    let ready = match prepare(args, label, pair, stored, trust) {
        Ok(ready) => ready,
        Err(refusal) => return Some(refusal.report("node", err)),
    };
    // A run of --restart beats from this runtime, while it polls (T-394).
    crate::detach::beat::keep(runtime.handle());
    // On the heap: Windows gives the main thread 1 MiB of stack.
    let code = runtime.block_on(Box::pin(serve(ready, server, None, None, err)));
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    Some(code)
}

/// The pair of the node, as the pair's road reads it, and whether it came
/// from the store; the pins of `--relay-addr` first, for the probe.
fn pair_of(args: &NodeArgs, label: &str) -> Result<(Pair, bool), Refusal> {
    crate::pairs::check_label(label)?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    let found = match &args.pair_file {
        Some(file) => (crate::pairs::usable(crate::pairs::from_file(file)?, label)?, false),
        None => (crate::pairs::stored(label)?, true),
    };
    crate::pairs::online()?;
    crate::node_transit::check()?; // PODSSH_TRANSIT (T-436), before anything connects
    Ok(found)
}

/// Each check of the node that needs no network, done.
pub(crate) struct Ready {
    pub label: String,
    pub pair: Pair,
    pub stored: bool,
    pub targets: Vec<Route>,
    pub roost: bool,
    pub key: podssh_relay::identity::file::Key,
    pub allow: Option<PathBuf>,
    pub trust: Trust,
}

/// The unasked road of a node of the pair's road whose TARGET passed its
/// check (Q65): the server, and why the probe found the upgrade refused on
/// the way; `None` when the relay answered, or no probe could tell, or the
/// road is off.
pub(crate) async fn unasked(pair: &Pair, trust: &Trust) -> Option<(Server, String)> {
    let Ok(Want::Unasked(server)) = piping_road::want() else { return None };
    let proxy = ProxyChoice::FromEnvironment;
    match probe::upgrade(&pair.relay, &pair.name, trust, &proxy, PROBE_LIMIT).await {
        Probe::Refused(why) => Some((server, why)),
        Probe::Passes | Probe::Unknown(_) => None,
    }
}

fn prepare(args: &NodeArgs, label: String, pair: Pair, stored: bool, trust: Trust) -> Result<Ready, Refusal> {
    let targets = crate::node::targets_of(&crate::node::words_of(args), false)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    // The key is made only once each check passed.
    let key = crate::channel::load_node_key(&place)?;
    crate::node_exit::ready(&label, &key.identity.public())?;
    Ok(Ready { label, pair, stored, targets, roost: args.sshd, key, allow: flags.allow, trust })
}

/// The settings of the layer on the road: the iroh road's features.
fn settings() -> Settings {
    Settings { features: piping::FEATURES, ..crate::layered::settings() }
}

/// Serve the road, and the pair's road too unless the upgrade was `refused`,
/// until Ctrl-C, or until both roads ended by themselves; `checked` is the
/// line of a TARGET that the caller checked already.
pub(crate) async fn serve(
    ready: Ready,
    server: Server,
    refused: Option<String>,
    checked: Option<String>,
    err: &mut dyn Write,
) -> i32 {
    let Ready { label, pair, stored, targets, roost, key, allow, trust } = ready;
    // TARGET first: a node that cannot reach it would serve no session.
    let target = match checked {
        Some(line) => line,
        None => match crate::node::probe(&targets, roost).await {
            Ok(versions) => crate::node::serving(&targets, &versions),
            Err(refusal) => return refusal.report("node", err),
        },
    };
    let say: piping::Say = {
        let label = label.clone();
        Arc::new(move |line: String| {
            podssh_ssh::err_line!("podssh node: {label}: {line}");
            crate::detach::on_line("node", &line);
        })
    };
    let roads = match &refused {
        Some(_) => format!("the Piping Server road through {server}"),
        None => format!("the pair's road through {} and the Piping Server road through {server}", pair.relay.host),
    };
    let (mode, expires) = (crate::node_flags::layer_mode(), crate::pairs::utc(pair.expires_ms));
    let _ = writeln!(
        err,
        "podssh node: {label}: serving {target} over {roads} {mode} until Ctrl-C; the pair expires {expires}"
    );
    if let Some(why) = &refused {
        let _ = writeln!(
            err,
            "podssh node: {label}: the WebSocket upgrade to {} was refused on the way ({why}); so the node serves the \
             Piping Server road alone, unasked, by the operator's ruling Q65 ({ENV}=no turns it off)",
            pair.relay.host
        );
    }
    // The channel of T-088 on both roads, with the node's key and its
    // allowlist: a session made on one road may resume on the other.
    // The net's members too (T-429), as on the other roads.
    let me = key.identity.public();
    let channel = crate::channel::node(&label, key, allow.clone(), err);
    let routes = crate::node::routes_of(&targets, crate::net::admit::grant(allow, Some(me)), roost, Some(me));
    let first = crate::node_exit::first(&targets);
    let (host, port) = (first.host, first.port);
    let handler = TcpHandler { host: host.clone(), port, timeout: DIAL_LIMIT, sshd: roost };
    let target = move || {
        let host = host.clone();
        async move { reverse::tcp::dial_target(&host, port, DIAL_LIMIT, roost).await }
    };
    let open = {
        let (channel, routes) = (Some(channel.clone()), routes.clone());
        move || {
            let (target, channel, routes) = (target.clone(), channel.clone(), routes.clone());
            async move { crate::channel::piped_by(channel, routes, target).await }
        }
    };
    let budget = reverse::layered::NODE_BUDGET;
    let keeper = Arc::new(Keeper::new(settings().resume_deadline));
    let secret = Arc::new(Secret::of_pair(&pair.name, pair.connect_token()));
    let left = Duration::from_millis(pair.expires_ms.saturating_sub(crate::pairs::now_ms()).max(0) as u64);
    let alone = refused.is_some();
    // The transit relay of Q65 beside the pair's road (T-436), with the
    // same keeper; not when the upgrade was refused, as its WebSocket is.
    let transit_open = open.clone();
    let transit = match (alone, crate::node_transit::url()) {
        (false, Some(url)) => crate::node_transit::road(&label, &pair, stored, &trust, url, say.clone()),
        _ => None,
    };
    let (stop, stopped) = watch::channel(false);
    let until_stopped = |mut stopped: watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    let door_road = async {
        let http = Arc::new(piping_road::http(&server, &trust));
        let node = piping::Node { secret, http, say: say.clone() };
        tokio::select! {
            () = Box::pin(piping::far::serve_kept(node, settings(), budget, open, keeper.clone())) => {}
            () = until_stopped(stopped.clone()) => {}
        }
    };
    let pair_road = async {
        if alone {
            return;
        }
        let say_pair = |line: String| (channel.say)(line);
        let proxy = ProxyChoice::FromEnvironment;
        let (repair, expiry) = crate::node_expiry::watch(&label, &pair, stored, channel.say.clone(), &trust);
        let mut config = NodeConfig {
            pair,
            label: stored.then(|| label.clone()),
            trust: &trust,
            proxy: &proxy,
            timeout: crate::pairs::REQUEST_LIMIT,
            settings: reverse::Settings {
                rejoin: crate::layered::settings().resume_deadline,
                ..reverse::Settings::default()
            },
            repair,
            wire: Wire::Tls,
            say: Some(&say_pair),
        };
        let piped = crate::channel::Piped { inner: Arc::new(handler), channel: Some(channel.clone()), routes };
        let layered = Layered::with_keeper(piped, crate::layered::settings(), budget, keeper.clone());
        let run = Box::pin(reverse::run(&mut config, Arc::new(layered), until_stopped(stopped.clone())));
        let exit = crate::node_transit::alongside(run, transit, transit_open, keeper.clone()).await;
        expiry.abort();
        if let Some((_, why)) = crate::node::ended(&label, exit) {
            (channel.say)(format!("the pair's road ended: {why}; the Piping Server road goes on"));
        }
    };
    // Alone, the road ends with its pair: a client's part of it expires too.
    let expired = async {
        if alone {
            tokio::time::sleep(left).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    let both = async { tokio::join!(door_road, pair_road) };
    tokio::pin!(both);
    tokio::select! {
        _ = &mut both => {}
        () = expired => {
            let _ = stop.send(true);
            both.await;
            let remedy = format!("make a new one with `podssh relay pair {label}`");
            let _ = writeln!(err, "podssh node: {label}: the pair expired; {remedy}");
            return Fault::PairExpired.code();
        }
        () = crate::node::stop_signal() => {
            let _ = stop.send(true);
            both.await;
        }
    }
    let _ = writeln!(err, "podssh node: {label}: stopped");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_road_needs_the_layer_the_channel_and_a_tcp_target() {
        let mut args =
            NodeArgs { name: Some("lab".into()), targets: vec!["127.0.0.1:22".into()], ..NodeArgs::default() };
        assert_eq!(unfit(&args), None);
        args.plain = true;
        assert!(unfit(&args).unwrap().contains("--plain"));
        args.plain = false;
        args.no_e2e = true;
        assert!(unfit(&args).unwrap().contains("--no-e2e"));
        args.no_e2e = false;
        args.targets = vec!["dns=udp:127.0.0.1:53".into()];
        assert!(unfit(&args).unwrap().contains("udp:"));
    }
}
