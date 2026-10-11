//! `podssh node NAME TARGET` (T-083): the node of the pair stored under the
//! label NAME, in front of the TCP service TARGET. Each session that an
//! operator opens is one connection to TARGET. `ROUTE=TARGET` offers a target
//! under a route (T-089), which an operator names in the end-to-end channel,
//! and the allowlist grants by key. The node runs until Ctrl-C or
//! SIGTERM (exit 0), or until the relay ends the pair. stdout stays empty:
//! a node has no answer to give. Each session runs the resumable layer
//! (T-153), or with `--plain` carries TARGET's bytes as they are (T-263).
//! With `--iroh`, the node serves the iroh road instead, with no pair
//! (T-163, `node_iroh`).

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::pair::Pair;
use podssh_relay::reverse::routes::{Route, Routed, Routes};
use podssh_relay::reverse::{self, E2e, Exit, Layered, NodeConfig, Settings, TcpHandler, Wire};
use podssh_ws::dial::ProxyChoice;
use podssh_ws::Trust;

use crate::exitmap::Fault;
use crate::pairs;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// What `podssh node` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeArgs {
    /// The label of a stored pair.
    pub name: Option<String>,
    /// Each TARGET: `HOST:PORT` or `[IPV6]:PORT`, and `ROUTE=TARGET` for a
    /// route (T-089).
    pub targets: Vec<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    /// A pair file to use in place of the store.
    pub pair_file: Option<String>,
    /// Each session's bytes as they are, with no resumable layer.
    pub plain: bool,
    /// Serve the iroh road, with no pair.
    pub iroh: bool,
    /// The node's key file, by its earlier name (T-163).
    pub iroh_key: Option<String>,
    /// The allowlist, by its earlier name (T-163).
    pub iroh_allow: Option<String>,
    /// A key for this run only, by its earlier name (T-163).
    pub iroh_ephemeral: bool,
    /// The node's key file, on each road (T-087).
    pub key: Option<String>,
    /// The operator keys that may come in, on each road (T-087).
    pub allow: Option<String>,
    /// A key for this run only.
    pub ephemeral_key: bool,
    /// No end-to-end channel (T-088).
    pub no_e2e: bool,
    /// The iroh relays, in place of the variable and the table.
    pub iroh_relay: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// Run the verb; returns the process exit code.
pub fn run_node(args: &NodeArgs, err: &mut dyn Write) -> i32 {
    // The key and the allowlist serve each road (T-087); the relays are the
    // iroh road's alone.
    if args.iroh_relay.is_some() && !args.iroh {
        return Refusal::usage("--iroh-relay is for the iroh road: add --iroh").report("node", err);
    }
    if args.plain && args.iroh {
        let why = "--plain is for the pair's road: the iroh road always runs the resumable layer";
        return Refusal::usage(why.to_string()).report("node", err);
    }
    if args.iroh {
        return iroh(args, err);
    }
    let ready = match prepare(args) {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report("node", err),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh node: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    let code = runtime.block_on(serve(ready, err));
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    code
}

/// Each check that needs no network, in order: the arguments, the pins, the
/// pair.
struct Ready {
    label: String,
    pair: Pair,
    /// Whether the pair came from the store, whose copy goes when the relay
    /// says that the pair was stopped.
    stored: bool,
    targets: Vec<Route>,
    trust: Trust,
    plain: bool,
    /// The node's key, for the end-to-end channel; `None` with `--no-e2e`.
    key: Option<podssh_relay::identity::file::Key>,
    allow: Option<PathBuf>,
}

/// The node's key and allowlist, by their names of T-087 or of T-163.
pub(crate) struct KeyFlags {
    pub key: Option<String>,
    pub ephemeral: bool,
    pub allow: Option<PathBuf>,
}

/// The flags of the node's key and allowlist; each by one of its two names.
pub(crate) fn key_flags(args: &NodeArgs) -> Result<KeyFlags, Refusal> {
    let both = |a: &str, b: &str| Refusal::usage(format!("{a} and {b} are one flag by two names: give one"));
    if args.key.is_some() && args.iroh_key.is_some() {
        return Err(both("--key", "--iroh-key"));
    }
    if args.allow.is_some() && args.iroh_allow.is_some() {
        return Err(both("--allow", "--iroh-allow"));
    }
    Ok(KeyFlags {
        key: args.key.clone().or_else(|| args.iroh_key.clone()),
        ephemeral: args.ephemeral_key || args.iroh_ephemeral,
        allow: args.allow.as_ref().or(args.iroh_allow.as_ref()).map(PathBuf::from),
    })
}

fn prepare(args: &NodeArgs) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the label of a pair (podssh relay pair NAME)")?;
    pairs::check_label(&label)?;
    let targets = targets_of(&args.targets, args.no_e2e)?;
    // The channel's flags are usage errors, said before anything is read.
    let flags = key_flags(args)?;
    if args.no_e2e && (flags.key.is_some() || flags.ephemeral || flags.allow.is_some()) {
        return Err(Refusal::usage(
            "--key, --ephemeral-key and --allow are the node's side of the end-to-end channel, which --no-e2e turns off",
        ));
    }
    let place = match args.no_e2e {
        true => None,
        false => Some(crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?),
    };
    crate::pins::apply(args.relay_addr.as_deref())?;
    let (pair, stored) = match &args.pair_file {
        Some(file) => (pairs::usable(pairs::from_file(file)?, &label)?, false),
        None => (pairs::stored(&label)?, true),
    };
    pairs::online()?;
    let trust = pairs::trust(args.ca_file.as_deref());
    // The key is made only once the node goes online.
    let key = match place {
        Some(place) => Some(crate::channel::load_node_key(&place)?),
        None => None,
    };
    Ok(Ready { label, pair, stored, targets, trust, plain: args.plain, key, allow: flags.allow })
}

/// The targets of the command line (T-089): `TARGET`, which an operator
/// that names no route reaches, and `ROUTE=TARGET` for each route; at most
/// one with no route, each route once. A route travels in the end-to-end
/// channel, so `--no-e2e` offers none.
pub(crate) fn targets_of(words: &[String], no_e2e: bool) -> Result<Vec<Route>, Refusal> {
    if words.is_empty() {
        return Err("missing TARGET: the HOST:PORT that each session reaches, or ROUTE=HOST:PORT".into());
    }
    let mut targets: Vec<Route> = Vec::new();
    for word in words {
        let (name, target) = match word.split_once('=') {
            Some((route, target)) => {
                podssh_ws::names::check_node_name(route).map_err(|_| {
                    Refusal::usage(format!(
                        "{word}: {route:?} is not a route: letters, digits, '.', '-' and '_', not first '-' or '.'"
                    ))
                })?;
                (Some(route.to_string()), target)
            }
            None => (None, word.as_str()),
        };
        let (host, port) = crate::proxy::parse_target(Some(target), None)
            .map_err(|why| Refusal::usage(format!("TARGET {word}: {why}")))?;
        if targets.iter().any(|t| t.name == name) {
            return Err(Refusal::usage(match &name {
                Some(route) => format!("the route {route} is given twice"),
                None => "two TARGETs with no route: give each one but one a ROUTE=".to_string(),
            }));
        }
        targets.push(Route { name, host, port });
    }
    if no_e2e && targets.iter().any(|t| t.name.is_some()) {
        return Err(Refusal::usage("a route travels in the end-to-end channel, which --no-e2e turns off"));
    }
    Ok(targets)
}

/// `NAME/ROUTE` as the label of a pair and the route of its node (T-089).
pub(crate) fn label_and_route(text: &str) -> Result<(String, Option<String>), Refusal> {
    let (label, route) = match text.split_once('/') {
        Some((label, route)) => (label, Some(route)),
        None => (text, None),
    };
    pairs::check_label(label)?;
    if let Some(route) = route {
        podssh_ws::names::check_node_name(route).map_err(|_| {
            Refusal::usage(format!(
                "{text}: {route:?} is not a route: letters, digits, '.', '-' and '_', not first '-' or '.'"
            ))
        })?;
    }
    Ok((label.to_string(), route.map(str::to_string)))
}

/// The targets as the first line says them.
pub(crate) fn shown(targets: &[Route]) -> String {
    let each = targets.iter().map(|t| {
        let at = podssh_ws::dial::authority(&t.host, t.port);
        t.name.as_ref().map_or(at.clone(), |route| format!("{route}={at}"))
    });
    each.collect::<Vec<_>>().join(", ")
}

/// Each target, dialled once: a node that cannot reach one would refuse its
/// sessions, so it does not start (69).
pub(crate) async fn probe(targets: &[Route]) -> Result<(), Refusal> {
    let proxy = ProxyChoice::FromEnvironment;
    for t in targets {
        if let Err(e) = podssh_ws::dial::dial(&t.host, t.port, &proxy, DIAL_LIMIT).await {
            let shown = shown(std::slice::from_ref(t));
            return Err(Refusal { message: format!("TARGET {shown}: {e}"), code: Fault::RelayUnreachable.code() });
        }
    }
    Ok(())
}

/// The routes of a node, when it has one, with who may use each.
pub(crate) fn routes_of(targets: &[Route], allow: Option<PathBuf>) -> Option<Routes> {
    targets.iter().any(|t| t.name.is_some()).then(|| Routes {
        routes: Arc::new(targets.to_vec()),
        grant: crate::channel::grant_of(allow),
        timeout: DIAL_LIMIT,
    })
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, pair, stored, targets, trust, plain, key, allow } = ready;
    let target = shown(&targets);
    let proxy = ProxyChoice::FromEnvironment;
    // TARGET first: a node that cannot reach it would serve no session.
    if let Err(refusal) = probe(&targets).await {
        return refusal.report("node", err);
    }
    let routes = routes_of(&targets, allow.clone());
    let mode = if plain { "in plain mode, with no resumable layer" } else { "with the resumable layer" };
    let _ = writeln!(
        err,
        "podssh node: {label}: serving {target} through {} {mode} until Ctrl-C; the pair expires {}",
        pair.relay.host,
        pairs::utc(pair.expires_ms)
    );
    // The channel of T-088: the node's key and who may come in, said now.
    let channel = match key {
        Some(key) => Some(crate::channel::node(&label, key, allow, err)),
        None => {
            let _ = writeln!(err, "podssh node: {label}: no end-to-end channel (--no-e2e): the relay sees each byte");
            None
        }
    };
    // As the operator's lines, written from inside the node as they come.
    let say = |line: String| eprintln!("podssh node: {label}: {line}");
    let mut config = NodeConfig {
        pair,
        label: stored.then(|| label.clone()),
        trust: &trust,
        proxy: &proxy,
        timeout: pairs::REQUEST_LIMIT,
        // A lost socket is taken again for as long as the layer keeps a
        // session (T-261).
        settings: Settings { rejoin: crate::layered::settings().resume_deadline, ..Settings::default() },
        repair: None,
        wire: Wire::Tls,
        say: Some(&say),
    };
    let first = &targets[0];
    let tcp = TcpHandler { host: first.host.clone(), port: first.port, timeout: DIAL_LIMIT };
    let (settings, budget) = (crate::layered::settings(), reverse::layered::NODE_BUDGET);
    // TARGET at `open` with no layer: an operator that does not speak the
    // layer can use the node, and a lost leg ends the session. With the
    // layer (T-153), a client that loses its leg resumes the session on a
    // new one, with the same connection to TARGET, dialled only after the
    // layer's handshake. The channel (T-088) runs above the layer, and
    // reaches TARGET only once the operator's key is let in.
    let exit = match (plain, channel, routes) {
        // Routes (T-089): the target of the route that each operator named.
        (true, Some(node), Some(routes)) => {
            Box::pin(reverse::run(&mut config, Arc::new(Routed::new(routes, node)), stop_signal())).await
        }
        (false, Some(node), Some(routes)) => {
            let handler = Arc::new(Layered::new(Routed::new(routes, node), settings, budget));
            Box::pin(reverse::run(&mut config, handler, stop_signal())).await
        }
        (true, None, _) => Box::pin(reverse::run(&mut config, Arc::new(tcp), stop_signal())).await,
        (true, Some(node), None) => {
            Box::pin(reverse::run(&mut config, Arc::new(E2e::new(tcp, node)), stop_signal())).await
        }
        (false, None, _) => {
            let handler = Arc::new(Layered::new(tcp, settings, budget));
            Box::pin(reverse::run(&mut config, handler, stop_signal())).await
        }
        (false, Some(node), None) => {
            let handler = Arc::new(Layered::new(E2e::new(tcp, node), settings, budget));
            Box::pin(reverse::run(&mut config, handler, stop_signal())).await
        }
    };
    finish(&label, exit, err)
}

/// The exit code for each end of a node, by the table of `exitmap`, and what
/// to do next.
fn finish(label: &str, exit: Exit, err: &mut dyn Write) -> i32 {
    let Some((fault, why)) = ended(label, exit) else {
        let _ = writeln!(err, "podssh node: {label}: stopped");
        return 0;
    };
    let _ = writeln!(err, "podssh node: {label}: {why}");
    fault.code()
}

/// The fault and the words for an end of the pair's road; none when it
/// was stopped.
pub(crate) fn ended(label: &str, exit: Exit) -> Option<(Fault, String)> {
    let remedy = format!("make a new pair with `podssh relay pair {label}`");
    let (fault, why) = match exit {
        Exit::Stopped => return None,
        Exit::NameInUse => (
            Fault::RelayUnreachable,
            "another node serves this pair (409), or the relay held this node's lost socket for too long; a pair \
             has one node at a time"
                .to_string(),
        ),
        Exit::PairStopped => (Fault::Revoked, format!("the pair was stopped on the relay; {remedy}")),
        Exit::PairExpired => (Fault::PairExpired, format!("the pair expired; {remedy}")),
        Exit::Forbidden => {
            (Fault::Auth, format!("the relay refused the pair (403): it was stopped, or its token is wrong; {remedy}"))
        }
        Exit::Fault(close) => (
            Fault::SessionFault,
            format!("the relay closed the node for a fault of this node: {} {}", close.code, close.reason),
        ),
        Exit::Unusable(why) => (Fault::Config, why),
    };
    Some((fault, why))
}

/// The node over the iroh road.
#[cfg(feature = "iroh")]
fn iroh(args: &NodeArgs, err: &mut dyn Write) -> i32 {
    crate::node_iroh::run(args, err)
}

/// The iroh road is not in this build: the refusal names the feature, before
/// anything is read or connects.
#[cfg(not(feature = "iroh"))]
fn iroh(_: &NodeArgs, err: &mut dyn Write) -> i32 {
    let _ = writeln!(err, "podssh node: {}", crate::ssh::iroh::not_built("--iroh"));
    crate::exit_codes::EXIT_NOT_IMPLEMENTED
}

/// Ctrl-C, or SIGTERM on Unix. When no signal can be watched, the node runs
/// until the relay ends it, and does not stop at once.
pub(crate) async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                stopped = tokio::signal::ctrl_c() => {
                    if stopped.is_err() {
                        term.recv().await;
                    }
                }
                _ = term.recv() => {}
            }
            return;
        }
    }
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
