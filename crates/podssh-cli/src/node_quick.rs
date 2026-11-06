//! `podssh node NAME TARGET --quick-tunnel` (T-300): the node in front of
//! the TCP service TARGET at `https://NAME.trycloudflare.com`, a quick
//! tunnel of Cloudflare's that podssh makes itself, with no `cloudflared`,
//! no pair and no account (`podssh_relay::quick`). The name is new each run,
//! and the one line on stdout. A visitor's WebSocket through the name is one
//! link of the resumable layer, with the end-to-end channel above it: the
//! name is public, so only an operator whose key is in the file of `--allow`,
//! or with no `--allow` a member of the net that names the node's key
//! (T-550), reaches TARGET, which is dialled only after the layer's handshake. The
//! node races its roads to port 7844 of Cloudflare's edge (T-400): QUIC
//! where no proxy is set and UDP answers a probe, as cloudflared does
//! (T-301), HTTP/2 on TCP, directly or through a proxy that allows it, and
//! HTTP/2 inside WARP's tunnel (T-374, `crate::node_warp`), first with
//! `--warp`; each starts 2 s after the one before, or at once when it
//! failed, and the first that registers is kept. It keeps two connections,
//! the second to the edge's other region first, and on the edge's GOAWAY it
//! connects again at once while the old connection drains (T-402). A lost
//! connection to the edge is made again, with the same name, until Ctrl-C.
//! With `--relay`, the node is its owner's relay too, behind the tunnel and
//! with no listener (T-428, `crate::node_quick_relay`), and TARGET may be
//! left out. With `--exit` (T-459), its sessions go through the routes of an
//! exit as on each other road (`crate::node_exit`): a member's word names a
//! target of its own, and TARGET may be left out too.
//! In a build with the iroh road, the node's record of pkarr names the
//! tunnel, at n0's server unless `PODSSH_IROH_PKARR` names another or `off`
//! (Q81), for a client with the node's key alone (T-445, `node_record`).
//! At SIGUSR2 it hands its sessions to the binary that takes its place, as
//! the pair's road's node does (T-679, `node_upgrade`), and its tunnel with
//! them (`kept_tunnel`): the new binary registers the same name again. A
//! node with `--relay` takes no upgrade in place, as the role's tokens and
//! pairs live in its process.

#[path = "node_quick_kept.rs"]
mod kept_tunnel;

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::identity::file;
use podssh_relay::quick::keep::{self, Gone, Keep, Made, Plan, Roads, Say};
use podssh_relay::quick::origin::Visitors;
use podssh_relay::quick::register::Connector;
use podssh_relay::quick::roads::{self, Link, Road};
use podssh_relay::quick::{api, edge};
use podssh_relay::reverse::framing::SessionId;
use podssh_relay::reverse::routes::{Route, Routed};
use podssh_relay::reverse::{self, E2e, Handler, Layered, TcpHandler};
use podssh_ws::ProxyChoice;
use tokio::io::DuplexStream;
use tokio::sync::{watch, Mutex};

use crate::exitmap::{sysexits, Fault};
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::node_quick_relay::Role;
use crate::node_warp::WarpRoad;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The connections that the node keeps to the edge at once, each to its own
/// region first: with two, a region in trouble or a GOAWAY leaves one
/// standing while the other registers again (T-414). Rule 2 of AGENTS.md
/// allows this second connection for the quick tunnel's node alone (Q62,
/// 2026-11-01). The drain of T-402 holds on each: an old connection serves
/// its streams while the next one registers, for 90 s at most.
pub(crate) const CONNECTIONS: u8 = 2;

/// Each check that needs no network, done.
struct Ready {
    label: String,
    targets: Vec<Route>,
    key: file::Key,
    /// Who comes in: the keys of `--allow`, else the net's members (T-550).
    door: Door,
    sshd: bool,
    /// The edge inside WARP's tunnel first (`--warp`).
    warp: bool,
    /// The relay role behind the tunnel (`--relay`).
    relay: Option<Role>,
    /// The server of its record: n0's, or the one of PODSSH_IROH_PKARR (T-445, Q81).
    record: Option<crate::node_record::Named>,
}

/// Run the node; returns the process exit code.
pub fn run(args: &NodeArgs, err: &mut dyn Write) -> i32 {
    let ready = match prepare(args) {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report("node", err),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh node: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    // A run of --restart beats from this runtime, while it polls (T-394).
    crate::detach::beat::keep(runtime.handle());
    let mut code = runtime.block_on(Box::pin(serve_quick(ready, err)));
    // An upgrade whose binary did not start, or a tunnel of the binary before
    // this one that the edge refused: the node serves again (T-679).
    while code == crate::node_upgrade::AGAIN {
        code = match prepare(args) {
            Ok(ready) => runtime.block_on(Box::pin(serve_quick(ready, err))),
            Err(refusal) => refusal.report("node", err),
        };
    }
    runtime.shutdown_background();
    code
}

fn prepare(args: &NodeArgs) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    let alone = [
        (args.iroh, "--iroh"),
        (args.plain, "--plain"),
        (args.no_e2e, "--no-e2e"),
        (args.pair_file.is_some(), "--pair-file"),
        (args.iroh_relay.is_some(), "--iroh-relay"),
        (args.derp, "--derp"),
        (args.derp_server.is_some(), "--derp-server"),
        (args.opentunnel, "--opentunnel"),
    ];
    if let Some((_, flag)) = alone.iter().find(|(given, _)| *given) {
        return Err(Refusal::usage(format!(
            "{flag} is not for --quick-tunnel, which runs the resumable layer and the end-to-end channel, with no pair"
        )));
    }
    if args.warp && !cfg!(feature = "warp") {
        let message = crate::ssh::cloud::warp::not_built("--warp");
        return Err(Refusal { message, code: crate::exit_codes::EXIT_NOT_IMPLEMENTED });
    }
    if args.targets.iter().any(|t| t.starts_with("udp:")) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: a quick tunnel carries TCP only"));
    }
    // With --relay and no TARGET, the node is the relay alone (T-428); with
    // --exit and none, the exit alone (T-459).
    let words = crate::node::words_of(args);
    let targets = match words.is_empty() && (args.relay || args.exit) {
        true => Vec::new(),
        false => crate::node::targets_of(&words, false)?,
    };
    if targets.len() > 1 || targets.first().is_some_and(|t| t.name.is_some()) {
        return Err(Refusal::usage("--quick-tunnel serves one TARGET, with no route"));
    }
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    // Its name is public: `--allow`, else the net that names its key, as
    // the DERP road's door (T-550); with neither, no one could come in.
    let why_open = "its name is public, so anyone may reach it";
    let door = crate::node_derp::door_of("--quick-tunnel", why_open, flags.allow.as_deref(), &place)?;
    crate::node_quick_relay::precheck(args, &door)?;
    crate::pairs::online()?;
    let record = crate::node_record::named()?;
    // One for this run only stays across an upgrade in place (T-679).
    let key = crate::node_upgrade::parts::node_key(&place)?;
    // An exit says its net, or why it cannot be one, before it connects (T-431).
    crate::node_exit::ready(&label, &key.identity.public())?;
    // After the key: the net's `relay:NAME` names the node by it (T-455).
    let relay = crate::node_quick_relay::role(args, &label, &door, key.identity.public())?;
    Ok(Ready { label, targets, key, door, sshd: args.sshd, warp: args.warp, relay, record })
}

/// The node's end of the channel, by its door: the keys of `--allow` and
/// the net's members, or the members alone, also when the node leaves the
/// net: a key that no list names is never let in on a public name.
fn channel_of(label: &str, key: file::Key, door: Door, err: &mut dyn Write) -> podssh_relay::e2e::ends::Node {
    match door {
        Door::Allow(path) => crate::channel::node(label, key, Some(path), err),
        Door::Net(_) => {
            let me = key.identity.public();
            let _ = writeln!(err, "podssh node: {label}: key {me}");
            if let Some(line) = crate::net::admit::line(&me) {
                let _ = writeln!(err, "podssh node: {label}: {line}");
            }
            let (admit, _) = crate::net::admit::doors(None, me, true);
            crate::channel::node_end(label, key.identity, admit)
        }
    }
}

/// The system and the machine as cloudflared names them, Go's names.
pub(crate) fn arch() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let machine = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    };
    format!("{os}_{machine}")
}

async fn serve_quick(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, key, door, sshd: roost, warp, relay, record } = ready;
    // TARGET first, when there is one; with none, the node is the relay
    // alone, or an exit's routes alone (T-459).
    let exit = crate::node_exit::asked();
    let target = match targets.is_empty() && !exit {
        true => None,
        false => match crate::node::probe(&targets, roost).await {
            Ok(versions) => Some(crate::node::serving(&targets, &versions)),
            Err(refusal) => return refusal.report("node", err),
        },
    };
    let proxy = ProxyChoice::FromEnvironment;
    let say: Say = {
        let label = label.clone();
        Arc::new(move |line: String| podssh_ssh::err_line!("podssh node: {label}: {line}"))
    };
    let (stop, stopped) = watch::channel(false);
    // A planned stop closes each socket of the role's reverse road with 1012
    // first, which its client tells apart from a lost link (T-255).
    let role = relay.as_ref().map(|relay| relay.cfg.clone());
    // Its list of keys at a URL, fetched again each TTL (T-646).
    if let Some(relay) = &relay {
        relay.keep_lists(&label);
    }
    crate::node_upgrade::lines(say.clone());
    let stopper = tokio::spawn(async move {
        // With the role behind the tunnel, Ctrl-C alone: the role's tokens
        // and pairs live in this process, so it takes no upgrade (T-679).
        match role.is_none() {
            true => crate::node_upgrade::stop().await,
            false => crate::node::stop_signal().await,
        }
        if let Some(cfg) = role {
            let _ = cfg.pairs.restart(crate::relay_serve::STOP_WAIT).await;
        }
        let _ = stop.send(true);
    });
    // The API is asked again for minutes after a refusal for now (T-401):
    // Ctrl-C ends the wait, with nothing made to undo. The tunnel of the
    // binary before this one needs no request: its name stays (T-679).
    let (trust, mut until) = (crate::pairs::trust(None), stopped.clone());
    let handed = kept_tunnel::of_the_run();
    let from_before = handed.is_some();
    let asked = match handed {
        Some(tunnel) => Ok(tunnel),
        None => tokio::select! {
            asked = api::request(&trust, &proxy, &*say) => asked,
            _ = until.wait_for(|stop| *stop) => {
                return crate::node_upgrade::or_finish(|| {
                    say("stopped".into());
                    0
                })
                .await;
            }
        },
    };
    let tunnel = match asked {
        Ok(tunnel) => tunnel,
        // A refusal for now past the budget: a later run can work (75).
        Err(api::Failed::ForNow(why)) => {
            return Refusal { message: why, code: sysexits::EX_TEMPFAIL }.report("node", err)
        }
        Err(api::Failed::Refused(why)) => {
            return Refusal { message: why, code: Fault::RelayUnreachable.code() }.report("node", err)
        }
    };
    // For the binary after an upgrade, which registers it again (T-679).
    kept_tunnel::keep(&tunnel);
    let url = format!("https://{}", tunnel.hostname);
    let serving = match &target {
        Some(target) => format!("serving {target} at {url}, a quick tunnel, {}", crate::node_flags::layer_mode()),
        None => format!("serving the relay alone at {url}, a quick tunnel"),
    };
    // With no --allow, the net is the door, and the first line says so (T-550).
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    let _ = writeln!(err, "podssh node: {label}: {serving} until Ctrl-C{by}");
    if let Some(relay) = &relay {
        let _ = writeln!(err, "podssh node: {label}: {}", relay.shown(&tunnel.hostname));
    }
    // Its record names the tunnel, for as long as the node runs (T-445).
    let line = |words: String| {
        let _ = writeln!(err, "podssh node: {label}: {words}");
    };
    let (_record, tell) = crate::node_record::alone(record, &key.identity, &trust, say.clone(), line);
    tell.quick(&tunnel.hostname);
    // As the pair's road does: the layer, the channel above it, then TARGET,
    // or an exit's routes (T-459); the edge keeps no bound of the relay's.
    let handler: Option<Arc<dyn Handler<Stream = DuplexStream>>> = match targets.is_empty() && !exit {
        true => None,
        false => {
            let me = key.identity.public();
            // Which routes each visitor may use: the keys of --allow, or the
            // net's policy for its members, as on the DERP road (T-550).
            let allow = match &door {
                Door::Allow(path) => Some(path.clone()),
                Door::Net(_) => None,
            };
            let channel = channel_of(&label, key, door, err);
            let (settings, budget) = (crate::layered::settings().off_the_pair(), reverse::layered::NODE_BUDGET);
            // The upgrade's keeper: the sessions of the binary before this
            // one, and those that go to the next (T-679).
            let keeper = crate::node_upgrade::channel_keeper(&channel, settings.resume_deadline);
            let grant = crate::net::admit::grant(allow, Some(me));
            match crate::node::routes_of(&targets, grant, roost, Some(me)) {
                Some(routes) => {
                    Some(Arc::new(Layered::with_keeper(Routed::new(routes, channel), settings, budget, keeper)))
                }
                None => {
                    let first = crate::node_exit::first(&targets);
                    let tcp = TcpHandler { host: first.host, port: first.port, timeout: DIAL_LIMIT, sshd: roost };
                    Some(Arc::new(Layered::with_keeper(E2e::new(tcp, channel), settings, budget, keeper)))
                }
            }
        }
    };
    // The name is the node's answer: the one line on stdout.
    podssh_ssh::out_line!("{url}");
    let ids = Arc::new(AtomicU64::new(1));
    let visit = move |stream: DuplexStream| {
        // Each visitor's id in the form of a relay's session id: 32 hex digits.
        let id = SessionId::parse(format!("{:032x}", ids.fetch_add(1, Ordering::Relaxed)).as_bytes());
        let handler = handler.clone();
        async move {
            // With no TARGET each path is the role's, and no visitor comes here.
            let (Some(handler), Ok(id)) = (handler, id) else { return };
            let Ok(mut session) = handler.open(id).await else { return };
            let mut stream = stream;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut session).await;
        }
    };
    // The relay's paths go to the role, in place of the 404 (T-428).
    let origin = relay.as_ref().map(|relay| relay.origin(&tunnel.hostname, targets.is_empty() && !exit));
    let visit = Visitors { visit, origin };
    // The tunnel's credentials, and this run's id, version and system, as
    // each connection registers them.
    let connector = Arc::new(Connector {
        account_tag: tunnel.account_tag.clone(),
        secret: tunnel.secret.clone(),
        tunnel_id: tunnel.id,
        client_id: rand::random::<[u8; 16]>(),
        version: format!("podssh {}", env!("CARGO_PKG_VERSION")),
        arch: arch(),
    });
    let roads = edge_roads(proxy, WarpRoad::new(warp), say.clone());
    // Said first; then a detached node goes on (T-380).
    let ready = Box::new(|| crate::detach::ready("node"));
    let keep = Keep { connector, visit, roads, say: say.clone(), ready, connections: CONNECTIONS };
    let kept = keep::keep(keep, stopped).await;
    let message = match kept {
        // An upgrade's handover ends this binary; else the stop's line.
        Ok(()) => {
            return crate::node_upgrade::or_finish(|| {
                say("stopped".into());
                0
            })
            .await
        }
        // The edge no longer takes the tunnel of the binary before this one:
        // a new tunnel, under a new name, which the clients of the sessions
        // that came over do not hold (T-679).
        Err(Gone::Refused(message)) if from_before => {
            // The next start listens for the stop itself.
            stopper.abort();
            kept_tunnel::forget();
            say(format!("{message}; the tunnel of {url} is gone, so the node asks for a new one, under a new name"));
            return crate::node_upgrade::AGAIN;
        }
        Err(Gone::Refused(message)) => return Refusal { message, code: Fault::Auth.code() }.report("node", err),
        // A host whose egress never reaches the edge cannot publish.
        Err(Gone::Unreached(why)) => format!(
            "{why}; a quick tunnel needs port 7844 of Cloudflare's edge: UDP for QUIC, TCP directly or through a \
             proxy that allows it, or TCP inside WARP's tunnel"
        ),
    };
    Refusal { message, code: Fault::RelayUnreachable.code() }.report("node", err)
}

/// The roads to the edge for one race, as `plan` asks: QUIC where no proxy
/// stands in its way, as a proxy carries no UDP (T-301), HTTP/2, then HTTP/2
/// inside WARP's tunnel, WARP's first with `--warp`; the road that won the
/// last race first; each to the edge's regions in the order of the
/// connection's index (T-402). The edge is asked for at each race, and its
/// fixed names are said once a run, as `podssh node` has no -v (T-339).
pub(crate) fn edge_roads(proxy: ProxyChoice, warp: WarpRoad, say: Say) -> Roads {
    let over_quic = matches!(podssh_ws::dial::proxy_from_env(edge::regions()[0]), Ok(None));
    let warp_first = warp.first;
    let warp = Arc::new(Mutex::new(warp));
    let said_fixed = Arc::new(AtomicBool::new(false));
    Arc::new(move |plan: Plan| -> Made {
        let (proxy, warp, say, said_fixed) = (proxy.clone(), warp.clone(), say.clone(), said_fixed.clone());
        Box::pin(async move {
            let found = edge::find(&proxy).await;
            if let Some(why) = &found.fixed {
                if !said_fixed.swap(true, Ordering::SeqCst) {
                    say(format!("{why}; the two names of Cloudflare's documents, port {}", edge::port()));
                }
            }
            let found = found.for_connection(plan.conn_index);
            let mut list = Vec::new();
            if over_quic {
                list.push(roads::quic(found.clone()));
            }
            list.push(roads::http2(proxy, found.clone()));
            let inside = warp_road(warp, found, say);
            match warp_first {
                true => list.insert(0, inside),
                false => list.push(inside),
            }
            roads::first_of(&mut list, plan.first);
            list
        })
    })
}

/// HTTP/2 inside WARP's tunnel to `found`: the tunnel opens at its first use,
/// one road at a time, and stays for the node's later connections.
fn warp_road(warp: Arc<Mutex<WarpRoad>>, found: edge::Edge, say: Say) -> Road {
    let dial = async move {
        let io = warp.lock().await.edge(&found, &*say).await?;
        Ok::<Link, String>(Link::Http2(Box::new(io)))
    };
    Road { name: crate::node_warp::ROAD, dial: Box::pin(dial) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_system_and_the_machine_are_named_as_go_names_them() {
        let arch = super::arch();
        assert!(arch.split_once('_').is_some_and(|(os, machine)| !os.is_empty() && !machine.is_empty()), "{arch}");
        assert!(!arch.contains("x86_64") && !arch.contains("aarch64") && !arch.contains("macos"), "{arch}");
    }

    /// With no --allow, the channel lets in the net's members alone (T-550):
    /// a key that no net names is refused, though a public name lets any key
    /// try, and an allowlist that is missing opens nothing.
    #[test]
    fn the_nets_door_refuses_a_key_that_no_net_names() {
        use podssh_relay::e2e::Ask;
        use podssh_relay::identity::{file, Identity};
        let key = file::Key { identity: Identity::from_seed(&[0x31; 32]), path: None, made: false };
        let node = super::channel_of("lab", key, super::Door::Net("home".into()), &mut Vec::new());
        let stranger = Identity::from_seed(&[0x51; 32]).public();
        assert!((node.admit)(&stranger, &Ask::Target).is_err(), "a stranger came in through the net's door");
    }
}
