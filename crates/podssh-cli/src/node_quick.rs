//! `podssh node NAME TARGET --quick-tunnel` (T-300): the node in front of
//! the TCP service TARGET at `https://NAME.trycloudflare.com`, a quick
//! tunnel of Cloudflare's that podssh makes itself, with no `cloudflared`,
//! no pair and no account (`podssh_relay::quick`). The name is new each run,
//! and the one line on stdout. A visitor's WebSocket through the name is one
//! link of the resumable layer, with the end-to-end channel above it: the
//! name is public, so only an operator whose key is in the file of `--allow`
//! reaches TARGET, which is dialled only after the layer's handshake. The
//! node races its roads to port 7844 of Cloudflare's edge (T-400): QUIC
//! where no proxy is set and UDP answers a probe, as cloudflared does
//! (T-301), HTTP/2 on TCP, directly or through a proxy that allows it, and
//! HTTP/2 inside WARP's tunnel (T-374, `crate::node_warp`), first with
//! `--warp`; each starts 2 s after the one before, or at once when it
//! failed, and the first that registers is kept. It keeps two connections,
//! the second to the edge's other region first, and on the edge's GOAWAY it
//! connects again at once while the old connection drains (T-402). A lost
//! connection to the edge is made again, with the same name, until Ctrl-C.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::identity::file;
use podssh_relay::quick::keep::{self, Gone, Keep, Made, Plan, Roads, Say};
use podssh_relay::quick::register::Connector;
use podssh_relay::quick::roads::{self, Link, Road};
use podssh_relay::quick::{api, edge};
use podssh_relay::reverse::framing::SessionId;
use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::{self, E2e, Handler, Layered, TcpHandler};
use podssh_ws::ProxyChoice;
use tokio::io::DuplexStream;
use tokio::sync::{watch, Mutex};

use crate::exitmap::{sysexits, Fault};
use crate::node::NodeArgs;
use crate::node_warp::WarpRoad;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The connections that the node keeps to the edge at once, each to its own
/// region first. One until the operator rules on a second that stays
/// (Q62): rule 2 of AGENTS.md allows one outbound connection, and its
/// exceptions name no second edge connection. The drain of T-402 holds
/// with one: the old connection serves its streams while the next one
/// registers, for 90 s at most.
const CONNECTIONS: u8 = 1;

/// Each check that needs no network, done.
struct Ready {
    label: String,
    targets: Vec<Route>,
    key: file::Key,
    allow: PathBuf,
    sshd: bool,
    /// The edge inside WARP's tunnel first (`--warp`).
    warp: bool,
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
    let code = runtime.block_on(Box::pin(serve_quick(ready, err)));
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
    let targets = crate::node::targets_of(&crate::node::words_of(args), false)?;
    if targets.len() != 1 || targets[0].name.is_some() {
        return Err(Refusal::usage("--quick-tunnel serves one TARGET, with no route"));
    }
    let flags = crate::node::key_flags(args)?;
    let allow = flags.allow.ok_or_else(|| {
        Refusal::usage(
            "--quick-tunnel needs --allow FILE: its name is public, so only the operator keys in FILE come in",
        )
    })?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    crate::pairs::online()?;
    let key = crate::channel::load_node_key(&place)?;
    Ok(Ready { label, targets, key, allow, sshd: args.sshd, warp: args.warp })
}

/// The system and the machine as cloudflared names them, Go's names.
fn arch() -> String {
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
    let Ready { label, targets, key, allow, sshd: roost, warp } = ready;
    let target = match crate::node::probe(&targets, roost).await {
        Ok(versions) => crate::node::serving(&targets, &versions),
        Err(refusal) => return refusal.report("node", err),
    };
    let proxy = ProxyChoice::FromEnvironment;
    let say: Say = {
        let label = label.clone();
        Arc::new(move |line: String| podssh_ssh::err_line!("podssh node: {label}: {line}"))
    };
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(async move {
        crate::node::stop_signal().await;
        let _ = stop.send(true);
    });
    // The API is asked again for minutes after a refusal for now (T-401):
    // Ctrl-C ends the wait, with nothing made to undo.
    let (trust, mut until) = (crate::pairs::trust(None), stopped.clone());
    let asked = tokio::select! {
        asked = api::request(&trust, &proxy, &*say) => asked,
        _ = until.wait_for(|stop| *stop) => {
            say("stopped".into());
            return 0;
        }
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
    let url = format!("https://{}", tunnel.hostname);
    let mode = crate::node_flags::layer_mode();
    let _ = writeln!(err, "podssh node: {label}: serving {target} at {url}, a quick tunnel, {mode} until Ctrl-C");
    let channel = crate::channel::node(&label, key, Some(allow), err);
    // The name is the node's answer: the one line on stdout.
    podssh_ssh::out_line!("{url}");
    let first = &targets[0];
    let tcp = TcpHandler { host: first.host.clone(), port: first.port, timeout: DIAL_LIMIT, sshd: roost };
    let (settings, budget) = (crate::layered::settings(), reverse::layered::NODE_BUDGET);
    // As the pair's road does: the layer, the channel above it, then TARGET.
    let handler = Arc::new(Layered::new(E2e::new(tcp, channel), settings, budget));
    let ids = Arc::new(AtomicU64::new(1));
    let visit = move |stream: DuplexStream| {
        // Each visitor's id in the form of a relay's session id: 32 hex digits.
        let id = SessionId::parse(format!("{:032x}", ids.fetch_add(1, Ordering::Relaxed)).as_bytes());
        let handler = handler.clone();
        async move {
            let Ok(id) = id else { return };
            let Ok(mut session) = handler.open(id).await else { return };
            let mut stream = stream;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut session).await;
        }
    };
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
        Ok(()) => {
            say("stopped".into());
            return 0;
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
fn edge_roads(proxy: ProxyChoice, warp: WarpRoad, say: Say) -> Roads {
    let over_quic = matches!(podssh_ws::dial::proxy_from_env(edge::REGIONS[0]), Ok(None));
    let warp_first = warp.first;
    let warp = Arc::new(Mutex::new(warp));
    let said_fixed = Arc::new(AtomicBool::new(false));
    Arc::new(move |plan: Plan| -> Made {
        let (proxy, warp, say, said_fixed) = (proxy.clone(), warp.clone(), say.clone(), said_fixed.clone());
        Box::pin(async move {
            let found = edge::find(&proxy).await;
            if let Some(why) = &found.fixed {
                if !said_fixed.swap(true, Ordering::SeqCst) {
                    say(format!("{why}; the two names of Cloudflare's documents, port {}", edge::PORT));
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
}
