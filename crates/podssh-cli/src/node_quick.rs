//! `podssh node NAME TARGET --quick-tunnel` (T-300): the node in front of
//! the TCP service TARGET at `https://NAME.trycloudflare.com`, a quick
//! tunnel of Cloudflare's that podssh makes itself, with no `cloudflared`,
//! no pair and no account (`podssh_relay::quick`). The name is new each run,
//! and the one line on stdout. A visitor's WebSocket through the name is one
//! link of the resumable layer, with the end-to-end channel above it: the
//! name is public, so only an operator whose key is in the file of `--allow`
//! reaches TARGET, which is dialled only after the layer's handshake. The
//! node reaches port 7844 of Cloudflare's edge over QUIC where no proxy is
//! set and UDP gets there, as cloudflared does (T-301), else over HTTP/2 on
//! TCP, directly or through a proxy that allows it; a lost connection to the
//! edge is made again, with the same name, until Ctrl-C.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::identity::file;
use podssh_relay::quick::register::{Registration, FEATURES};
use podssh_relay::quick::serve::{self, Ended, Step};
use podssh_relay::quick::{api, edge, quic};
use podssh_relay::reverse::framing::SessionId;
use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::{self, E2e, Handler, Layered, TcpHandler};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::sync::{mpsc, watch};

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The waits between connections to the edge after a loss: doubled from the
/// first, to the most.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MOST: Duration = Duration::from_secs(30);

/// Each check that needs no network, done.
struct Ready {
    label: String,
    targets: Vec<Route>,
    key: file::Key,
    allow: PathBuf,
    sshd: bool,
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
    ];
    if let Some((_, flag)) = alone.iter().find(|(given, _)| *given) {
        return Err(Refusal::usage(format!(
            "{flag} is not for --quick-tunnel, which runs the resumable layer and the end-to-end channel, with no pair"
        )));
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
    Ok(Ready { label, targets, key, allow, sshd: args.sshd })
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
    let Ready { label, targets, key, allow, sshd: roost } = ready;
    let target = match crate::node::probe(&targets, roost).await {
        Ok(versions) => crate::node::serving(&targets, &versions),
        Err(refusal) => return refusal.report("node", err),
    };
    let proxy = ProxyChoice::FromEnvironment;
    let tunnel = match api::request(&crate::pairs::trust(None), &proxy).await {
        Ok(tunnel) => tunnel,
        Err(why) => return Refusal { message: why, code: Fault::RelayUnreachable.code() }.report("node", err),
    };
    let url = format!("https://{}", tunnel.hostname);
    let mode = crate::node_flags::layer_mode();
    let _ = writeln!(err, "podssh node: {label}: serving {target} at {url}, a quick tunnel, {mode} until Ctrl-C");
    let channel = crate::channel::node(&label, key, Some(allow), err);
    // The name is the node's answer: the one line on stdout.
    println!("{url}");
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
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(async move {
        crate::node::stop_signal().await;
        let _ = stop.send(true);
    });
    let say = |line: String| eprintln!("podssh node: {label}: {line}");
    let (client_id, version, arch) =
        (rand::random::<[u8; 16]>(), format!("podssh {}", env!("CARGO_PKG_VERSION")), arch());
    let (mut wait, mut connected_once) = (RETRY_FIRST, false);
    // QUIC first, as cloudflared's own default, where no proxy stands in its
    // way: a proxy carries no UDP (T-301).
    let mut over_quic = matches!(podssh_ws::dial::proxy_from_env(edge::REGIONS[0]), Ok(None));
    loop {
        if *stopped.borrow() {
            break;
        }
        let link = match link(&mut over_quic, &proxy, &say).await {
            Ok(link) => link,
            // A host whose egress never reaches the edge cannot publish.
            Err(why) if !connected_once => {
                let message = format!(
                    "{why}; a quick tunnel needs port 7844 of Cloudflare's edge: UDP for QUIC, or TCP, directly or \
                     through a proxy that allows it"
                );
                return Refusal { message, code: Fault::RelayUnreachable.code() }.report("node", err);
            }
            Err(why) => {
                say(format!("{why}; trying again in {} s", wait.as_secs()));
                pause(&mut wait, &stopped).await;
                continue;
            }
        };
        connected_once = true;
        let registration = Registration {
            account_tag: &tunnel.account_tag,
            secret: &tunnel.secret,
            tunnel_id: tunnel.id,
            conn_index: 0,
            client_id,
            features: FEATURES,
            version: &version,
            arch: &arch,
        };
        let (steps, mut heard) = mpsc::unbounded_channel();
        // A connection that registered was a good one: the next waits from
        // the start again, not from the longest wait of the failures before.
        let registered = Arc::new(AtomicBool::new(false));
        let transport = link.transport();
        let said = tokio::spawn({
            let (label, registered) = (label.clone(), registered.clone());
            async move {
                while let Some(step) = heard.recv().await {
                    let line = match step {
                        Step::Registered { location } => {
                            registered.store(true, Ordering::SeqCst);
                            format!("registered at Cloudflare's {location}, over {transport}")
                        }
                        Step::Visitor => continue,
                        Step::Unregistered => "unregistered".to_string(),
                    };
                    eprintln!("podssh node: {label}: {line}");
                }
            }
        });
        let mut until = stopped.clone();
        let stop_asked = async move {
            let _ = until.wait_for(|stop| *stop).await;
        };
        let served = match link {
            Link::Quic(edge) => edge.serve(&registration, visit.clone(), steps, stop_asked).await,
            Link::Http2(tls) => serve::serve(tls, &registration, visit.clone(), steps, stop_asked).await,
        };
        let _ = said.await;
        if registered.load(Ordering::SeqCst) {
            wait = RETRY_FIRST;
        }
        match served {
            Ok(()) => break,
            Err(Ended::Refused { cause, retry: false, .. }) => {
                let message = format!("the edge refused the tunnel's connection: {cause}");
                return Refusal { message, code: Fault::Auth.code() }.report("node", err);
            }
            Err(Ended::Refused { cause, after, .. }) => {
                wait = after.clamp(RETRY_FIRST, RETRY_MOST);
                say(format!("the edge refused the connection for now ({cause}); trying again in {} s", wait.as_secs()));
            }
            Err(e) => say(format!("{e}; connecting again in {} s", wait.as_secs())),
        }
        pause(&mut wait, &stopped).await;
    }
    say("stopped".into());
    0
}

/// A connection to the edge, by the transport that answered.
enum Link<T> {
    Quic(quic::EdgeConnection),
    Http2(T),
}

impl<T> Link<T> {
    fn transport(&self) -> &'static str {
        match self {
            Link::Quic(_) => "QUIC",
            Link::Http2(_) => "HTTP/2",
        }
    }
}

/// QUIC while `over_quic` holds, else HTTP/2 through `proxy`. QUIC that
/// fails says why and gives way to HTTP/2 for the rest of the run, as a
/// network that drops UDP drops it again.
async fn link(
    over_quic: &mut bool,
    proxy: &ProxyChoice,
    say: &dyn Fn(String),
) -> Result<Link<impl AsyncRead + AsyncWrite + Unpin + Send>, String> {
    if *over_quic {
        match quic::connect_edge().await {
            Ok(edge) => return Ok(Link::Quic(edge)),
            Err(why) => {
                *over_quic = false;
                say(format!("{why}; over HTTP/2 from now on"));
            }
        }
    }
    edge::connect(proxy).await.map(Link::Http2)
}

/// Wait `wait`, unless the end comes first, and double it for the next time.
async fn pause(wait: &mut Duration, stopped: &watch::Receiver<bool>) {
    let mut until = stopped.clone();
    tokio::select! {
        () = tokio::time::sleep(*wait) => {}
        _ = until.wait_for(|stop| *stop) => {}
    }
    *wait = (*wait * 2).min(RETRY_MOST);
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
