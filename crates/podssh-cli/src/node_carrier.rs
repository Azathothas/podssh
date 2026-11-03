//! `podssh node NAME TARGET --carrier ADDR` (T-595): the node's socket of the
//! reverse road on a stream that exists already, for a host whose every road
//! out is closed: stdin and stdout, as the exec channel of a platform's own
//! SSH gives them to the program that it starts; a descriptor; or a program
//! that the node starts. The other end (`podssh operator --carrier`) serves
//! the relay's side of the socket in its own process (`crate::carrier`). No
//! relay, no pair and no token: the stream is the door, and NAME is a label
//! alone, for the node's key. One stream for the node's life: at its end the
//! sessions end, and the node exits 0 after its client's Close, or 69 for a
//! stream that failed. TARGET, the routes, a roost, a UDP TARGET, the layer
//! and the end-to-end channel are as on the pair's road.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends::Node;
use podssh_relay::reverse::routes::{Route, Routed};
use podssh_relay::reverse::{self, E2e, End, Handler, Layered, Settings, TcpHandler};
use podssh_relay::serve::reverse::carrier::{self, Link};
use podssh_ws::session::RelaySession;
use tokio::process::Child;

use crate::exitmap::Fault;
use crate::node::{key_flags, probe, routes_of, serving, stop_signal, targets_of, words_of, NodeArgs, DIAL_LIMIT};
use crate::pipe::address::Address;
use crate::relay_settings::Refusal;

/// How long the program that carried the stream may take to end after it.
const CHILD_LIMIT: Duration = Duration::from_secs(2);

/// The flags that a node of a carrier takes none of, checked before anything
/// else, an `--install` among them: its stream is its parent's, so it
/// reaches no relay, has no pair, and goes to no background.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    let Some(text) = args.carrier.as_deref() else { return Ok(()) };
    if args.exit {
        return Err(Refusal::usage("--exit over a carrier is not built yet: its client comes with it"));
    }
    let refused = [
        (args.pair_file.is_some(), "--pair-file"),
        (args.relay_addr.is_some(), "--relay-addr"),
        (args.ca_file.is_some(), "--ca-file"),
        (args.iroh, "--iroh"),
        (args.iroh_relay.is_some(), "--iroh-relay"),
        (args.derp, "--derp"),
        (args.derp_server.is_some(), "--derp-server"),
        (args.opentunnel, "--opentunnel"),
        (args.quick_tunnel, "--quick-tunnel"),
        (args.warp, "--warp"),
        (args.relay, "--relay"),
        (args.mint.is_some(), "--mint"),
        (args.pairs.is_some(), "--pairs"),
        (args.allow_private, "--allow-private"),
        (args.temporary.is_some(), "--temporary"),
        (args.install, "--install"),
        (args.uninstall, "--uninstall"),
        (args.detach, "--detach"),
        (args.restart, "--restart"),
        (args.detach_name.is_some(), "--detach-name"),
    ];
    if let Some((_, flag)) = refused.into_iter().find(|(given, _)| *given) {
        return Err(Refusal::usage(format!(
            "{flag} does not go with --carrier: the node's one road is the stream of {text}, which its parent holds"
        )));
    }
    let found = crate::carrier::parse(text)?;
    crate::carrier::no_terminal(&found, crate::carrier::stdin_is_terminal())
}

/// Each check that needs no stream, in order: the flags, NAME, each TARGET,
/// the channel's flags and the node's key.
struct Ready {
    label: String,
    /// The stream, in the user's words, and as `pipe` reads it.
    text: String,
    found: Address,
    targets: Vec<Route>,
    plain: bool,
    key: Option<podssh_relay::identity::file::Key>,
    allow: Option<std::path::PathBuf>,
    sshd: bool,
    udp: bool,
}

/// Run the node over the carrier; the process exit code.
pub(crate) fn run(args: &NodeArgs, err: &mut dyn Write) -> i32 {
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
    // A read of stdin may still wait in a helper thread: the node has ended.
    runtime.shutdown_background();
    code
}

fn prepare(args: &NodeArgs) -> Result<Ready, Refusal> {
    check(args)?;
    let text = args.carrier.clone().unwrap_or_default();
    let found = crate::carrier::parse(&text)?;
    let label = args.name.clone().ok_or("missing NAME: the label of the node, under which its key is kept")?;
    crate::pairs::check_label(&label)?;
    let (targets, udp) = match crate::node_udp::target_of(&args.targets)? {
        Some(_) if args.sshd => {
            return Err(Refusal::usage("--sshd stands in front of an sshd, which a udp: TARGET is not"))
        }
        Some(target) => (vec![target], true),
        None => (targets_of(&words_of(args), args.no_e2e)?, false),
    };
    let flags = key_flags(args)?;
    if args.no_e2e && (flags.key.is_some() || flags.ephemeral || flags.allow.is_some()) {
        return Err(Refusal::usage(
            "--key, --ephemeral-key and --allow are the node's side of the end-to-end channel, which --no-e2e turns off",
        ));
    }
    let key = match args.no_e2e {
        true => None,
        false => {
            let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
            Some(crate::channel::load_node_key(&place)?)
        }
    };
    let (plain, allow, sshd) = (args.plain, flags.allow, args.sshd);
    Ok(Ready { label, text, found, targets, plain, key, allow, sshd, udp })
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, text, found, targets, plain, key, allow, sshd: roost, udp } = ready;
    // TARGET first, as on each road: a node that could serve no session
    // does not start.
    let target = if udp {
        match crate::node_udp::probe(&targets[0], DIAL_LIMIT).await {
            Ok(()) => crate::node_udp::shown(&targets[0]),
            Err(refusal) => return refusal.report("node", err),
        }
    } else {
        match probe(&targets, roost).await {
            Ok(versions) => serving(&targets, &versions),
            Err(refusal) => return refusal.report("node", err),
        }
    };
    let me = key.as_ref().map(|key| key.identity.public());
    let routes = routes_of(&targets, crate::net::admit::grant(allow.clone(), me), roost, me);
    let mode = if plain { "in plain mode, with no resumable layer".into() } else { crate::node_flags::layer_mode() };
    let _ = writeln!(err, "podssh node: {label}: serving {target} over the carrier {text} {mode}, until it ends");
    let channel = match key {
        Some(key) => Some(crate::channel::node(&label, key, allow, err)),
        None => {
            let _ = writeln!(
                err,
                "podssh node: {label}: no end-to-end channel (--no-e2e): what carries the stream sees each byte"
            );
            None
        }
    };
    let (link, child) = match crate::carrier::open(&found) {
        Ok(opened) => opened,
        Err(refusal) => return refusal.report("node", err),
    };
    let session = carrier::node_socket(link);
    // The node's first frame: the client opens no session before it.
    if let Err(e) = carrier::greet(&session).await {
        let _ = writeln!(err, "podssh node: {label}: the carrier {text} failed at once: {e}");
        return finish(child, Fault::RelayUnreachable.code()).await;
    }
    let _ = writeln!(err, "podssh node: {label}: online: the carrier's client takes this node's sessions");
    let first = crate::node_exit::first(&targets);
    let end = if udp {
        let flow_label = label.clone();
        let flow_say: Arc<dyn Fn(String) + Send + Sync> =
            Arc::new(move |line: String| podssh_ssh::err_line!("podssh node: {flow_label}: {line}"));
        with_handler(session, crate::node_udp::handler(&first, DIAL_LIMIT, flow_say), plain, channel).await
    } else {
        let tcp = TcpHandler { host: first.host.clone(), port: first.port, timeout: DIAL_LIMIT, sshd: roost };
        let (settings, budget) = (crate::layered::settings(), reverse::layered::NODE_BUDGET);
        // The channel above the layer, and the route that each operator
        // named in it, as on the pair's road.
        match (plain, channel, routes) {
            (true, Some(node), Some(routes)) => served(session, Arc::new(Routed::new(routes, node))).await,
            (false, Some(node), Some(routes)) => {
                served(session, Arc::new(Layered::new(Routed::new(routes, node), settings, budget))).await
            }
            (_, channel, _) => with_handler(session, tcp, plain, channel).await,
        }
    };
    let (code, why) = ended(end);
    let _ = writeln!(err, "podssh node: {label}: {why}");
    finish(child, code).await
}

/// The sessions of the stream, each opened by `inner`: at `open` with no
/// layer, or after the layer's handshake, with the channel above the layer.
async fn with_handler<H: Handler>(session: RelaySession<Link>, inner: H, plain: bool, channel: Option<Node>) -> End {
    let (settings, budget) = (crate::layered::settings(), reverse::layered::NODE_BUDGET);
    match (plain, channel) {
        (true, None) => served(session, Arc::new(inner)).await,
        (true, Some(node)) => served(session, Arc::new(E2e::new(inner, node))).await,
        (false, None) => served(session, Arc::new(Layered::new(inner, settings, budget))).await,
        (false, Some(node)) => served(session, Arc::new(Layered::new(E2e::new(inner, node), settings, budget))).await,
    }
}

/// The node's side of the socket, until the stream ends, or Ctrl-C or
/// SIGTERM.
async fn served<H: Handler>(session: RelaySession<Link>, handler: Arc<H>) -> End {
    let mut stop = Box::pin(stop_signal());
    reverse::serve(session, handler, Settings::default(), &mut stop).await
}

/// The exit code for each end of the stream, and its words: 0 for a stop or
/// the client's Close 1000, 69 for each other end.
fn ended(end: End) -> (i32, String) {
    let unreachable = Fault::RelayUnreachable.code();
    match end {
        End::Stopped => (0, "stopped".into()),
        End::Closed(close) if close.code == 1000 => (0, "the carrier's client ended the stream".into()),
        End::Closed(close) => {
            let reason = podssh_ws::text::one_line(&close.reason);
            (unreachable, format!("the carrier's client closed the stream ({} {reason})", close.code))
        }
        End::Failed(e) => (unreachable, format!("the carrier's stream failed: {e}")),
    }
}

/// The program that carried the stream, when the node started one, ends
/// with it: waited for, then ended.
async fn finish(child: Option<Child>, code: i32) -> i32 {
    if let Some(mut child) = child {
        if tokio::time::timeout(CHILD_LIMIT, child.wait()).await.is_err() {
            let _ = child.kill().await;
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_relay::reverse::RelayClose;

    /// `node lab 127.0.0.1:22 --carrier CARRIER`.
    fn args(carrier: Option<&str>) -> NodeArgs {
        let name = Some("lab".to_string());
        let (targets, carrier) = (vec!["127.0.0.1:22".to_string()], carrier.map(str::to_string));
        NodeArgs { name, targets, carrier, ..NodeArgs::default() }
    }

    #[test]
    fn a_node_of_a_carrier_takes_no_flag_of_a_relay_a_pair_or_the_background() {
        let base = || args(Some("exec:cat"));
        let given: [(&str, NodeArgs); 8] = [
            ("--pair-file", NodeArgs { pair_file: Some("x".into()), ..base() }),
            ("--iroh", NodeArgs { iroh: true, ..base() }),
            ("--derp", NodeArgs { derp: true, ..base() }),
            ("--quick-tunnel", NodeArgs { quick_tunnel: true, ..base() }),
            ("--install", NodeArgs { install: true, ..base() }),
            ("--detach", NodeArgs { detach: true, ..base() }),
            ("--relay-addr", NodeArgs { relay_addr: Some("a=127.0.0.1".into()), ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
        ];
        for (flag, args) in given {
            let refusal = check(&args).unwrap_err();
            assert_eq!(refusal.code, 64, "{flag}: {}", refusal.message);
            assert!(refusal.message.contains(flag), "{flag}: {}", refusal.message);
        }
        assert!(check(&base()).is_ok());
        assert_eq!(check(&args(Some("tcp:127.0.0.1:22"))).unwrap_err().code, 64);
        assert!(check(&args(None)).is_ok(), "no carrier, nothing to check");
    }

    #[test]
    fn the_client_s_close_is_a_clean_end_and_each_other_end_is_69() {
        let close = |code: u16| End::Closed(RelayClose { code, reason: "why".into(), clean: true });
        assert_eq!(ended(End::Stopped).0, 0);
        assert_eq!(ended(close(1000)).0, 0);
        assert_eq!(ended(close(1011)), (69, "the carrier's client closed the stream (1011 why)".into()));
        let failed = ended(End::Failed(podssh_ws::SessionError::ClosedWithoutClose("gone".into())));
        assert_eq!(failed.0, 69);
        assert!(failed.1.starts_with("the carrier's stream failed: "), "{}", failed.1);
    }
}
