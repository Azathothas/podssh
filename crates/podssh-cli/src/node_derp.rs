//! `podssh node NAME TARGET --derp` (T-379): the node in front of the TCP
//! service TARGET over the DERP road of `podssh-relay` (T-349), through
//! Tailscale's servers for tailcat, or those of `--derp-server` or
//! `PODSSH_DERP_SERVER`. Its home is the first server whose probe answers,
//! and its key there is derived from the node's identity, so its ticket
//! (`derp:...`) stays while its home does; when the home goes away, the node
//! calls the next server of its list home, and says its new ticket. With
//! the pair NAME, or the one of `--pair-file`, it serves the pair's road
//! too, with one keeper for both, so that a session resumes on either
//! (T-164). The road needs the end-to-end channel and `--allow`: a DERP
//! server lets any key send, so the channel's allowlist is the node's only
//! door. A node with no pair, and an allowlist, serves the road unasked
//! (the operator's ruling Q50) and says so; `PODSSH_DERP=no` turns that off.
//! stdout stays empty: the lines are on stderr.

use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::derp::far::{self, Node, Roam};
use podssh_relay::derp::{self, dial, servers, Conn, Secret, Server, Ticket};
use podssh_relay::e2e::ends;
use podssh_relay::identity::Identity;
use podssh_relay::pair::Pair;
use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::{self, Layered, NodeConfig, TcpHandler, Wire};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::Settings;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// `no`: no road through tailcat's fleet unasked (Q50): a node with no pair
/// refuses as before, and a client dials no ticket that it kept.
pub const FALLBACK_ENV: &str = "PODSSH_DERP";

/// Whether the fallback of Q50 is on, by [`FALLBACK_ENV`].
pub(crate) fn fallback_on() -> Result<bool, Refusal> {
    fallback_from(std::env::var(FALLBACK_ENV).ok().as_deref())
}

/// Unset, empty or yes: on; no: off; another word is a setting that
/// cannot be used (78).
pub(crate) fn fallback_from(value: Option<&str>) -> Result<bool, Refusal> {
    let Some(value) = value else { return Ok(true) };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Ok(true),
        "no" | "off" | "false" | "0" => Ok(false),
        _ => Err(Refusal::config(format!("{FALLBACK_ENV}={value}: yes or no"))),
    }
}

/// Whether a UDP TARGET is among the node's, which the DERP road cannot carry.
fn has_udp(args: &NodeArgs) -> bool {
    args.targets.iter().any(|t| t.starts_with("udp:") || t.contains("=udp:"))
}

/// Why a node with no `--derp` serves the DERP road, when it does: it has
/// no pair (none stored, or expired), and an allowlist, and nothing else
/// asked of it needs the pair's road (Q50).
pub(crate) fn unasked(args: &NodeArgs) -> Result<Option<String>, Refusal> {
    let other = args.derp || args.iroh || args.plain || args.no_e2e;
    let allowed = args.allow.is_some() || args.iroh_allow.is_some();
    if other || !allowed || args.pair_file.is_some() || has_udp(args) {
        return Ok(None);
    }
    let Some(label) = args.name.as_deref().filter(|label| crate::pairs::check_label(label).is_ok()) else {
        return Ok(None);
    };
    if !fallback_on()? {
        return Ok(None);
    }
    Ok(crate::pairs::stored(label).err().map(|refusal| refusal.message))
}

/// The flags of the DERP road, checked before anything is read.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain {
        return Err(Refusal::usage("--plain is for the pair's road: the DERP road always runs the resumable layer"));
    }
    if args.no_e2e {
        return Err(Refusal::usage(
            "--no-e2e cannot go with --derp: a DERP server lets any key send, so the end-to-end channel and its \
             allowlist are the node's only door",
        ));
    }
    if has_udp(args) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the DERP road carries TCP only"));
    }
    if args.allow.is_none() && args.iroh_allow.is_none() {
        return Err(Refusal::usage(
            "--derp needs --allow FILE, the client keys that may come in: a DERP server lets any key send to the node",
        ));
    }
    Ok(())
}

/// A node's DERP road, online: the node, its connection to its home, its
/// ticket, and the servers that it may move to.
pub(crate) struct Online {
    node: Node,
    first: Conn,
    pub ticket: Ticket,
    servers: Vec<Server>,
}

/// The home, the first of `servers` whose probe answers through the proxy;
/// a connection to it under the node's key, derived from `identity`; and
/// the ticket. With none, the refusal (69) names each server's miss.
pub(crate) async fn online(
    identity: &Identity,
    servers: &[Server],
    trust: &Trust,
    say: derp::Say,
) -> Result<Online, Refusal> {
    let unreachable = Fault::RelayUnreachable.code();
    let proxy = ProxyChoice::FromEnvironment;
    let (home, missed) = servers::home(servers, trust, &proxy).await;
    let Some(home) = home else {
        let message = format!(
            "no DERP server answered {} ({}); podssh doctor checks the way to them",
            servers::PROBE_PATH,
            missed.join("; ")
        );
        return Err(Refusal { message, code: unreachable });
    };
    for why in &missed {
        say(format!("a DERP server did not answer: {why}"));
    }
    let secret = Arc::new(Secret::of_node(identity));
    let node = Node { secret, server: home.clone(), dial: dial::tls(trust.clone(), proxy), say };
    let first = far::connect(&node)
        .await
        .map_err(|why| Refusal { message: format!("the DERP server {home}: {why}"), code: unreachable })?;
    let ticket = Ticket { node: identity.public(), derp: first.key(), server: home };
    Ok(Online { node, first, ticket, servers: servers.to_vec() })
}

impl Online {
    /// The node's home.
    pub(crate) fn home(&self) -> &Server {
        &self.ticket.server
    }

    /// Serve the road's sessions for ever with `keeper`, which another road
    /// may share; when the home goes away, the next server of the list, and
    /// a line with the new ticket.
    pub(crate) async fn serve<A, O, F>(self, settings: Settings, budget: usize, open: O, keeper: Arc<Keeper<A>>)
    where
        A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        O: Fn() -> F + Clone + Send + Sync + 'static,
        F: Future<Output = Result<A, String>> + Send + 'static,
    {
        let Online { node, first, ticket, servers } = self;
        let say = node.say.clone();
        let moved: far::Moved = Arc::new(move |server: &Server| {
            let now = Ticket { server: server.clone(), ..ticket.clone() };
            say(format!("the home moved to the DERP server {server}; the ticket is now {now}"));
        });
        far::serve_roaming(node, Roam { servers, moved }, Some(first), settings, budget, open, keeper).await;
    }
}

/// The settings of the layer on the DERP road: the iroh road's features.
pub(crate) fn settings() -> Settings {
    Settings { features: derp::FEATURES, ..crate::layered::settings() }
}

/// Each check of the node that needs no network, done.
struct Ready {
    label: String,
    targets: Vec<Route>,
    roost: bool,
    key: podssh_relay::identity::file::Key,
    allow: PathBuf,
    servers: Vec<Server>,
    trust: Trust,
    /// The pair's road: the pair, and whether it came from the store; or
    /// why there is none.
    pair: Result<(Pair, bool), String>,
    /// Why the node serves the road unasked, when it does.
    unasked: Option<String>,
}

fn prepare(args: &NodeArgs, unasked: Option<String>) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    check(args)?;
    let targets = crate::node::targets_of(&crate::node::words_of(args), args.no_e2e)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let allow = flags.allow.ok_or("--derp needs --allow FILE")?;
    let servers = crate::ssh::derp::servers(args.derp_server.as_deref())?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    // A pair that `--pair-file` names must be good; a stored one may be
    // missing or expired, and the node then serves the DERP road alone.
    let pair = match &args.pair_file {
        Some(file) => Ok((crate::pairs::usable(crate::pairs::from_file(file)?, &label)?, false)),
        None => crate::pairs::stored(&label).map(|pair| (pair, true)).map_err(|refusal| refusal.message),
    };
    crate::pairs::online()?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    // The key is made only once each check passed.
    let key = crate::channel::load_node_key(&place)?;
    Ok(Ready { label, targets, roost: args.sshd, key, allow, servers, trust, pair, unasked })
}

/// Run the node of the DERP road; `unasked` is why it serves the road with
/// no `--derp`. Returns the process exit code.
pub fn run(args: &NodeArgs, unasked: Option<String>, err: &mut dyn Write) -> i32 {
    let ready = match prepare(args, unasked) {
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
    // On the heap: Windows gives the main thread 1 MiB of stack.
    let code = runtime.block_on(Box::pin(serve(ready, err)));
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    code
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, allow, servers, trust, pair, unasked } = ready;
    // TARGET first: a node that cannot reach it would serve no session.
    let target = match crate::node::probe(&targets, roost).await {
        Ok(versions) => crate::node::serving(&targets, &versions),
        Err(refusal) => return refusal.report("node", err),
    };
    let say: derp::Say = {
        let label = label.clone();
        Arc::new(move |line: String| eprintln!("podssh node: {label}: {line}"))
    };
    let kept = match (&key.path, key.made) {
        (None, _) => "a key for this run only: the ticket lasts as long as the run".to_string(),
        (Some(path), true) => format!("a new key, in {}: the ticket is new", path.display()),
        (Some(path), false) => format!("in {}", path.display()),
    };
    let identity = Arc::new(key.identity);
    let road = match online(&identity, &servers, &trust, say.clone()).await {
        Ok(road) => road,
        Err(refusal) => return refusal.report("node", err),
    };
    if let Some(why) = &unasked {
        let _ = writeln!(
            err,
            "podssh node: {label}: {why}; so the node serves the DERP road unasked, through Tailscale's tailcat fleet \
             or the servers of {}, by the operator's ruling Q50 ({FALLBACK_ENV}=no turns it off)",
            servers::ENV
        );
    }
    let roads = match &pair {
        Ok((pair, _)) => format!(
            "the DERP road and the pair's road through {} (the pair expires {})",
            pair.relay.host,
            crate::pairs::utc(pair.expires_ms)
        ),
        Err(why) if unasked.is_none() => format!("the DERP road alone ({why})"),
        Err(_) => "the DERP road alone".to_string(),
    };
    let public = identity.public();
    let _ = writeln!(err, "podssh node: {label}: serving {target} over {roads} until Ctrl-C");
    let _ = writeln!(err, "podssh node: {label}: key {public}, the node derp:{} ({kept})", public.hex());
    let _ = writeln!(err, "podssh node: {label}: home {}, the first DERP server whose probe answered", road.home());
    let _ = writeln!(err, "podssh node: {label}: ticket {}", road.ticket);
    let _ = writeln!(err, "podssh node: {label}: {}", crate::channel::who_may(Some(allow.as_path())));
    // The channel of T-088 on both roads, with this node's key and its
    // allowlist: a session made on one road may resume on the other.
    let channel = ends::Node { identity: identity.clone(), admit: crate::channel::admit_of(Some(allow.clone())), say };
    let routes = crate::node::routes_of(&targets, Some(allow), roost);
    let (host, port) = (targets[0].host.clone(), targets[0].port);
    let handler = TcpHandler { host: host.clone(), port, timeout: DIAL_LIMIT, sshd: roost };
    let target = move || {
        let host = host.clone();
        async move { reverse::tcp::dial_target(&host, port, DIAL_LIMIT, roost).await }
    };
    // Each session of either road is a pipe (T-164): the target is reached
    // once the operator's key is let in.
    let open = {
        let (channel, routes) = (Some(channel.clone()), routes.clone());
        move || {
            let (target, channel, routes) = (target.clone(), channel.clone(), routes.clone());
            async move { crate::channel::piped_by(channel, routes, target).await }
        }
    };
    let budget = podssh_relay::reverse::layered::NODE_BUDGET;
    let keeper = Arc::new(Keeper::new(settings().resume_deadline));
    let (stop, stopped) = watch::channel(false);
    let until_stopped = |mut stopped: watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    let derp_road = async {
        tokio::select! {
            () = Box::pin(road.serve(settings(), budget, open, keeper.clone())) => {}
            () = until_stopped(stopped.clone()) => {}
        }
    };
    let pair_road = async {
        let Ok((pair, stored)) = pair else { return };
        let say_pair = |line: String| (channel.say)(line);
        let proxy = ProxyChoice::FromEnvironment;
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
            repair: None,
            wire: Wire::Tls,
            say: Some(&say_pair),
        };
        let piped = crate::channel::Piped { inner: Arc::new(handler), channel: Some(channel.clone()), routes };
        let layered = Layered::with_keeper(piped, crate::layered::settings(), budget, keeper.clone());
        let exit = Box::pin(reverse::run(&mut config, Arc::new(layered), until_stopped(stopped.clone()))).await;
        if let Some((_, why)) = crate::node::ended(&label, exit) {
            (channel.say)(format!("the pair's road ended: {why}; the DERP road goes on"));
        }
    };
    // Until Ctrl-C, or until both roads ended by themselves.
    let both = async { tokio::join!(derp_road, pair_road) };
    tokio::pin!(both);
    tokio::select! {
        _ = &mut both => {}
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
    use super::fallback_from;

    #[test]
    fn podssh_derp_turns_the_fallback_off_with_no_and_refuses_another_word() {
        for on in [None, Some(""), Some("yes"), Some("On"), Some("1")] {
            assert!(fallback_from(on).unwrap(), "{on:?}");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert!(!fallback_from(Some(off)).unwrap(), "{off}");
        }
        let refused = fallback_from(Some("maybe")).unwrap_err();
        assert_eq!(refused.code, 78);
        assert!(refused.message.contains("PODSSH_DERP=maybe"), "{}", refused.message);
    }
}
