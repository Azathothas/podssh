//! `podssh node NAME TARGET --derp` (T-379): the node in front of the TCP
//! service TARGET over the DERP road of `podssh-relay` (T-349), through
//! Tailscale's servers for tailcat, or those of `--derp-server` or
//! `PODSSH_DERP_SERVER`. Its home is the first server whose probe answers,
//! and its key there is derived from the node's identity, so its ticket
//! (`derp:...`) stays while its home does; when the home goes away, the node
//! calls the next server of its list home, and says its new ticket. With
//! the pair NAME, or the one of `--pair-file`, it serves the pair's road
//! too, with one keeper for both, so that a session resumes on either
//! (T-164), and the transit relay's for the pair's operators (T-436,
//! `node_transit`). The road needs the end-to-end channel and a door for it:
//! a DERP server lets any key send, so the channel's admission is the node's
//! only door. That door is `--allow`, or, where the node's key is a member of
//! the net held here, the net's members alone (T-452, `Door`). A node with
//! no pair, and a door, serves the road unasked (the operator's ruling Q50)
//! and says so; `PODSSH_DERP=no` turns that off. Its record of pkarr names
//! its DERP home, at n0's server unless `PODSSH_IROH_PKARR` names another or
//! `off`, in a build with the iroh road (T-445, Q81, `node_record`). stdout
//! stays empty: the lines are on stderr.

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::derp::far::{self, Node, Roam};
use podssh_relay::derp::{self, dial, servers, Conn, Secret, Server, Ticket};
use podssh_relay::e2e::ends;
use podssh_relay::identity::file::{self as key_file, Place};
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

/// Whether a UDP TARGET is among the node's, which the DERP road cannot carry,
/// nor OpenTunnel's.
pub(crate) fn has_udp(args: &NodeArgs) -> bool {
    args.targets.iter().any(|t| t.starts_with("udp:") || t.contains("=udp:"))
}

/// Why a node with no `--derp` serves the DERP road, when it does: it has
/// no pair (none stored, or expired), and a door (an allowlist, or a net
/// that names its key, T-452), and nothing else asked of it needs the pair's
/// road (Q50).
pub(crate) fn unasked(args: &NodeArgs) -> Result<Option<String>, Refusal> {
    let other = args.derp || args.iroh || args.plain || args.no_e2e || args.opentunnel;
    if other || args.pair_file.is_some() || has_udp(args) {
        return Ok(None);
    }
    let Some(label) = args.name.as_deref().filter(|label| crate::pairs::check_label(label).is_ok()) else {
        return Ok(None);
    };
    let allowed = args.allow.is_some() || args.iroh_allow.is_some() || net_door(args, label);
    if !allowed || !fallback_on()? {
        return Ok(None);
    }
    Ok(crate::pairs::stored(label).err().map(|refusal| refusal.message))
}

/// Whether the net held here names the node's key as it is kept: the door
/// of a node with no `--allow` (T-452). A flag that cannot be used is the
/// later checks' to say.
pub(crate) fn net_door(args: &NodeArgs, label: &str) -> bool {
    let Ok(flags) = crate::node::key_flags(args) else { return false };
    let Ok(place) = crate::channel::node_place(label, flags.key.as_deref(), flags.ephemeral) else { return false };
    matches!(door(None, &place), Ok(Door::Net(_)))
}

/// Who comes in over the DERP road.
pub(crate) enum Door {
    /// The keys of `--allow`, and the net's members when the node is one.
    Allow(PathBuf),
    /// No `--allow`: the members of the net of this name alone (T-452).
    Net(String),
}

/// The door of a node of the DERP road, read before its key is made, as a
/// key made now is in no net: `--allow`, else the net held here when it
/// names the key kept at `place`. A node with neither is refused, as before
/// the net, as no client could come in.
pub(crate) fn door(allow: Option<&Path>, place: &Place) -> Result<Door, Refusal> {
    door_of("--derp", "a DERP server lets any key send to the node", allow, place)
}

/// The door of a node of the road of `flag`, which lets anyone in as
/// `why_open` says, by [`door`]'s rule: also the OpenTunnel road's (T-531).
pub(crate) fn door_of(flag: &str, why_open: &str, allow: Option<&Path>, place: &Place) -> Result<Door, Refusal> {
    if let Some(path) = allow {
        return Ok(Door::Allow(path.to_path_buf()));
    }
    let why = match key_file::existing(place) {
        Ok(Some(identity)) => match crate::net::admit::member_door(&identity.public()) {
            Ok(net) => return Ok(Door::Net(net)),
            Err(why) => why,
        },
        Ok(None) if matches!(place, Place::Ephemeral) => "a key for this run only is in no net".to_string(),
        Ok(None) => "the node has no key yet, so no net names it".to_string(),
        Err(why) => format!("the node's key: {why}"),
    };
    Err(Refusal::usage(format!(
        "{flag} needs --allow FILE, the client keys that may come in, or a key that the net held here names \
         ({why}): {why_open}"
    )))
}

/// The flags of the DERP road, checked before anything is read; its door is
/// `door`'s.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain {
        return Err(Refusal::usage("--plain is for the pair's road: the DERP road always runs the resumable layer"));
    }
    if args.opentunnel {
        return Err(Refusal::usage("--derp and --opentunnel are two roads: give one; run a second node for the other"));
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
    Ok(())
}

/// A node's DERP road, online: the node, its connection to its home, its
/// ticket, and the servers that it may move to.
pub(crate) struct Online {
    node: Node,
    first: Conn,
    pub ticket: Ticket,
    servers: Vec<Server>,
    /// The keeper of the node's record, told of each home (T-445).
    tell: crate::node_record::Tell,
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
            "no DERP server answered {} ({}); podssh doctor checks the way to them, and --opentunnel serves the \
             node through OpenTunnel instead",
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
    Ok(Online { node, first, ticket, servers: servers.to_vec(), tell: Default::default() })
}

impl Online {
    /// The node's home.
    pub(crate) fn home(&self) -> &Server {
        &self.ticket.server
    }

    /// With `tell`, which hears the ticket now and at each move, so that
    /// the node's record names its DERP home (T-445).
    pub(crate) fn telling(mut self, tell: crate::node_record::Tell) -> Online {
        tell.derp(&self.ticket);
        self.tell = tell;
        self
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
        let Online { node, first, ticket, servers, tell } = self;
        let say = node.say.clone();
        let moved: far::Moved = Arc::new(move |server: &Server| {
            let now = Ticket { server: server.clone(), ..ticket.clone() };
            say(format!("the home moved to the DERP server {server}; the ticket is now {now}"));
            tell.derp(&now);
        });
        far::serve_roaming(node, Roam { servers, moved }, Some(first), settings, budget, open, keeper).await;
    }
}

/// The settings of the layer on the DERP road: the iroh road's features, and
/// no window of the pair's relay (T-443).
pub(crate) fn settings() -> Settings {
    Settings { features: derp::FEATURES, ..crate::layered::settings().off_the_pair() }
}

/// Each check of the node that needs no network, done.
struct Ready {
    label: String,
    targets: Vec<Route>,
    roost: bool,
    key: podssh_relay::identity::file::Key,
    door: Door,
    servers: Vec<Server>,
    trust: Trust,
    /// The pair's road: the pair, and whether it came from the store; or
    /// why there is none.
    pair: Result<(Pair, bool), String>,
    /// Why the node serves the road unasked, when it does.
    unasked: Option<String>,
    /// The server of its record: n0's, or the one of PODSSH_IROH_PKARR (T-445, Q81).
    record: Option<crate::node_record::Named>,
}

fn prepare(args: &NodeArgs, unasked: Option<String>) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    check(args)?;
    let targets = crate::node::targets_of(&crate::node::words_of(args), args.no_e2e)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let door = door(flags.allow.as_deref(), &place)?;
    let servers = crate::ssh::derp::servers(args.derp_server.as_deref())?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    // A pair that `--pair-file` names must be good; a stored one may be
    // missing or expired, and the node then serves the DERP road alone.
    let pair = match &args.pair_file {
        Some(file) => Ok((crate::pairs::usable(crate::pairs::from_file(file)?, &label)?, false)),
        None => crate::pairs::stored(&label).map(|pair| (pair, true)).map_err(|refusal| refusal.message),
    };
    crate::pairs::online()?;
    crate::node_transit::check()?; // PODSSH_TRANSIT (T-436), before anything connects
    let record = crate::node_record::named()?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    // The key is made only once each check passed.
    let key = crate::channel::load_node_key(&place)?;
    crate::node_exit::ready(&label, &key.identity.public())?;
    Ok(Ready { label, targets, roost: args.sshd, key, door, servers, trust, pair, unasked, record })
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
    // A run of --restart beats from this runtime, while it polls (T-394).
    crate::detach::beat::keep(runtime.handle());
    // On the heap: Windows gives the main thread 1 MiB of stack.
    let code = runtime.block_on(Box::pin(serve(ready, err)));
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    code
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, door, servers, trust, pair, unasked, record } = ready;
    // TARGET first: a node that cannot reach it would serve no session.
    let target = match crate::node::probe(&targets, roost).await {
        Ok(versions) => crate::node::serving(&targets, &versions),
        Err(refusal) => return refusal.report("node", err),
    };
    let say: derp::Say = {
        let label = label.clone();
        Arc::new(move |line: String| {
            podssh_ssh::err_line!("podssh node: {label}: {line}");
            crate::detach::on_line("node", &line);
        })
    };
    let kept = match (&key.path, key.made) {
        (None, _) => "a key for this run only: the ticket lasts as long as the run".to_string(),
        (Some(path), true) => format!("a new key, in {}: the ticket is new", path.display()),
        (Some(path), false) => format!("in {}", path.display()),
    };
    // A key that an earlier run kept in another user's tree (T-593).
    let note = key.path.as_deref().and_then(podssh_relay::cache::kept_note);
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
    // With no --allow, the net is the door, and the first line says so (T-452).
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    let _ = writeln!(err, "podssh node: {label}: serving {target} over {roads} until Ctrl-C{by}");
    let _ = writeln!(err, "podssh node: {label}: key {public}, the node derp:{} ({kept})", public.hex());
    if let Some(note) = &note {
        let _ = writeln!(err, "podssh node: {label}: {note}");
    }
    let _ = writeln!(err, "podssh node: {label}: home {}, the first DERP server whose probe answered", road.home());
    let _ = writeln!(err, "podssh node: {label}: ticket {}", road.ticket);
    if let Door::Allow(allow) = &door {
        let _ = writeln!(err, "podssh node: {label}: {}", crate::channel::who_may(Some(allow.as_path())));
    }
    if let Some(line) = crate::net::admit::line(&public) {
        let _ = writeln!(err, "podssh node: {label}: {line}");
    }
    // Its record names its DERP home, now and at each move (T-445).
    let line = |words: String| {
        let _ = writeln!(err, "podssh node: {label}: {words}");
    };
    let (_record, tell) = crate::node_record::alone(record, &identity, &trust, say.clone(), line);
    let road = road.telling(tell);
    // The channel of T-088 on both roads, with this node's key and its door:
    // a session made on one road may resume on the other. With no --allow,
    // the net's members alone, also when the node leaves the net.
    let allow = match door {
        Door::Allow(path) => Some(path),
        Door::Net(_) => None,
    };
    // Grants used once (T-226), signed by the node's key or by its door's.
    let redeem = crate::grants::door(&label, public, allow.clone());
    let (admit, grant) = crate::net::admit::doors(allow, public, true);
    let channel =
        ends::Node { identity: identity.clone(), admit, say: say.clone(), redeem, leases: Default::default() };
    let routes = crate::node::routes_of(&targets, grant, roost, Some(public));
    let first = crate::node_exit::first(&targets);
    let (host, port) = (first.host, first.port);
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
    // The transit relay of Q65 for the pair's operators (T-436), beside the
    // pair's road and with its keeper.
    let transit = match (&pair, crate::node_transit::url()) {
        (Ok((pair, stored)), Some(url)) => crate::node_transit::road(&label, pair, *stored, &trust, url, say.clone()),
        _ => None,
    };
    let transit_open = open.clone();
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
        let pair_run = Box::pin(reverse::run(&mut config, Arc::new(layered), until_stopped(stopped.clone())));
        let exit = crate::node_transit::alongside(pair_run, transit, transit_open, keeper.clone()).await;
        expiry.abort();
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
