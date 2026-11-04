//! `podssh node NAME TARGET --opentunnel` (T-531): the node in front of the
//! TCP service TARGET over the OpenTunnel road of `podssh-relay` (T-530),
//! through `opentunnel.xyz`, which needs no account, or the service of
//! `PODSSH_OPENTUNNEL`. The node makes one tunnel and keeps it in the cache
//! with its token and its key, so that each start keeps its name and binds
//! no new CSR; the key and the CSR are this binary's, made as its ACME
//! client makes them ([`Keys`]). It says its name on stderr, which a client
//! gives as `--opentunnel-name`. With the pair NAME, or the one of
//! `--pair-file`, it serves the pair's road too, with one keeper for both, so
//! that a session resumes on either, and the transit relay's for the pair's
//! operators (T-436). A tunnel's name is in the logs of Certificate
//! Transparency and anyone may open a connection to it, so the road needs the
//! end-to-end channel and a door: `--allow`, or the net's members where the
//! node's key is one (T-452), as on the DERP road. A node with no pair, a
//! door, and the DERP road turned off (`PODSSH_DERP=no`), so with no other
//! road, serves it unasked, by the operator's ruling Q76, and says so;
//! `PODSSH_OPENTUNNEL=no` turns the road off. stdout stays empty.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends;
use podssh_relay::opentunnel::api::Api;
use podssh_relay::opentunnel::{self, dial, far, Credentials, Service, Setting, Store};
use podssh_relay::pair::Pair;
use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::{self, Layered, NodeConfig, TcpHandler, Wire};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::Settings;
use podssh_ws::{ProxyChoice, Trust};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::acme::certs;
use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The bound on a node's first tunnel when it serves the road unasked.
const UNASKED_LIMIT: Duration = Duration::from_secs(20);

/// The key of a tunnel's name and its CSR: a P-256 key of aws-lc-rs and the
/// CSR that rcgen writes, as the ACME client's (T-447).
pub(crate) struct Keys;

impl Credentials for Keys {
    fn key(&self) -> Result<Zeroizing<String>, String> {
        Ok(certs::Key::generate()?.pem())
    }

    fn csr(&self, key_pem: &str, hostname: &str) -> Result<String, String> {
        let der = certs::pem_block(key_pem, "PRIVATE KEY").ok_or("the tunnel's key is not PKCS #8 in PEM")?;
        let key = certs::Key::from_pkcs8(&der)?;
        Ok(certs::pem("CERTIFICATE REQUEST", &certs::tunnel_csr(hostname, &key)?))
    }
}

/// `PODSSH_OPENTUNNEL`, read: a value that is none of its forms is a setting
/// that cannot be used (78).
pub(crate) fn setting() -> Result<Setting, Refusal> {
    opentunnel::setting(std::env::var(opentunnel::ENV).ok().as_deref()).map_err(Refusal::config)
}

/// The service of the road, when the road is on.
pub(crate) fn service() -> Result<Option<Service>, Refusal> {
    Ok(match setting()? {
        Setting::On(service) => Some(service),
        Setting::Off => None,
    })
}

/// Why a node with no `--opentunnel` serves the road, when it does: it has
/// no pair (none stored, or expired), and a door, and nothing else asked of it
/// needs another road, and the DERP road, which would serve it unasked first,
/// is off: a node with no other road (Q76).
pub(crate) fn unasked(args: &NodeArgs) -> Result<Option<String>, Refusal> {
    let other = args.derp || args.iroh || args.plain || args.no_e2e || args.opentunnel || args.exit;
    if other || args.pair_file.is_some() || crate::node_derp::has_udp(args) || crate::node_derp::fallback_on()? {
        return Ok(None);
    }
    let Some(label) = args.name.as_deref().filter(|label| crate::pairs::check_label(label).is_ok()) else {
        return Ok(None);
    };
    let door = args.allow.is_some() || args.iroh_allow.is_some() || crate::node_derp::net_door(args, label);
    if !door || service()?.is_none() {
        return Ok(None);
    }
    Ok(crate::pairs::stored(label).err().map(|refusal| refusal.message))
}

/// The road of `args`, asked or unasked: the exit code of its run; none when
/// the node takes another road.
pub(crate) fn dispatch(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    let unasked = match unasked(args) {
        Ok(unasked) => unasked,
        Err(refusal) => return Some(refusal.report("node", err)),
    };
    (args.opentunnel || unasked.is_some()).then(|| run(args, unasked, err))
}

/// The flags of the road, checked before anything is read.
fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain {
        return Err(Refusal::usage(
            "--plain is for the pair's road: the OpenTunnel road always runs the resumable layer",
        ));
    }
    if args.no_e2e {
        return Err(Refusal::usage(
            "--no-e2e cannot go with --opentunnel: anyone may connect to a tunnel's name, so the end-to-end channel \
             and its allowlist are the node's only door",
        ));
    }
    if crate::node_derp::has_udp(args) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the OpenTunnel road carries TCP only"));
    }
    if args.exit {
        return Err(Refusal::usage("--exit goes on the pair's road and the DERP road: --opentunnel does not carry it"));
    }
    Ok(())
}

/// The trust of the service: OpenTunnel's own, a public service, takes the
/// host's (`SSL_CERT_FILE`, else the default stores), never the pair relay's
/// `--ca-file`; a service that `PODSSH_OPENTUNNEL` names takes the pair's, as
/// it may be the user's own, under the same CA.
fn trust_for(service: &Service, pair: &Trust) -> Trust {
    if *service == Service::hosted() {
        crate::pairs::trust(None)
    } else {
        pair.clone()
    }
}

/// Each check of the node that needs no network, done.
struct Ready {
    label: String,
    targets: Vec<Route>,
    roost: bool,
    key: podssh_relay::identity::file::Key,
    door: Door,
    service: Service,
    trust: Trust,
    pair: Result<(Pair, bool), String>,
    unasked: Option<String>,
}

fn prepare(args: &NodeArgs, unasked: Option<String>) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key and its tunnel")?;
    crate::pairs::check_label(&label)?;
    check(args)?;
    let Some(service) = service()? else {
        return Err(Refusal::usage(format!("--opentunnel: {}=no turns the OpenTunnel road off", opentunnel::ENV)));
    };
    let targets = crate::node::targets_of(&crate::node::words_of(args), args.no_e2e)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let why_open = "anyone may connect to a tunnel's name, which the logs of Certificate Transparency show";
    let door = crate::node_derp::door_of("--opentunnel", why_open, flags.allow.as_deref(), &place)?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    let pair = match &args.pair_file {
        Some(file) => Ok((crate::pairs::usable(crate::pairs::from_file(file)?, &label)?, false)),
        None => crate::pairs::stored(&label).map(|pair| (pair, true)).map_err(|refusal| refusal.message),
    };
    crate::pairs::online()?;
    crate::node_transit::check()?; // PODSSH_TRANSIT (T-436), before anything connects
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    // The key is made only once each check passed.
    let key = crate::channel::load_node_key(&place)?;
    Ok(Ready { label, targets, roost: args.sshd, key, door, service, trust, pair, unasked })
}

/// Run the node of the OpenTunnel road; `unasked` is why it serves the road
/// with no `--opentunnel`. Returns the process exit code.
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

/// The settings of the layer on the road: no window of the pair's relay.
pub(crate) fn settings() -> Settings {
    crate::layered::settings().off_the_pair()
}

/// The line of where the tunnel is kept.
fn kept_line(path: Option<&PathBuf>, made: bool) -> String {
    match (path, made) {
        (Some(path), true) => format!("a new tunnel, kept in {}", path.display()),
        (Some(path), false) => format!("the tunnel kept in {}", path.display()),
        (None, _) => "a tunnel that no directory of the cache took: each start makes a new one".to_string(),
    }
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, door, service, trust, pair, unasked } = ready;
    // TARGET first: a node that cannot reach it would serve no session.
    let target = match crate::node::probe(&targets, roost).await {
        Ok(versions) => crate::node::serving(&targets, &versions),
        Err(refusal) => return refusal.report("node", err),
    };
    let say: opentunnel::Say = {
        let label = label.clone();
        Arc::new(move |line: String| {
            podssh_ssh::err_line!("podssh node: {label}: {line}");
            crate::detach::on_line("node", &line);
        })
    };
    let identity = Arc::new(key.identity);
    let api = Api::new(service.clone(), dial::tls(trust_for(&service, &trust), ProxyChoice::FromEnvironment));
    let reach = far::online(api, Store::cache(&service, &label), &Keys, say.clone());
    // Unasked, a node that cannot reach the service ends soon, as it would
    // with no road; asked, it takes the service's own retries.
    let reached = match unasked {
        Some(_) => tokio::time::timeout(UNASKED_LIMIT, reach)
            .await
            .unwrap_or_else(|_| Err(format!("no tunnel within {} s", UNASKED_LIMIT.as_secs()))),
        None => reach.await,
    };
    let (node, provisioned) = match reached {
        Ok(online) => online,
        Err(why) => {
            let message = format!("no OpenTunnel road through {service}: {why}");
            return Refusal { message, code: Fault::RelayUnreachable.code() }.report("node", err);
        }
    };
    if let Some(why) = &unasked {
        let _ = writeln!(
            err,
            "podssh node: {label}: {why}; so the node serves the OpenTunnel road unasked, through {service}, by the \
             operator's ruling Q76 ({}=no turns it off)",
            opentunnel::ENV
        );
    }
    let roads = match &pair {
        Ok((pair, _)) => format!(
            "the OpenTunnel road and the pair's road through {} (the pair expires {})",
            pair.relay.host,
            crate::pairs::utc(pair.expires_ms)
        ),
        Err(why) if unasked.is_none() => format!("the OpenTunnel road alone ({why})"),
        Err(_) => "the OpenTunnel road alone".to_string(),
    };
    let public = identity.public();
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    let name = node.name();
    let _ = writeln!(err, "podssh node: {label}: serving {target} over {roads} until Ctrl-C{by}");
    let _ = writeln!(err, "podssh node: {label}: key {public}");
    let _ = writeln!(err, "podssh node: {label}: {}", kept_line(provisioned.path.as_ref(), provisioned.made));
    let _ = writeln!(err, "podssh node: {label}: name {name} (podssh ssh node://{label} --opentunnel-name {name})");
    let _ = writeln!(
        err,
        "podssh node: {label}: TLS ends at this host; {service} sees the name, the times and the sizes, and the \
         end-to-end channel keeps the bytes"
    );
    if let Door::Allow(allow) = &door {
        let _ = writeln!(err, "podssh node: {label}: {}", crate::channel::who_may(Some(allow.as_path())));
    }
    if let Some(line) = crate::net::admit::line(&public) {
        let _ = writeln!(err, "podssh node: {label}: {line}");
    }
    // The channel of T-088 on both roads, with this node's key and its door.
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
    let transit = match (&pair, crate::node_transit::url()) {
        (Ok((pair, stored)), Some(url)) => crate::node_transit::road(&label, pair, *stored, &trust, url, say.clone()),
        _ => None,
    };
    let transit_open = open.clone();
    let (stop, stopped) = watch::channel(false);
    let until_stopped = |mut stopped: watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    let has_pair = pair.is_ok();
    let tunnel_road = async {
        tokio::select! {
            why = Box::pin(far::serve_kept(node, settings(), budget, open, keeper.clone())) => Some(why),
            () = until_stopped(stopped.clone()) => None,
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
            (channel.say)(format!("the pair's road ended: {why}; the OpenTunnel road goes on"));
        }
    };
    // Until Ctrl-C, or until both roads ended by themselves.
    let both = async { tokio::join!(tunnel_road, pair_road) };
    tokio::pin!(both);
    let ended = tokio::select! {
        (ended, ()) = &mut both => ended,
        () = crate::node::stop_signal() => {
            let _ = stop.send(true);
            both.await.0
        }
    };
    match ended {
        // The service refused the tunnel for good: with no pair, nothing serves.
        Some(why) if !has_pair => {
            let message = format!("the OpenTunnel road ended: {why}");
            Refusal { message, code: Fault::RelayUnreachable.code() }.report("node", err)
        }
        _ => {
            let _ = writeln!(err, "podssh node: {label}: stopped");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binary_s_keys_make_a_tunnel_s_csr_from_its_own_pem() {
        let key = Keys.key().unwrap();
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
        let csr = Keys.csr(&key, "abcdefghijkl.opentunnel.xyz").unwrap();
        assert!(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"), "{csr}");
        assert!(Keys.csr("no key", "abcdefghijkl.opentunnel.xyz").is_err());
    }

    #[test]
    fn opentunnel_s_service_takes_the_host_s_trust_and_a_named_one_the_pair_s() {
        let pair = Trust::File("/the/pair/relay/ca.pem".into());
        let own = Service::parse("https://tunnels.example.test").unwrap();
        assert!(
            matches!(trust_for(&own, &pair), Trust::File(ref f) if f == std::path::Path::new("/the/pair/relay/ca.pem"))
        );
    }

    #[test]
    fn a_node_of_the_road_takes_no_flag_that_would_open_its_door_or_change_its_road() {
        let base = || NodeArgs {
            name: Some("lab".into()),
            targets: vec!["127.0.0.1:22".into()],
            opentunnel: true,
            ..NodeArgs::default()
        };
        for (flag, args) in [
            ("--plain", NodeArgs { plain: true, ..base() }),
            ("--no-e2e", NodeArgs { no_e2e: true, ..base() }),
            ("udp:", NodeArgs { targets: vec!["udp:127.0.0.1:53".into()], ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
        ] {
            let refusal = check(&args).unwrap_err();
            assert_eq!(refusal.code, 64, "{flag}: {}", refusal.message);
            assert!(refusal.message.contains(flag), "{flag}: {}", refusal.message);
        }
        assert!(check(&base()).is_ok());
    }
}
