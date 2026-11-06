//! `podssh node NAME TARGET --frp FILE` (T-498): the node in front of the
//! TCP service TARGET through the user's own frps, as an frpc of it: the
//! node logs in with frps's token and registers an STCP service of its name
//! with the file's secret, which has no public port; each visitor's work
//! connection is a link of the resumable layer, with the end-to-end channel
//! above it, served by the layer's far end with the node's keeper, so that a
//! session resumes on its next link (`podssh_ws::frp`, `crate::frp_file`).
//! frps sees the service's name, the times and the sizes; the channel keeps
//! the bytes. A visitor holds the STCP secret, but the node's door is still
//! its own: `--allow`, or the net's members where the node's key is one, as
//! on the DERP road. The road runs alone, with no pair. stdout stays empty.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends;
use podssh_relay::reverse;
use podssh_relay::reverse::routes::Route;
use podssh_relay::session::record::Role;
use podssh_relay::session::{far, Settings};
use podssh_ws::frp;

use crate::exitmap::Fault;
use crate::frp_file::{self, Frp};
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// The node of `--frp`, or of `PODSSH_FRP` when no other road is asked:
/// the process exit code; `None` when neither names a file.
pub(crate) fn dispatch(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    let path = args.frp.clone().or_else(|| std::env::var(frp_file::ENV).ok().filter(|p| !p.trim().is_empty()))?;
    Some(run(args, &path, err))
}

/// The flags that the road takes, checked before anything connects.
fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain {
        return Err(Refusal::usage("--plain is for the pair's road: the frp road always runs the resumable layer"));
    }
    if args.no_e2e {
        return Err(Refusal::usage(
            "--no-e2e cannot go with --frp: frps would see each byte, and the end-to-end channel and its allowlist \
             are the node's door",
        ));
    }
    if crate::node_derp::has_udp(args) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the frp road carries TCP only"));
    }
    if args.exit {
        return Err(Refusal::usage("--exit goes on the pair's road and the DERP road: --frp does not carry it"));
    }
    if args.iroh || args.derp || args.opentunnel || args.quick_tunnel {
        return Err(Refusal::usage("--frp is the node's one road: it goes with no other road's flag"));
    }
    Ok(())
}

/// Each check of the node that needs no network, done.
struct Ready {
    label: String,
    frp: Frp,
    targets: Vec<Route>,
    roost: bool,
    key: podssh_relay::identity::file::Key,
    door: Door,
}

fn prepare(args: &NodeArgs, path: &str) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, the name of its STCP service")?;
    crate::pairs::check_label(&label)?;
    check(args)?;
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    let frp = frp_file::read(path, trust, &format!("--frp {path}"))?;
    let targets = crate::node::targets_of(&crate::node::words_of(args), args.no_e2e)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let why_open = "anyone who holds the STCP secret reaches the node through frps";
    let door = crate::node_derp::door_of("--frp", why_open, flags.allow.as_deref(), &place)?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    crate::pairs::online()?;
    let key = crate::node_upgrade::parts::node_key(&place)?;
    Ok(Ready { label, frp, targets, roost: args.sshd, key, door })
}

/// Run the node of the frp road: the process exit code.
pub fn run(args: &NodeArgs, path: &str, err: &mut dyn Write) -> i32 {
    let ready = match prepare(args, path) {
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
    let mut code = runtime.block_on(Box::pin(serve(ready, err)));
    // An upgrade whose binary did not start: this one serves again (T-679).
    while code == crate::node_upgrade::AGAIN {
        code = match prepare(args, path) {
            Ok(ready) => runtime.block_on(Box::pin(serve(ready, err))),
            Err(refusal) => refusal.report("node", err),
        };
    }
    runtime.shutdown_background();
    code
}

/// The settings of the layer on the road: no window of the pair's relay.
fn settings() -> Settings {
    crate::layered::settings().off_the_pair()
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, frp, targets, roost, key, door } = ready;
    // TARGET first: a node that cannot reach it would serve no session.
    let target = match crate::node::probe(&targets, roost).await {
        Ok(versions) => crate::node::serving(&targets, &versions),
        Err(refusal) => return refusal.report("node", err),
    };
    let say: frp::node::Say = {
        let label = label.clone();
        Arc::new(move |line: String| {
            podssh_ssh::err_line!("podssh node: {label}: {line}");
            crate::detach::on_line("node", &line);
        })
    };
    let service = frp.name.clone().unwrap_or_else(|| label.clone());
    let identity = Arc::new(key.identity);
    let public = identity.public();
    let shown = frp.road.server.shown();
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    let _ = writeln!(err, "podssh node: {label}: serving {target} over the frp road through {shown} until Ctrl-C{by}");
    let _ = writeln!(err, "podssh node: {label}: key {public}");
    let _ = writeln!(
        err,
        "podssh node: {label}: frps sees the STCP service {service}, the times and the sizes; the end-to-end channel \
         keeps the bytes"
    );
    let allow = match door {
        Door::Allow(path) => Some(path),
        Door::Net(_) => None,
    };
    let redeem = crate::grants::door(&label, public, allow.clone());
    let (admit, grant) = crate::net::admit::doors(allow, public, true);
    let gate = crate::node_ask::gate();
    let channel =
        ends::Node { identity: identity.clone(), admit, say: say.clone(), redeem, leases: Default::default(), gate };
    let routes = crate::node::routes_of(&targets, grant, roost, Some(public));
    let first = crate::node_exit::first(&targets);
    let (host, port) = (first.host, first.port);
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
    let keeper = crate::node_upgrade::channel_keeper(&channel, settings().resume_deadline);
    crate::node_upgrade::lines(say.clone());
    // Each work connection that a visitor took is one link of the layer.
    let work = {
        let keeper = keeper.clone();
        move |link: tokio::io::DuplexStream| {
            let (keeper, open) = (keeper.clone(), open.clone());
            async move { far::serve(link, Role::NODE, settings(), &keeper, budget, open).await }
        }
    };
    let road = frp::node::serve(frp.road, service, say.clone(), work);
    tokio::select! {
        why = road => {
            let message = format!("the frp road ended: {why}");
            Refusal { message, code: Fault::RelayUnreachable.code() }.report("node", err)
        }
        () = crate::node_upgrade::stop() => {
            crate::node_upgrade::or_finish(|| {
                let _ = writeln!(err, "podssh node: {label}: stopped");
                0
            })
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_of_the_road_takes_no_flag_that_would_open_its_door_or_add_a_road() {
        let base = || NodeArgs {
            name: Some("lab".into()),
            targets: vec!["127.0.0.1:22".into()],
            frp: Some("/a/file".into()),
            ..NodeArgs::default()
        };
        for (flag, args) in [
            ("--plain", NodeArgs { plain: true, ..base() }),
            ("--no-e2e", NodeArgs { no_e2e: true, ..base() }),
            ("udp:", NodeArgs { targets: vec!["udp:127.0.0.1:53".into()], ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
            ("another road", NodeArgs { derp: true, ..base() }),
        ] {
            let refusal = check(&args).unwrap_err();
            assert_eq!(refusal.code, 64, "{flag}: {}", refusal.message);
        }
        assert!(check(&base()).is_ok());
    }
}
