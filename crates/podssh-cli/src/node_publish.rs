//! `podssh node NAME --publish-tls TARGET` (T-649, GitHub #147): the node of
//! a pair whose sessions are a site that podssh's relay role publishes by its
//! name (`podssh relay serve --publish SITE=PAIR`). The role sends each TLS
//! connection whose ClientHello names SITE here, before any handshake and
//! with each byte untouched, as one session of the pair. Each session is one
//! connection to TARGET, a TLS service of this host, carried as it came, with
//! no resumable layer and no end-to-end channel, which a visitor speaks
//! neither of; so TARGET's own certificate answers, and the role holds no key
//! of the name. With `--acme SITE`, the node ends TLS itself with a
//! certificate for SITE from ACME's TLS-ALPN-01, whose validation the role
//! routes here too, and TARGET gets the cleartext (`node_publish_end`). The
//! first line names the pair that `--publish` names, and says what the role
//! sees: the name, never the bytes.

use std::io::Write;
use std::sync::Arc;

use podssh_relay::pair::Pair;
use podssh_relay::reverse::routes::Route;
use podssh_relay::reverse::{self, Exit, NodeConfig, Settings, TcpHandler, Wire};
use podssh_ws::dial::ProxyChoice;
use podssh_ws::Trust;
use tokio::sync::Notify;

use crate::node::{NodeArgs, DIAL_LIMIT};
use crate::node_publish_end::Ending;
use crate::pairs;
use crate::relay_settings::Refusal;

/// What the node was asked for, checked before anything connects.
struct Ready {
    label: String,
    pair: Pair,
    /// The pair came from the store, whose copy goes when the relay says
    /// that the pair was stopped.
    stored: bool,
    target: Route,
    trust: Trust,
    /// The node's own TLS, with `--acme`.
    ending: Option<Ending>,
}

/// The node of `--publish-tls`; `None` without the flag, when `--acme` and
/// `--acme-directory`, which go with it alone, are refused.
pub fn run(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    let Some(target) = args.publish_tls.as_deref() else {
        if args.acme.is_some() || args.acme_directory.is_some() {
            let why = "--acme and --acme-directory end the TLS of a published site: they go with --publish-tls TARGET";
            return Some(Refusal::usage(why).report("node", err));
        }
        return None;
    };
    if let Err(refusal) = refused(args) {
        return Some(refusal.report("node", err));
    }
    // --detach (T-380), as each other road of the node takes it.
    if args.detach && !crate::detach::is_child() {
        return Some(crate::detach::start("node", args.restart, args.detach_name.as_deref(), err));
    }
    let ready = match prepare(args, target) {
        Ok(ready) => ready,
        Err(refusal) => return Some(refusal.report("node", err)),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh node: could not start the async runtime: {e}");
            return Some(crate::exitmap::Fault::SessionFault.code());
        }
    };
    // A run of --restart beats from this runtime, while it polls (T-394).
    crate::detach::beat::keep(runtime.handle());
    let code = runtime.block_on(serve(ready, err));
    runtime.shutdown_background();
    Some(code)
}

/// Each flag that a published site does not take: its sessions are a
/// visitor's TLS, so no other road, no layer, no channel and no route of
/// the node's serves them; a TARGET is the flag's own.
fn refused(args: &NodeArgs) -> Result<(), Refusal> {
    let flags = crate::node_flags::key_flags(args)?;
    let others = [
        (!args.targets.is_empty(), "a TARGET beside it (--publish-tls names the one)"),
        (args.carrier.is_some(), "--carrier"),
        (args.temporary.is_some(), "--temporary"),
        (args.iroh, "--iroh"),
        (args.derp || args.derp_server.is_some(), "--derp"),
        (args.opentunnel, "--opentunnel"),
        (args.quick_tunnel || args.warp || args.relay, "--quick-tunnel"),
        (args.exit || args.routes.is_some(), "--exit"),
        (args.sshd, "--sshd"),
        (args.resume_deadline.is_some(), "--resume-deadline"),
        (flags.key.is_some() || flags.ephemeral || flags.allow.is_some(), "--key, --ephemeral-key or --allow"),
        (args.grant_to.is_some() || args.revoked.is_some(), "a grant"),
        (args.ask, "--ask"),
        ((args.restart || args.detach_name.is_some()) && !args.detach, "--restart or --detach-name with no --detach"),
    ];
    match others.iter().find(|(given, _)| *given) {
        Some((_, what)) => Err(Refusal::usage(format!(
            "--publish-tls serves the pair's sessions as a visitor's TLS, with no resumable layer, no end-to-end \
             channel and no other road: {what} does not go with it"
        ))),
        None => Ok(()),
    }
}

/// The checks that need no network: the label, TARGET, the pair, the trust
/// and the certificate's name.
fn prepare(args: &NodeArgs, target: &str) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the label of a pair (podssh relay pair NAME)")?;
    pairs::check_label(&label)?;
    let (host, port) = crate::proxy::parse_target(Some(target), None)
        .map_err(|why| Refusal::usage(format!("--publish-tls {target}: {why}")))?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    let (pair, stored) = match &args.pair_file {
        Some(file) => (pairs::usable(pairs::from_file(file)?, &label)?, false),
        None => (pairs::stored(&label)?, true),
    };
    pairs::online()?;
    let trust = pairs::trust(args.ca_file.as_deref());
    let ending = match args.acme.as_deref() {
        Some(name) => Some(Ending::open(name, args.acme_directory.as_deref(), trust.clone())?),
        None => None,
    };
    Ok(Ready { label, pair, stored, target: Route { name: None, host, port }, trust, ending })
}

async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, pair, stored, target, trust, ending } = ready;
    // TARGET first, once: a node that cannot reach it would refuse each
    // visitor.
    if let Err(refusal) = crate::node::probe(std::slice::from_ref(&target), false).await {
        return refusal.report("node", err);
    }
    let at = podssh_ws::dial::authority(&target.host, target.port);
    let how = match &ending {
        None => format!("{at}, a TLS service of this host whose certificate answers, its bytes as they came"),
        Some(end) => format!("{at} in cleartext, this node ending TLS {}", end.shown()),
    };
    let name = pair.name.clone();
    let _ = writeln!(
        err,
        "podssh node: {label}: publishing {how}, through {} as its pair {name}, which podssh relay serve --publish \
         SITE={name} sends here by the name of each ClientHello: the relay reads that name, never the bytes; with no \
         resumable layer and no end-to-end channel, until Ctrl-C; the pair expires {}",
        pair.relay.host,
        pairs::utc(pair.expires_ms)
    );
    // The lines as each node's, and the first `online`, after which a CA's
    // validation of the name can reach this node.
    let online = Arc::new(Notify::new());
    let say: crate::node_expiry::Say = Arc::new({
        let (label, online) = (label.clone(), online.clone());
        move |line: String| {
            if line.starts_with("online") {
                online.notify_one();
            }
            podssh_ssh::err_line!("podssh node: {label}: {line}");
            crate::detach::on_line("node", &line);
        }
    });
    crate::node_upgrade::lines(say.clone());
    // Its expiry said before it comes, and its renewal at podssh's relay
    // role, which keeps the pair's name that --publish names (T-395, T-592).
    let (repair, expiry) = crate::node_expiry::watch(&label, &pair, stored, say.clone(), &trust);
    let proxy = ProxyChoice::FromEnvironment;
    let mut config = NodeConfig {
        pair,
        label: stored.then(|| label.clone()),
        trust: &trust,
        proxy: &proxy,
        timeout: pairs::REQUEST_LIMIT,
        settings: Settings::default(),
        repair,
        wire: Wire::Tls,
        say: Some(&*say),
    };
    let ended = match ending {
        None => {
            let tcp = TcpHandler { host: target.host, port: target.port, timeout: DIAL_LIMIT, sshd: false };
            Ok(Box::pin(reverse::run(&mut config, Arc::new(tcp), crate::node_upgrade::stop())).await)
        }
        Some(end) => Box::pin(end.run(&mut config, &target, online, say.clone())).await,
    };
    expiry.abort();
    match ended {
        Ok(exit) => crate::node_upgrade::or_finish(|| finish(&label, exit, err)).await,
        // The first order of a certificate failed: no TLS to end.
        Err(why) => {
            crate::journal::line(err, podssh_ssh::LogLevel::Error, &format!("podssh node: {label}: {why}"));
            crate::exitmap::sysexits::EX_UNAVAILABLE
        }
    }
}

/// The exit code of the node's end, as each node of the pair's road says it.
fn finish(label: &str, exit: Exit, err: &mut dyn Write) -> i32 {
    let Some((fault, why)) = crate::node::ended(label, exit) else {
        let _ = writeln!(err, "podssh node: {label}: stopped");
        return 0;
    };
    crate::journal::line(err, podssh_ssh::LogLevel::Error, &format!("podssh node: {label}: {why}"));
    fault.code()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(more: impl FnOnce(&mut NodeArgs)) -> NodeArgs {
        let mut args =
            NodeArgs { name: Some("site".into()), publish_tls: Some("127.0.0.1:8443".into()), ..NodeArgs::default() };
        more(&mut args);
        args
    }

    // T-649: a published site takes no other road, layer, channel or route.
    #[test]
    fn a_published_site_refuses_each_flag_of_another_road_or_of_the_channel() {
        assert!(refused(&args(|_| {})).is_ok());
        assert!(refused(&args(|a| (a.plain, a.no_e2e) = (true, true))).is_ok(), "what it is already");
        // A change of the flags, and the words of its refusal.
        type Case = (fn(&mut NodeArgs), &'static str);
        let cases: [Case; 8] = [
            (|a| a.targets = vec!["127.0.0.1:22".into()], "a TARGET beside it"),
            (|a| a.carrier = Some("stdio".into()), "--carrier"),
            (|a| a.iroh = true, "--iroh"),
            (|a| a.quick_tunnel = true, "--quick-tunnel"),
            (|a| a.exit = true, "--exit"),
            (|a| a.allow = Some("keys".into()), "--allow"),
            (|a| a.resume_deadline = Some("1h".into()), "--resume-deadline"),
            (|a| a.restart = true, "--restart"),
        ];
        for (given, says) in cases {
            let refusal = refused(&args(given)).unwrap_err();
            assert_eq!(refusal.code, crate::exit_codes::EXIT_USAGE, "{says}");
            assert!(refusal.message.contains(says) && refusal.message.contains("does not go with it"), "{refusal:?}");
        }
    }

    // T-649: --acme without --publish-tls is refused, and with neither the
    // node goes on to its other roads.
    #[test]
    fn acme_goes_with_publish_tls_alone() {
        let mut err = Vec::new();
        let plain = NodeArgs { name: Some("site".into()), ..NodeArgs::default() };
        assert_eq!(run(&plain, &mut err), None);
        let acme = NodeArgs { acme: Some("site.example.org".into()), ..plain };
        assert_eq!(run(&acme, &mut err), Some(crate::exit_codes::EXIT_USAGE));
        assert!(String::from_utf8_lossy(&err).contains("they go with --publish-tls TARGET"));
    }
}
