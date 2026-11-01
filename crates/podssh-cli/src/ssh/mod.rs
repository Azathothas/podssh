//! `podssh ssh`: the native client. The command line is resolved first
//! ([`resolve`]), so a bad one fails before anything connects; then the first
//! hop is reached through the relay (or directly with `--direct`) and
//! `podssh-ssh` does the rest.
//!
//! Exit codes follow OpenSSH: the remote command's status, 128 + a signal
//! number when it was killed, 255 for podssh's own failures. A usage error is
//! 64, and a bad relay variable 78, before anything is attempted.

mod agents;
pub mod args;
mod attach;
// The server's version line, for doctor and the direct road (T-363).
pub(crate) mod banner;
// iap:// and eice://, a cloud's own tunnel to a VM (T-351).
pub mod cloud;
pub mod cloudflare;
pub mod config;
pub mod control;
// derp:TICKET, and the DERP road of node://NAME (T-379).
pub mod derp;
pub mod dump;
mod elevate;
// `--expect` and `--send` (T-191).
pub mod expect;
pub mod forward;
pub(crate) mod hop;
pub mod iroh;
mod jump;
pub mod keywords;
mod local_bind;
// `LocalCommand` and `PermitLocalCommand` (T-191).
pub mod local_command;
pub mod local_spec;
mod login;
pub mod node;
pub mod options;
pub mod persist;
pub mod picker;
mod recording;
pub mod resolve;
mod resolve_env;
pub mod result;
// The race of a node's roads: iroh, the pair's, DERP (T-164, T-379).
pub(crate) mod roads;
pub mod tokens;
pub mod transport;
mod upgrade;
pub mod x11;

use std::io::Write;
use std::sync::Arc;

use podssh_ssh::relay_stream::RelayEnd;
use podssh_ssh::retry::Retry;
use podssh_ssh::{Log, LogLevel, EXIT_FAILURE};

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::pager::Tty;
use crate::session_log::Place;
use crate::snippets::Asking;
use args::SshArgs;
use resolve::{Env, Resolved, Transport};

/// Run `podssh ssh`; returns the process exit code. With `--result-file`,
/// the run's result is written at its end, on each path (T-054). `tty` says
/// whether stdin and stdout are terminals, for the host picker (T-188).
pub fn run_ssh(args: &SshArgs, tty: Tty, err: &mut dyn Write) -> i32 {
    // A service of this run, or the variables of one, before anything reads them (T-393).
    if let Some(code) = crate::node_install::ssh::first(args, err) {
        return code;
    }
    let (started, start_ms) = (std::time::Instant::now(), crate::pairs::now_ms());
    if args.result_file.as_deref() == Some("-") {
        let _ = writeln!(err, "podssh ssh: --result-file -: stdout carries the command's output; name a file");
        return EXIT_USAGE;
    }
    // The session log (T-056): a value that is not one is refused first.
    let log = match crate::session_log::place() {
        Ok(place) => place,
        Err(refusal) => return refusal.report("ssh", err),
    };
    let code = run(args, tty, err);
    let object = result::object(code, started);
    // With no failure class, the code is the remote command's, or a
    // session's that ended with none: no failure of podssh (T-195).
    if object["failure"].is_null() {
        crate::error_program::not_a_failure();
    }
    if let Some(path) = &args.result_file {
        result::write(path, &object, err);
    }
    if let Some(line) = crate::session_log::ssh_line(start_ms, &object).filter(|_| log != Place::Off) {
        if let Err(why) = crate::session_log::append(&log, &line) {
            let _ = writeln!(err, "podssh ssh: the session log: {why}");
        }
    }
    code
}

fn run(args: &SshArgs, tty: Tty, err: &mut dyn Write) -> i32 {
    if args.version {
        let _ = writeln!(err, "podssh {} (SSH: russh, aws-lc-rs)", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    let env = Env::from_process();
    // No destination, and a person at the terminal (T-188): a `Host` name of
    // ssh_config, picked from a list; in each other case the run refuses as
    // before.
    let picked = match picker::pick(args, tty, &env, &mut picker::Terminal) {
        Ok(picked) => picked,
        Err(refusal) => return refusal.report("ssh", err),
    };
    let args = picked.as_ref().unwrap_or(args);
    // `--attach DEST` alone lists the kept shells at DEST (T-158).
    let listed = attach::listing(args);
    let args = listed.as_ref().unwrap_or(args);
    // Before anything is resolved or connects: the road is not in this build.
    if let Some(destination) = args.destination.as_deref().filter(|d| iroh::is_iroh(d) && !cfg!(feature = "iroh")) {
        let _ = writeln!(err, "podssh ssh: {}", iroh::refusal(destination));
        return EXIT_NOT_IMPLEMENTED;
    }
    if args.iroh_ticket.is_some() && !cfg!(feature = "iroh") {
        let _ = writeln!(err, "podssh ssh: {}", iroh::not_built("--iroh-ticket"));
        return EXIT_NOT_IMPLEMENTED;
    }
    // WARP's road is in a build with the feature `warp` alone (T-352).
    let unbuilt = |d: &&str| cloud::warp::is_warp(d) && !cfg!(feature = "warp");
    if let Some(destination) = args.destination.as_deref().filter(unbuilt) {
        let _ = writeln!(err, "podssh ssh: {}", cloud::warp::not_built(destination));
        return EXIT_NOT_IMPLEMENTED;
    }
    // The Tor road is in a build with the feature `tor` alone (T-353).
    let unbuilt = |d: &&str| cloud::tor::is_tor(d) && !cfg!(feature = "tor");
    if let Some(destination) = args.destination.as_deref().filter(unbuilt) {
        let _ = writeln!(err, "podssh ssh: {}", cloud::tor::not_built(destination));
        return EXIT_NOT_IMPLEMENTED;
    }
    if let Err(refusal) = crate::pins::apply(args.relay_addr.as_deref()) {
        return refusal.report("ssh", err);
    }
    // This client's own deadline only shortens the far end's (T-306).
    if let Err(refusal) = crate::layered::own_deadline(args.resume_deadline.as_deref()) {
        return refusal.report("ssh", err);
    }
    // A snippet (T-187): its command as written goes through the resolve,
    // and its values go in once the connection is known.
    let chosen = match crate::snippets::choose(args, &env.settings.snippets) {
        Ok(chosen) => chosen,
        Err(refusal) => return refusal.report("ssh", err),
    };
    let args = chosen.as_ref().map_or(args, |(args, _)| args);
    let mut resolved = match resolve::resolve_or_refuse(args, &env) {
        Ok(r) => r,
        Err(refusal) => return refusal.report("ssh", err),
    };
    // Shown and asked before anything connects; -G runs nothing.
    if let Some((_, snippet)) = chosen.as_ref().filter(|_| !args.print_config) {
        let options = &resolved.options;
        let asking = Asking { yes: args.yes, quiet: options.log_level < LogLevel::Info, batch: options.batch_mode };
        let label = args.destination.clone().unwrap_or_default();
        if let Err(refusal) = crate::snippets::settle("ssh", snippet, vec![(label, &mut resolved)], asking, err) {
            return refusal.report("ssh", err);
        }
    }
    // -G: the settings, and nothing opened: no relay, no token, no pool.
    if args.print_config {
        let mut out = std::io::stdout().lock();
        for line in dump::lines(&resolved) {
            let _ = writeln!(out, "{line}");
        }
        return 0;
    }
    if (args.restart || args.detach_name.is_some()) && !resolved.detach {
        let _ =
            writeln!(err, "podssh ssh: --restart and --detach-name are for a detached run; give -f or --detach too");
        return EXIT_USAGE;
    }
    // -f, --detach and ForkAfterAuthentication (T-380): the run goes on in
    // this binary started again, which says when its request went.
    if resolved.detach && resolved.control.command.is_none() {
        if matches!(resolved.options.request, podssh_ssh::Request::Shell | podssh_ssh::Request::StdioForward(_)) {
            let _ = writeln!(
                err,
                "podssh ssh: -f goes to the background with a command or -N, as OpenSSH's: a shell or -W needs this \
                 terminal"
            );
            return EXIT_USAGE;
        }
        if !crate::detach::is_child() {
            return crate::detach::start("ssh", args.restart, args.detach_name.as_deref(), err);
        }
        // As OpenSSH's -f: a command reads no stdin (-n).
        resolved.options.stdin_null = true;
        crate::detach::when_requested("ssh");
        // A relative path that the run reads again (a key at a reconnect, a
        // known_hosts that takes a new key), as ssh_config may write it,
        // keeps the caller's directory at ready (T-397).
        let o = &resolved.options;
        if o.identity_files.iter().chain(&o.user_known_hosts).chain(&o.global_known_hosts).any(|p| p.is_relative()) {
            crate::detach::stay_here();
        }
    }
    // One run of an installed service at a time; the parent of -f held none.
    if let Some(code) = crate::node_install::lock::enter("ssh", args.env_file.as_deref(), err) {
        return code;
    }
    // LocalCommand's shell, before anything connects (T-191).
    if let Err(refusal) = local_command::shell(&mut resolved.options) {
        return refusal.report("ssh", err);
    }
    // The destination of the session log; an -O request is no session.
    if resolved.control.command.is_none() {
        let destination = &resolved.options.destination;
        crate::session_log::target(&destination.host, Some(destination.port), road(&resolved.transport));
    }
    let log = match &resolved.log_file {
        Some(path) => match Log::to_file(resolved.options.log_level, path) {
            Ok(log) => log,
            Err(e) => {
                let _ = writeln!(err, "podssh ssh: -E {}: {e}", path.display());
                return EXIT_USAGE;
            }
        },
        None => Log::new(resolved.options.log_level),
    };
    let log = Arc::new(log);
    for note in &resolved.notes {
        log.verbose(note);
    }
    for warning in &resolved.warnings {
        log.info(warning);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log.error(&format!("could not start the async runtime: {e}"));
            return EXIT_FAILURE;
        }
    };
    // A run of --restart beats from this runtime, while it polls (T-394).
    crate::detach::beat::keep(runtime.handle());
    // On the heap: the future of each road is large, and Windows gives the
    // main thread 1 MiB of stack.
    let code = runtime.block_on(transport::settled(Box::pin(connect_and_run(resolved, log))));
    // A read on stdin may still be blocked in a helper thread; do not wait for
    // it, or podssh would hang after the session has ended.
    runtime.shutdown_background();
    code
}

/// The road of a run, as the session log names it when no relay host does.
fn road(transport: &Transport) -> &'static str {
    match transport {
        Transport::Relay { .. } => "relay",
        Transport::Direct => "direct",
        Transport::Node { .. } => "node",
        Transport::Iroh { .. } => "iroh",
        Transport::Cloudflare { .. } => "cloudflare",
        Transport::Cloud { road, .. } => road.word(),
        Transport::Derp { .. } => "derp",
        Transport::Forwarder { .. } => "forwarder",
        Transport::Shadowsocks { .. } => "shadowsocks",
    }
}

/// The run of a resolved command line on its road: its exit code. The
/// session daemon of `podssh session` runs its session here too (T-186).
pub(crate) async fn connect_and_run(mut resolved: Resolved, log: Arc<Log>) -> i32 {
    // -X and -Y: the probe, before anything connects (T-037).
    if let Some(plan) = resolved.x11.clone() {
        match x11::probe(&plan, &x11::Env::from_process()).await {
            Ok(forward) => resolved.options.forward_x11 = Some(forward),
            Err(why) => {
                log.error(&why);
                return podssh_ssh::EXIT_FAILURE;
            }
        }
    }
    // The file of --record, before anything connects (T-033).
    if let Some(path) = resolved.record.clone() {
        match recording::create(&path) {
            Ok(target) => resolved.options.record = Some(target),
            Err(why) => {
                log.error(&why);
                return podssh_ssh::EXIT_FAILURE;
            }
        }
    }
    // Connection sharing first (T-039): a master that answers takes the
    // run and its forwards, or this run becomes the master.
    #[cfg(unix)]
    if let control::Start::Exit(code) = control::start(&mut resolved, &log).await {
        return code;
    }
    #[cfg(not(unix))]
    if resolved.control.path.is_some() {
        log.verbose("ControlPath has no effect on Windows: each run is one connection");
    }
    // -L and -D: each listener bound before anything connects (T-038).
    if !resolved.local.is_empty() {
        match local_bind::listeners(&resolved.local, resolved.gateway_ports, &log).await {
            Ok(forwards) => resolved.options.local_forwards = forwards,
            Err((code, line)) => {
                log.error(&line);
                return code;
            }
        }
    }
    // ~C adds forwards as the command line does (T-291).
    resolved.options.command_line = Some(local_bind::command_line(resolved.gateway_ports, log.clone()));
    if let Some(kept) = resolved.persist.clone() {
        return Box::pin(persist::run(&resolved, &kept, log)).await;
    }
    // --upgrade (T-167): the first login, then a move to a temporary node.
    if let Some(upgrade) = resolved.upgrade.clone() {
        return Box::pin(upgrade::run(&resolved, &upgrade, log)).await;
    }
    let opts = &resolved.options;
    if let Transport::Node { label, pair_file, trust, race, derp, channel } = &resolved.transport {
        // The DERP road: the ticket given, else the one kept under the label
        // (Q50); never with --no-e2e, as its node's door is the channel.
        let derp = derp.road(label).filter(|_| !channel.off);
        if race.is_some() || derp.is_some() {
            let raced = roads::Raced { iroh: race.as_ref(), derp };
            return Box::pin(roads::connect(label, pair_file.as_deref(), trust, raced, channel, opts, log)).await;
        }
        return Box::pin(node::connect(label, pair_file.as_deref(), trust, channel, opts, log)).await;
    }
    if let Transport::Iroh { ticket, key, relays, trust, channel } = &resolved.transport {
        return Box::pin(iroh::connect(ticket, key.as_deref(), relays, trust, channel, opts, log)).await;
    }
    if let Transport::Derp { ticket, servers, trust, channel } = &resolved.transport {
        return Box::pin(derp::connect(ticket, servers, trust, channel, opts, log)).await;
    }
    let (code, relay) = Box::pin(tries(&resolved, &log)).await;
    if let Some(end) = relay.as_ref().and_then(podssh_ssh::RelayStatus::get) {
        podssh_ssh::outcome::relay_end(&end);
    }
    // A relay that ends the session on an IPv6 target may have no route
    // there: the note names --direct.
    if let (true, Some(status), Transport::Relay { family, .. }) = (code != 0, relay, &resolved.transport) {
        let first = opts.jump.first().unwrap_or(&opts.destination);
        let v6 = *family == Some(6) || podssh_relay::relay::is_ipv6_literal(&first.host);
        if let Some(RelayEnd::Closed { reason, .. }) = status.get() {
            if let Some(note) = podssh_relay::relay::ipv6_note(v6, &reason) {
                log.error(&format!("{note}; where this host has IPv6, --direct connects without the relay"));
            }
        }
    }
    code
}

/// The run, and a new try of it after a drop of the relay that came before
/// any request reached the destination (T-025): to the next relay host when
/// the link to the relay broke, once more when the relay lost the target.
/// Each try says why, with the backoff of a failed upgrade; the tries in all
/// are at most the rounds of `ConnectionAttempts` times the relay hosts, and
/// a try after the first asks nothing: a key that a passphrase opened and a
/// password that the server took are used again, and a login that needs a
/// prompt stops. Its exit code, and the relay leg's status of the last try.
async fn tries(resolved: &Resolved, log: &Arc<Log>) -> (i32, Option<podssh_ssh::RelayStatus>) {
    let mut opts = resolved.options.clone();
    opts.remembered.get_or_insert_with(Default::default);
    let hosts = match &resolved.transport {
        Transport::Relay { relays, .. } => relays.hosts.len().max(1),
        _ => 1,
    };
    let most = (resolved.connection_attempts.max(1) as usize).saturating_mul(hosts);
    let first = opts.jump.first().unwrap_or(&opts.destination);
    let target = podssh_ws::dial::authority(&first.host, first.port);
    let (mut tried, mut skip, mut again) = (0usize, 0usize, false);
    loop {
        tried += 1;
        let reached = match transport::reach_skipping(resolved, skip, log).await {
            Ok(reached) => reached,
            Err(failure) => {
                for line in &failure.lines {
                    log.error(line);
                }
                let leg = if matches!(resolved.transport, Transport::Relay { .. }) { "relay" } else { "connect" };
                podssh_ssh::outcome::failure_is(leg);
                return (EXIT_FAILURE, None);
            }
        };
        let relay = reached.relay.clone();
        let direct_proxy = reached.direct_proxy.clone();
        // A podssh node behind a cf:// name (T-300): the layer's heartbeat
        // finds a dead link, as on node:// (T-154).
        if reached.layer.is_some() && resolved.alive_default && opts.keepalive_interval.take().is_some() {
            log.verbose("the far end runs the resumable layer, whose heartbeat finds a dead link: no SSH keepalives");
        }
        let outcome = podssh_ssh::run::run_outcome(reached.stream, &opts, reached.relay, log.clone()).await;
        // The layer's CLOSE, and the line of its failure, before the exit.
        transport::settle(reached.layer).await;
        let how = match outcome.retry {
            Some(Retry::NextHost) if tried < most && skip + 1 < hosts => {
                skip += 1;
                "on the next relay host"
            }
            Some(Retry::Again) if tried < most.max(2) && !again => {
                again = true;
                "once more"
            }
            _ => {
                for line in &outcome.lines {
                    log.error(line);
                }
                // A proxy that took the CONNECT and sent nothing back (T-317).
                if outcome.code != 0 {
                    if let Some(cause) = direct_proxy.as_ref().and_then(|d| d.cause(&target)) {
                        log.error(&cause);
                    }
                }
                return (outcome.code, relay);
            }
        };
        let wait = podssh_relay::open::backoff(tried as u32);
        let why = outcome.lines.first().map_or("the relay dropped the session", String::as_str);
        log.info(&format!("{why}; nothing had reached {target}, so podssh tries {how} in {:.1} s", wait.as_secs_f32()));
        tokio::time::sleep(wait).await;
        // A person may not be there to answer a prompt again.
        opts.set_batch_mode();
    }
}
