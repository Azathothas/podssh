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
pub mod cloudflare;
pub mod config;
pub mod control;
pub mod dump;
mod elevate;
pub mod forward;
mod hop;
pub mod iroh;
mod jump;
pub mod keywords;
mod local_bind;
pub mod local_spec;
mod login;
pub mod node;
pub mod options;
pub mod persist;
mod recording;
pub mod resolve;
pub mod tokens;
pub mod transport;
pub mod x11;

use std::io::Write;
use std::sync::Arc;

use podssh_ssh::relay_stream::RelayEnd;
use podssh_ssh::retry::Retry;
use podssh_ssh::{Log, EXIT_FAILURE};

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use args::SshArgs;
use resolve::{Env, Resolved, Transport};

/// Run `podssh ssh`; returns the process exit code.
pub fn run_ssh(args: &SshArgs, err: &mut dyn Write) -> i32 {
    if args.version {
        let _ = writeln!(err, "podssh {} (SSH: russh, aws-lc-rs)", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    // Before anything is resolved or connects: the road is not in this build.
    if let Some(destination) = args.destination.as_deref().filter(|d| iroh::is_iroh(d) && !cfg!(feature = "iroh")) {
        let _ = writeln!(err, "podssh ssh: {}", iroh::refusal(destination));
        return EXIT_NOT_IMPLEMENTED;
    }
    if args.iroh_ticket.is_some() && !cfg!(feature = "iroh") {
        let _ = writeln!(err, "podssh ssh: {}", iroh::not_built("--iroh-ticket"));
        return EXIT_NOT_IMPLEMENTED;
    }
    if let Err(refusal) = crate::pins::apply(args.relay_addr.as_deref()) {
        return refusal.report("ssh", err);
    }
    let resolved = match resolve::resolve_or_refuse(args, &Env::from_process()) {
        Ok(r) => r,
        Err(refusal) => return refusal.report("ssh", err),
    };
    // -G: the settings, and nothing opened: no relay, no token, no pool.
    if args.print_config {
        let mut out = std::io::stdout().lock();
        for line in dump::lines(&resolved) {
            let _ = writeln!(out, "{line}");
        }
        return 0;
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
    // On the heap: the future of each road is large, and Windows gives the
    // main thread 1 MiB of stack.
    let code = runtime.block_on(Box::pin(connect_and_run(resolved, log)));
    // A read on stdin may still be blocked in a helper thread; do not wait for
    // it, or podssh would hang after the session has ended.
    runtime.shutdown_background();
    code
}

async fn connect_and_run(mut resolved: Resolved, log: Arc<Log>) -> i32 {
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
    if let Some(name) = resolved.persist.as_deref() {
        return Box::pin(persist::run(&resolved, name, log)).await;
    }
    let opts = &resolved.options;
    if let Transport::Node { label, pair_file, trust, race, channel } = &resolved.transport {
        if let Some(race) = race {
            return Box::pin(iroh::race_connect(label, pair_file.as_deref(), trust, race, channel, opts, log)).await;
        }
        return Box::pin(node::connect(label, pair_file.as_deref(), trust, channel, opts, log)).await;
    }
    if let Transport::Iroh { ticket, key, relays, trust, channel } = &resolved.transport {
        return Box::pin(iroh::connect(ticket, key.as_deref(), relays, trust, channel, opts, log)).await;
    }
    let (code, relay) = Box::pin(tries(&resolved, &log)).await;
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
                return (EXIT_FAILURE, None);
            }
        };
        let relay = reached.relay.clone();
        let outcome = podssh_ssh::run::run_outcome(reached.stream, &opts, reached.relay, log.clone()).await;
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
