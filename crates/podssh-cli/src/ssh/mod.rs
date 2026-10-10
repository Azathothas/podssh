//! `podssh ssh`: the native client. The command line is resolved first
//! ([`resolve`]), so a bad one fails before anything connects; then the first
//! hop is reached through the relay (or directly with `--direct`) and
//! `podssh-ssh` does the rest.
//!
//! Exit codes follow OpenSSH: the remote command's status, 128 + a signal
//! number when it was killed, 255 for podssh's own failures. A usage error is
//! 64, and a bad relay variable 78, before anything is attempted.

pub mod args;
pub mod dump;
pub mod forward;
pub mod iroh;
pub mod keywords;
pub mod node;
pub mod options;
pub mod persist;
pub mod resolve;
pub mod tokens;
pub mod transport;

use std::io::Write;
use std::sync::Arc;

use podssh_ssh::relay_stream::RelayEnd;
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

async fn connect_and_run(resolved: Resolved, log: Arc<Log>) -> i32 {
    if let Some(name) = resolved.persist.as_deref() {
        return Box::pin(persist::run(&resolved, name, log)).await;
    }
    let opts = &resolved.options;
    if let Transport::Node { label, pair_file, trust, race } = &resolved.transport {
        if let Some(race) = race {
            return Box::pin(iroh::race_connect(label, pair_file.as_deref(), trust, race, opts, log)).await;
        }
        return Box::pin(node::connect(label, pair_file.as_deref(), trust, opts, log)).await;
    }
    if let Transport::Iroh { ticket, key, relays, trust } = &resolved.transport {
        return Box::pin(iroh::connect(ticket, key.as_deref(), relays, trust, opts, log)).await;
    }
    let reached = match transport::reach(&resolved, &log).await {
        Ok(reached) => reached,
        Err(failure) => {
            for line in &failure.lines {
                log.error(line);
            }
            return EXIT_FAILURE;
        }
    };
    let relay = reached.relay.clone();
    let code = podssh_ssh::run(reached.stream, opts, reached.relay, log.clone()).await;
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
