//! `podssh ssh`: the native client. The command line is resolved first
//! ([`resolve`]), so a bad one fails before anything connects; then the first
//! hop is reached through the relay (or directly with `--direct`) and
//! `podssh-ssh` does the rest.
//!
//! Exit codes follow OpenSSH: the remote command's status, 128 + a signal
//! number when it was killed, 255 for podssh's own failures. A usage error is
//! 64, before anything is attempted.

pub mod args;
pub mod options;
pub mod resolve;

use std::io::Write;
use std::sync::Arc;

use podssh_ssh::{Log, EXIT_FAILURE};
use podssh_ws::ProxyChoice;

use crate::exit_codes::EXIT_USAGE;
use args::SshArgs;
use resolve::{Env, Resolved, Transport};

/// Run `podssh ssh`; returns the process exit code.
pub fn run_ssh(args: &SshArgs, err: &mut dyn Write) -> i32 {
    if args.version {
        let _ = writeln!(err, "podssh {} (SSH: russh, aws-lc-rs)", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    let resolved = match resolve::resolve(args, &Env::from_process()) {
        Ok(r) => r,
        Err(why) => {
            let _ = writeln!(err, "podssh ssh: {why}");
            return EXIT_USAGE;
        }
    };
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
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log.error(&format!("could not start the async runtime: {e}"));
            return EXIT_FAILURE;
        }
    };
    let code = runtime.block_on(connect_and_run(resolved, log));
    // A read on stdin may still be blocked in a helper thread; do not wait for
    // it, or podssh would hang after the session has ended.
    runtime.shutdown_background();
    code
}

async fn connect_and_run(resolved: Resolved, log: Arc<Log>) -> i32 {
    let opts = &resolved.options;
    let first = opts.jump.first().unwrap_or(&opts.destination).clone();
    let target = format!("{}:{}", first.host, first.port);
    match &resolved.transport {
        Transport::Relay { relay, trust, family } => {
            let mut path = match crate::relay::forward_path(&first.host, first.port) {
                Ok(p) => p,
                Err(why) => {
                    log.error(&why);
                    return EXIT_FAILURE;
                }
            };
            if let Some(f) = family {
                path.push_str(&format!("?family={f}"));
            }
            log.verbose(&format!("connecting to {target} through the relay {}", relay.host));
            let mut notes = Vec::new();
            let opened = crate::relay_open::open(relay, &path, trust, &target, &mut |n: &str| notes.push(n.to_string())).await;
            for note in notes {
                log.info(&note);
            }
            match opened {
                Ok(session) => {
                    let (stream, status) = podssh_ssh::relay_stream::spawn(session);
                    podssh_ssh::run(stream, opts, Some(status), log).await
                }
                Err(e) => {
                    for line in e.lines() {
                        log.error(&line);
                    }
                    EXIT_FAILURE
                }
            }
        }
        Transport::Direct => {
            if crate::relay_open::offline() {
                log.error(&format!("{} is set, so podssh does not connect anywhere", crate::relay_open::OFFLINE_ENV));
                return EXIT_FAILURE;
            }
            log.verbose(&format!("connecting to {target} directly"));
            let dialled = podssh_ws::dial::dial(
                &first.host,
                first.port,
                &ProxyChoice::FromEnvironment,
                crate::relay_open::CONNECT_TIMEOUT,
            )
            .await;
            match dialled {
                Ok(tcp) => {
                    let _ = tcp.set_nodelay(true);
                    podssh_ssh::run(tcp, opts, None, log).await
                }
                Err(e) => {
                    log.error(&format!("could not connect to {target}: {e}"));
                    EXIT_FAILURE
                }
            }
        }
    }
}
