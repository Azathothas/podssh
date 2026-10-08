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
use podssh_relay::open::Request;
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
    if let Err(why) = crate::pins::apply(args.relay_addr.as_deref()) {
        let _ = writeln!(err, "podssh ssh: {why}");
        return EXIT_USAGE;
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
        Transport::Relay { relays, trust, family } => {
            let mut path = match podssh_relay::relay::forward_path(&first.host, first.port) {
                Ok(p) => p,
                Err(why) => {
                    log.error(&why);
                    return EXIT_FAILURE;
                }
            };
            if let Some(f) = family {
                path.push_str(&format!("?family={f}"));
            }
            let hosts: Vec<&str> = relays.hosts.iter().map(|r| r.host.as_str()).collect();
            log.verbose(&format!("connecting to {target} through the relay ({})", hosts.join(", ")));
            let request = Request {
                relays,
                path: &path,
                trust,
                target: &target,
                rounds: resolved.connection_attempts,
            };
            let note_log = log.clone();
            let opened = podssh_relay::open(&request, &mut |note: &str| note_log.info(note)).await;
            match opened {
                Ok(opened) => {
                    log.verbose(&format!("the relay host {} opened the session", opened.relay.host));
                    let (stream, status) = podssh_ssh::relay_stream::spawn(opened.session);
                    podssh_ssh::run(stream, opts, Some(status), log).await
                }
                Err(failure) => {
                    for line in failure.lines(&target) {
                        log.error(&line);
                    }
                    EXIT_FAILURE
                }
            }
        }
        Transport::Direct => {
            if podssh_relay::open::offline() {
                log.error(&format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV));
                return EXIT_FAILURE;
            }
            let rounds = resolved.connection_attempts.max(1);
            for round in 1..=rounds {
                if round > 1 {
                    let wait = podssh_relay::open::backoff(round - 1);
                    log.info(&format!("retrying in {:.1} s (attempt {round} of {rounds})", wait.as_secs_f32()));
                    tokio::time::sleep(wait).await;
                }
                log.verbose(&format!("connecting to {target} directly"));
                let dialled = podssh_ws::dial::dial(
                    &first.host,
                    first.port,
                    &ProxyChoice::FromEnvironment,
                    podssh_relay::open::CONNECT_TIMEOUT,
                )
                .await;
                match dialled {
                    Ok(tcp) => {
                        let _ = tcp.set_nodelay(true);
                        return podssh_ssh::run(tcp, opts, None, log).await;
                    }
                    Err(e) => log.error(&format!("could not connect to {target}: {e}")),
                }
            }
            EXIT_FAILURE
        }
    }
}
