//! One host of `podssh each` (T-183), on the road that `podssh ssh` takes:
//! the first hop reached through the relay or with `--direct`
//! ([`crate::ssh::transport`]), then the login and the command on the one
//! SSH client, `podssh_ssh::run`, with its output into the host's place as
//! it comes. No second SSH client.

use std::sync::Arc;

use podssh_relay::token::Origin;
use podssh_ssh::{Log, Request};
use tokio::sync::mpsc;

use super::fan::Ended;
use super::out::{self, Place};
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved, Transport};
use crate::ssh::transport;

/// One host, resolved before anything connects.
pub(crate) struct Plan {
    /// The host as the list names it, which each of its lines starts with.
    pub label: String,
    pub resolved: Resolved,
    pub log: Arc<Log>,
    /// `BatchMode` as `-o` and ssh_config give it, before each turns it on:
    /// with it, a snippet asks nothing (T-187).
    pub batch_mode: bool,
}

/// The plan of the host `label`: the command line of `args` with that
/// destination, no terminal, no input and no prompt, as `podssh ssh` would
/// resolve it, with the `Host` blocks of ssh_config for that host. Each
/// refusal names the host.
pub(crate) fn plan(label: &str, args: &SshArgs, env: &Env) -> Result<Plan, Refusal> {
    planned(label, args, env, false)
}

/// The plan of the host `label` for the broadcast (T-185): as [`plan`], with
/// a shell with no pty in place of a command, whose input the broadcast
/// gives it.
pub(crate) fn shell_plan(label: &str, args: &SshArgs, env: &Env) -> Result<Plan, Refusal> {
    planned(label, args, env, true)
}

fn planned(label: &str, args: &SshArgs, env: &Env, shell: bool) -> Result<Plan, Refusal> {
    let mut ssh = args.clone();
    ssh.destination = Some(label.to_string());
    // Many sessions cannot share one terminal or one stdin.
    ssh.no_tty = true;
    ssh.stdin_null = true;
    let named = |r: Refusal| Refusal { message: format!("{label}: {}", r.message), code: r.code };
    let mut resolved = resolve::resolve_or_refuse(&ssh, env).map_err(named)?;
    if shell {
        shell_only(&mut resolved).map_err(named)?;
    } else if !matches!(resolved.options.request, Request::Exec(_)) {
        return Err(named(Refusal::usage(
            "SessionType in ssh_config asks for no command here, and podssh each runs one on each host",
        )));
    }
    if matches!(resolved.transport, Transport::Node { .. } | Transport::Iroh { .. }) {
        return Err(named(Refusal::usage(
            "podssh each reaches a host through the relay or with --direct; a node:// or iroh: destination is \
             for podssh ssh",
        )));
    }
    // N questions at once cannot be answered: an unknown host key refuses
    // its host and names its fingerprint and accept-new.
    let batch_mode = resolved.options.batch_mode;
    resolved.options.set_batch_mode();
    let forwards = !resolved.local.is_empty() || !resolved.options.remote_forwards.is_empty();
    if forwards || resolved.x11.is_some() || resolved.control.path.is_some() {
        let note = "podssh each opens no forward, no X11 and no control socket: those of ssh_config are not used";
        resolved.notes.push(note.to_string());
    }
    resolved.options.remote_forwards.clear();
    // A LocalCommand's output would come with no host's label (T-191).
    if resolved.options.local_command.take().is_some() {
        resolved.notes.push("podssh each runs no LocalCommand: the one of ssh_config is not used".to_string());
    }
    let log = Arc::new(Log::new(resolved.options.log_level).with_prefix(format!("{label}: ")));
    Ok(Plan { label: label.to_string(), resolved, log, batch_mode })
}

/// The broadcast's shell (T-185): a `RemoteCommand` of ssh_config is not
/// used, with a note, and a `SessionType` that asks for no shell is
/// refused. Ctrl-C goes to no host there, so no session sends `signal INT`
/// for it; `:intr` asks for one.
fn shell_only(resolved: &mut Resolved) -> Result<(), Refusal> {
    let command = match &resolved.options.request {
        Request::Shell => false,
        Request::Exec(_) => true,
        _ => return Err(Refusal::usage("SessionType in ssh_config asks for no shell, and --interactive opens one")),
    };
    if command {
        let note = "podssh each --interactive opens a shell on each host: the RemoteCommand of ssh_config is not used";
        resolved.notes.push(note.to_string());
        resolved.options.request = Request::Shell;
    }
    resolved.options.interrupt_signal = false;
    Ok(())
}

/// Run the command on the host of `plan`, its output into `place` as it
/// comes; with `--output-dir`, its status into its status file at the end.
/// How it ended.
pub(crate) async fn run(plan: &Plan, place: Place) -> Ended {
    let status_file = match &place {
        Place::Files(files) => Some(files.status.clone()),
        Place::Lines { .. } => None,
    };
    let (sink, pieces) = mpsc::channel(16);
    let mut opts = plan.resolved.options.clone();
    opts.output = Some(sink);
    let log = plan.log.clone();
    // The options, and with them the sink, go when the session ends: then
    // the drain has each piece, and ends too.
    let session = async move {
        let reached = match transport::reach(&plan.resolved, &log).await {
            Ok(reached) => reached,
            Err(failure) => {
                for line in &failure.lines {
                    log.error(line);
                }
                let why = failure.lines.first().cloned().unwrap_or_else(|| "no connection".to_string());
                return Ended::Failed(why);
            }
        };
        let outcome = podssh_ssh::run::run_outcome(reached.stream, &opts, reached.relay, log.clone()).await;
        for line in &outcome.lines {
            log.error(line);
        }
        match outcome.lines.first() {
            Some(why) => Ended::Failed(why.clone()),
            None => Ended::Status(outcome.code),
        }
    };
    let (ended, drained) = tokio::join!(Box::pin(session), out::drain(pieces, place));
    if let Err(why) = drained {
        plan.log.error(&why);
    }
    if let (Some(path), Some(code)) = (status_file, ended.code()) {
        if let Err(why) = out::status(&path, code).await {
            plan.log.error(&why);
        }
    }
    ended
}

/// A relay token before the fan-out, so that the hosts read the one that the
/// cache keeps, and the relay sees one mint, not one for each host. With no
/// cache (`PODSSH_CACHE_DIR=none`), each host mints its own, as each run
/// does; offline or with `--direct`, there is none to get.
pub(crate) async fn first_token(resolved: &Resolved, log: &Log) {
    let Transport::Relay { relays, trust, .. } = &resolved.transport else { return };
    if podssh_relay::open::offline() || matches!(podssh_relay::cache::chosen(), podssh_relay::cache::Chosen::Nothing) {
        return;
    }
    let proxy = podssh_ws::ProxyChoice::FromEnvironment;
    let ctx = podssh_relay::token::MintContext {
        relay: relays.primary(),
        trust,
        proxy: &proxy,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
    };
    match podssh_relay::token::obtain(&ctx, false).await {
        Ok(token) => {
            let from = match token.origin {
                Origin::Environment => "PODSSH_RELAY_TOKEN",
                Origin::Cache => "the cache",
                Origin::Minted => "a mint, kept in the cache",
            };
            log.verbose(&format!("one relay token for each host, from {from}"));
        }
        Err(e) => log.verbose(&format!("no relay token before the hosts ({e}); each host gets its own")),
    }
}
