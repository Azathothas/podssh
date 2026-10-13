//! `podssh job` (T-193): jobs on a far host that outlive the connection.
//! `start HOST -- COMMAND` starts the command in the host's tmux and prints
//! its ID; `list HOST` gives each job with its state and its exit status;
//! `log HOST ID` gives its output; `stop HOST ID` ends it and removes it.
//! A queue of detached jobs comes on top (T-197, [`queue`]): `submit`
//! queues a command, which a runner on the host starts when a slot is free;
//! `wait` reads the state until the job ends, and exits with its status;
//! `fetch` copies the output and named files back ([`fetch`]). The host is a
//! plain POSIX host reached with SSH: nothing of podssh runs there but the
//! far script ([`far`]), under sh, with tmux, which it probes before
//! anything starts.
//!
//! **tmux holds each job.** The job outlives the connection, and `stop`
//! ends the tmux session of that exact name, so that no other process can
//! take its place, as a process ID given again could. With no tmux nothing
//! starts, and the exit is 255 with the reason. The output and the status
//! go to files of a private directory, so that they outlive the job too.
//!
//! **Exit codes are those of `podssh ssh`**: 64 a usage error and 78 a
//! setting, before anything connects; 255 a failure of podssh (no
//! connection, no login, no tmux, no such job); `wait` the job's status;
//! 75 when the `--timeout` of `wait` passed, or when `fetch` finds the job
//! still queued or running; else 0.

mod args;
pub mod far;
pub mod fetch;
pub mod list;
pub mod queue;

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use podssh_ssh::{Connection, Log, EXIT_FAILURE};

use crate::exitmap::sysexits;
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved, Transport};
pub use args::{action, files, id, new_id, now_ms, slots, Action, JobArgs, ID_LEN, MOST_SLOTS, SUBCOMMANDS};

/// The connection to `host`, resolved as `podssh ssh` resolves its
/// destination, with the `Host` blocks of ssh_config for it: no terminal and
/// no input, no agent and no forward. A `node://` or `iroh:` destination is
/// refused: a job needs the host's own sh.
pub(crate) fn plan(host: &str, args: &SshArgs, env: &Env) -> Result<Resolved, Refusal> {
    let mut ssh = args.clone();
    ssh.destination = Some(host.to_string());
    ssh.no_tty = true;
    ssh.stdin_null = true;
    let named = |r: Refusal| Refusal { message: format!("{host}: {}", r.message), code: r.code };
    let mut resolved = resolve::resolve_or_refuse(&ssh, env).map_err(named)?;
    if matches!(resolved.transport, Transport::Node { .. } | Transport::Iroh { .. }) {
        return Err(Refusal::usage(
            "podssh job reaches a host through the relay or with --direct; a node:// or iroh: destination is for \
             podssh ssh",
        ));
    }
    resolved.options.forward_agent = podssh_ssh::Agent::Off;
    resolved.options.remote_forwards.clear();
    Ok(resolved)
}

/// Run `podssh job`; the process exit code. The answers go to `out`: an ID,
/// the list, a job's output; podssh's own words go to stderr.
pub fn run_job(args: &JobArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let action = match action(args) {
        Ok(action) => action,
        Err(why) => return Refusal::usage(why).report("job", err),
    };
    let word = args.host.clone().unwrap_or_default();
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("job", err);
    }
    let env = Env::from_process();
    // `submit` takes a list of hosts, with braces and groups (T-184); each
    // other call takes one host, and `resolve` refuses a pattern of more.
    let labels = match &action {
        Action::Submit { .. } => match crate::hosts::expand(&word, &env.settings.groups) {
            Ok(labels) => labels,
            Err(refusal) => return refusal.report("job", err),
        },
        _ => vec![word],
    };
    let mut plans = Vec::with_capacity(labels.len());
    for label in &labels {
        match plan(label, &args.ssh, &env) {
            Ok(resolved) => plans.push(resolved),
            Err(refusal) => return refusal.report("job", err),
        }
    }
    let log = Arc::new(Log::new(plans[0].options.log_level));
    // Each note and warning once: the same of many hosts is one line.
    let mut said: Vec<&str> = Vec::new();
    for resolved in &plans {
        let notes = resolved.notes.iter().map(|n| (n, true));
        for (text, verbose) in notes.chain(resolved.warnings.iter().map(|w| (w, false))) {
            if !said.contains(&text.as_str()) {
                said.push(text);
                if verbose {
                    log.verbose(text);
                } else {
                    log.info(text);
                }
            }
        }
    }
    crate::cp::gauge::init(false, plans[0].options.log_level == podssh_ssh::LogLevel::Quiet);
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log.error(&format!("could not start the async runtime: {e}"));
            return EXIT_FAILURE;
        }
    };
    // On the heap: the future of a connection is large, and Windows gives
    // the main thread 1 MiB of stack.
    let code = runtime.block_on(Box::pin(perform(&action, &labels, &plans, &log, out)));
    runtime.shutdown_background();
    code
}

/// The calls of `action` on the hosts of `plans`: the exit code.
async fn perform(action: &Action, labels: &[String], plans: &[Resolved], log: &Arc<Log>, out: &mut dyn Write) -> i32 {
    let (host, resolved) = (labels[0].as_str(), &plans[0]);
    match action {
        Action::Submit { command, slots } => submit(labels, plans, command, *slots, log, out).await,
        Action::Wait { id, timeout } => {
            let waited = queue::wait(resolved, host, id, log);
            match timeout {
                Some(limit) => match tokio::time::timeout(*limit, Box::pin(waited)).await {
                    Ok(code) => code,
                    Err(_) => {
                        log.error(&format!(
                            "the --timeout of {} s passed, and job {id} on {host} has not ended",
                            limit.as_secs()
                        ));
                        sysexits::EX_TEMPFAIL
                    }
                },
                None => waited.await,
            }
        }
        Action::Fetch { id, dir, files } => {
            let dir = PathBuf::from(dir.clone().unwrap_or_else(|| format!("podssh-job-{id}")));
            fetch::fetch(resolved, host, id, &dir, files.as_deref(), log).await
        }
        _ => {
            let Some(handles) = far::connect(resolved, log).await else { return EXIT_FAILURE };
            let handle = handles.last().expect("the destination's connection");
            let code = match act(action, host, handle, log, out).await {
                Ok(()) => 0,
                Err(why) => {
                    log.error(&why);
                    EXIT_FAILURE
                }
            };
            podssh_ssh::run::disconnect_all(&handles).await;
            code
        }
    }
}

/// `submit` (T-197): to the one host, or to the host of the list with the
/// fewest jobs queued or running, read with one list of each. The ID on
/// stdout, after the host when the list had more than one.
async fn submit(
    labels: &[String],
    plans: &[Resolved],
    command: &str,
    slots: Option<u32>,
    log: &Arc<Log>,
    out: &mut dyn Write,
) -> i32 {
    let at = if labels.len() == 1 {
        0
    } else {
        let mut counts = Vec::with_capacity(labels.len());
        for (label, resolved) in labels.iter().zip(plans) {
            let Some(handles) = far::connect(resolved, log).await else {
                log.info(&format!("{label}: no connection, so it is left out"));
                counts.push(None);
                continue;
            };
            let counted = queue::count(handles.last().expect("the destination's connection"), label).await;
            podssh_ssh::run::disconnect_all(&handles).await;
            counts.push(match counted {
                Ok(n) => {
                    log.verbose(&format!("{label}: {n} jobs queued or running"));
                    Some(n)
                }
                Err(why) => {
                    log.info(&format!("{why}; {label} is left out"));
                    None
                }
            });
        }
        match queue::choose(&counts) {
            Some(at) => at,
            None => {
                log.error("no host of the list gave the list of its jobs; nothing was queued");
                return EXIT_FAILURE;
            }
        }
    };
    let host = labels[at].as_str();
    let Some(handles) = far::connect(&plans[at], log).await else { return EXIT_FAILURE };
    let queued = queue::submit(handles.last().expect("the destination's connection"), host, command, slots).await;
    podssh_ssh::run::disconnect_all(&handles).await;
    match queued {
        Ok(id) => {
            let _ = if labels.len() == 1 { writeln!(out, "{id}") } else { writeln!(out, "{host} {id}") };
            log.verbose(&format!("job {id} is queued on {host}: {command}"));
            0
        }
        Err(why) => {
            log.error(&why);
            EXIT_FAILURE
        }
    }
}

/// The first line of an answer, when it says what was done; else why not.
pub(crate) fn first_line<'a>(host: &str, lines: &'a [String]) -> Result<&'a str, String> {
    let first = lines.first().ok_or_else(|| format!("{host} gave podssh job an empty answer"))?;
    match far::refusal(host, first) {
        Some(why) => Err(why),
        None => Ok(first),
    }
}

/// An answer that this binary does not know: another version of the far
/// script, or a fault of it.
pub(crate) fn unexpected(host: &str, line: &str) -> String {
    format!("{host} gave an answer that podssh job does not know: {line}")
}

/// One call on one connection: `start`, `list`, `log` or `stop`.
async fn act(action: &Action, host: &str, handle: &Connection, log: &Log, out: &mut dyn Write) -> Result<(), String> {
    match action {
        Action::Start(command) => {
            let id = new_id();
            let name = list::dir_name(now_ms(), &id);
            let lines = far::lines(handle, host, &["start", name.as_str(), "-", command.as_str()]).await?;
            let first = first_line(host, &lines)?;
            if first != format!("started {id}") {
                return Err(unexpected(host, first));
            }
            let _ = writeln!(out, "{id}");
            log.verbose(&format!("job {id} runs on {host}: {command}"));
            Ok(())
        }
        Action::List { json } => {
            let lines = far::lines(handle, host, &["list"]).await?;
            first_line(host, &lines)?;
            let jobs = list::parse(&lines).ok_or_else(|| format!("{host}: the list of its jobs came cut"))?;
            let text = if *json { format!("{}\n", list::json(host, &jobs)) } else { list::text(&jobs) };
            let _ = out.write_all(text.as_bytes());
            Ok(())
        }
        Action::Log(id) => match far::stream(handle, host, &["log", id.as_str()], "out", out).await? {
            far::Streamed::Out => Ok(()),
            far::Streamed::Other(line) => {
                if let Some(why) = far::refusal(host, &line) {
                    return Err(why);
                }
                let state = line.strip_prefix("no-out ").ok_or_else(|| unexpected(host, &line))?;
                log.info(&format!("job {id} on {host} has no output yet: it is {state}"));
                Ok(())
            }
        },
        Action::Stop(id) => {
            let lines = far::lines(handle, host, &["stop", id.as_str()]).await?;
            let first = first_line(host, &lines)?;
            if first == format!("stopped {id}") {
                log.info(&format!("job {id} on {host} stopped, and removed with its output"));
            } else if first == format!("removed {id}") {
                log.info(&format!("job {id} on {host} removed with its output; it did not run"));
            } else {
                return Err(unexpected(host, first));
            }
            Ok(())
        }
        Action::Submit { .. } | Action::Wait { .. } | Action::Fetch { .. } => {
            unreachable!("perform runs them with connections of their own")
        }
    }
}

#[cfg(test)]
mod tests;
