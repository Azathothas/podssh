//! `podssh cp`: files between this host and a server, over SFTP (T-133).
//!
//! **The destination's name never holds a file that was not verified**
//! ([`transfer`]): the bytes go to a temporary name beside it, the SHA-256 of
//! what was sent is compared with the far side's, and only then is the file
//! renamed onto the destination. The whole copy, the login included, has the
//! `--timeout` deadline.
//!
//! **Exit codes are sysexits**, as `proxy`'s: 64 a usage error; 66 a source
//! that is missing or cannot be read; 69 no server to copy with (the relay or
//! the host cannot be reached, or the server has no SFTP); 70 a copy that
//! went wrong (the digests differ, the session broke); 73 a destination that
//! cannot be written; 75 the `--timeout` passed; 77 a login or a host key
//! refused; 78 a setting of the environment. With several files, the first
//! failure's code.

mod digest;
pub mod operand;
pub mod plan;
mod transfer;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use clap::ArgMatches;
use podssh_ssh::run::HopError;
use podssh_ssh::sftp::{Limits, Sftp};
use podssh_ssh::Log;

use crate::exitmap::Fault;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved};
use operand::Operand;
use plan::{Direction, Plan};
use transfer::{Done, Failed};

/// `cp`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpArgs {
    /// SRC... DST, as typed.
    pub paths: Vec<String>,
    /// The connection flags, read as `ssh` reads them: `cp`'s rows share
    /// their ids. The destination comes from the operands.
    pub ssh: SshArgs,
}

impl CpArgs {
    /// Read the values out of `cp`'s matches.
    pub fn from_matches(m: &ArgMatches) -> Self {
        let paths = if m.try_contains_id("paths").unwrap_or(false) {
            m.get_many::<String>("paths").map(|v| v.cloned().collect()).unwrap_or_default()
        } else {
            Vec::new()
        };
        CpArgs { paths, ssh: SshArgs::from_matches(m) }
    }
}

/// What a run ended with: each file done, and the first failure.
struct Outcome {
    done: Vec<Done>,
    failed: Option<(String, Failed)>,
}

/// Run `podssh cp`; returns the process exit code.
pub fn run_cp(args: &CpArgs, deadline: Option<Duration>, jsonl: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let plan = match plan::plan(&args.paths, cfg!(windows)) {
        Ok(plan) => plan,
        Err(why) => {
            let _ = writeln!(err, "podssh cp: {why}.\n  Nothing has been attempted.");
            return Fault::Usage.code();
        }
    };
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("cp", err);
    }
    let resolve_for = |server: &operand::Remote| {
        let mut ssh = args.ssh.clone();
        ssh.destination = Some(server.destination());
        resolve::resolve_or_refuse(&ssh, &Env::from_process())
    };
    let servers: Vec<operand::Remote> = match (&plan.sources[0], &plan.destination) {
        (Operand::Remote(a), Operand::Remote(b)) => vec![a.clone(), b.clone()],
        _ => plan.server().cloned().into_iter().collect(),
    };
    let mut resolved = Vec::new();
    for server in &servers {
        match resolve_for(server) {
            Ok(r) => resolved.push(r),
            Err(refusal) => return refusal.report("cp", err),
        }
    }
    let log = Arc::new(Log::new(resolved[0].options.log_level));
    for r in &resolved {
        for note in &r.notes {
            log.verbose(note);
        }
        for warning in &r.warnings {
            log.info(warning);
        }
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log.error(&format!("could not start the async runtime: {e}"));
            return Fault::SessionFault.code();
        }
    };
    let run = run_plan(&plan, &resolved, &log);
    let outcome = runtime.block_on(async {
        match deadline {
            Some(limit) => tokio::time::timeout(limit, run).await.unwrap_or_else(|_| Outcome {
                done: Vec::new(),
                failed: Some((
                    String::new(),
                    Failed {
                        fault: Fault::TimedOut,
                        message: format!("the --timeout of {} s passed", limit.as_secs()),
                    },
                )),
            }),
            None => run.await,
        }
    });
    runtime.shutdown_background();
    report(&outcome, jsonl, out, &log)
}

/// Print each file done and the failure; the exit code.
fn report(outcome: &Outcome, jsonl: bool, out: &mut dyn Write, log: &Log) -> i32 {
    for done in &outcome.done {
        if jsonl {
            let line = serde_json::json!({
                "event": "done",
                "source": done.source,
                "destination": done.destination,
                "bytes": done.bytes,
                "sha256": digest::hex(&done.sum),
                "verified_by": done.verified_by,
                "atomic": !done.not_atomic,
            });
            let _ = writeln!(out, "{line}");
        } else {
            log.verbose(&format!(
                "{} -> {}: {} bytes, SHA-256 {} (far side: {})",
                done.source,
                done.destination,
                done.bytes,
                digest::hex(&done.sum),
                done.verified_by
            ));
        }
    }
    let Some((source, failed)) = &outcome.failed else { return 0 };
    if jsonl {
        let line = serde_json::json!({
            "event": "error",
            "source": source,
            "message": failed.message,
            "code": failed.fault.code(),
        });
        let _ = writeln!(out, "{line}");
    }
    log.error(&failed.message);
    failed.fault.code()
}

/// The fault of a sysexits code that `transport::reach` gave.
fn fault_of(code: i32) -> Fault {
    [Fault::Usage, Fault::Auth, Fault::Config].into_iter().find(|f| f.code() == code).unwrap_or(Fault::RelayUnreachable)
}

/// A connection that failed, as the fault of `cp`.
fn hop_failure(e: HopError) -> Failed {
    let fault = match e {
        HopError::Unreachable(_) => Fault::RelayUnreachable,
        HopError::HostKey(_) | HopError::Auth(_) => Fault::Auth,
    };
    Failed { fault, message: e.to_string() }
}

/// Run each copy of the plan.
async fn run_plan(plan: &Plan, resolved: &[Resolved], log: &Arc<Log>) -> Outcome {
    match plan.direction {
        Direction::Up | Direction::Down => {
            session(plan, &resolved[0], log, None).await.expect("up and down need no copy-data")
        }
        Direction::Across => across(plan, resolved, log).await,
    }
}

/// Server to server. On one server that has `copy-data`, the server copies;
/// else down to a local temporary file, then up from it, one connection at
/// a time (`AGENTS.md`, rule 2), each copy verified.
async fn across(plan: &Plan, resolved: &[Resolved], log: &Arc<Log>) -> Outcome {
    let (Operand::Remote(from), Operand::Remote(to)) = (&plan.sources[0], &plan.destination) else {
        unreachable!("a copy across has a remote source and a remote destination")
    };
    if from.same_server(to) {
        if let Some(outcome) = session(plan, &resolved[0], log, None).await {
            return outcome;
        }
        log.verbose("the server has no copy-data: the copy goes through this host");
    }
    let name = from.path.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
    let dir = std::env::temp_dir().join(format!("podssh-cp-{:016x}", rand::random::<u64>()));
    if let Err(e) = std::fs::create_dir(&dir) {
        let failed = Failed { fault: Fault::CantCreate, message: format!("{}: {e}", dir.display()) };
        return Outcome { done: Vec::new(), failed: Some((from.path.clone(), failed)) };
    }
    let local = dir.join(if name.is_empty() { "file" } else { &name });
    let leg = |source: Operand, destination: Operand, direction| Plan { direction, sources: vec![source], destination };
    let down = leg(Operand::Remote(from.clone()), Operand::Local(local.display().to_string()), Direction::Down);
    let mut outcome = session(&down, &resolved[0], log, None).await.expect("a copy down needs no copy-data");
    if outcome.failed.is_none() {
        // The local copy has the source's name, so a directory or an empty
        // path on the far side takes that name, as a copy up does.
        let up = leg(Operand::Local(local.display().to_string()), Operand::Remote(to.clone()), Direction::Up);
        outcome = session(&up, &resolved[1], log, Some(from.path.clone())).await.expect("a copy up needs no copy-data");
    }
    let _ = std::fs::remove_dir_all(&dir);
    outcome
}

/// One connection, one SFTP session, and each file of `plan` over it.
/// `named` replaces the source's name in the report (a copy across). A copy
/// within one server is `None` when the server has no `copy-data`.
async fn session(plan: &Plan, resolved: &Resolved, log: &Arc<Log>, named: Option<String>) -> Option<Outcome> {
    let mut outcome = Outcome { done: Vec::new(), failed: None };
    let first = match &plan.sources[0] {
        Operand::Local(p) => p.clone(),
        Operand::Remote(r) => r.path.clone(),
    };
    let reached = match crate::ssh::transport::reach(resolved, log).await {
        Ok(reached) => reached,
        Err(not) => {
            for line in &not.lines {
                log.error(line);
            }
            let fault = fault_of(not.code);
            let message = format!("{}: no connection to the server", resolved.options.destination.host);
            outcome.failed = Some((first, Failed { fault, message }));
            return Some(outcome);
        }
    };
    let handles = match podssh_ssh::run::connect_hops(reached.stream, &resolved.options, log).await {
        Ok(handles) => handles,
        Err(e) => {
            outcome.failed = Some((first, hop_failure(e)));
            return Some(outcome);
        }
    };
    let handle = handles.last().expect("the destination's connection");
    let sftp = match Sftp::open(handle, Limits::default()).await {
        Ok(sftp) => sftp,
        Err(e) => {
            let failed = Failed {
                fault: Fault::RelayUnreachable,
                message: format!("{}: {e}", resolved.options.destination.host),
            };
            outcome.failed = Some((first, failed));
            return Some(outcome);
        }
    };
    if plan.direction == Direction::Across && !sftp.has("copy-data") {
        let _ = sftp.close_session();
        podssh_ssh::run::disconnect_all(&handles).await;
        return None;
    }
    let many = plan.sources.len() > 1;
    for source in &plan.sources {
        let result = match (source, &plan.destination) {
            (Operand::Local(path), Operand::Remote(dest)) => {
                transfer::up(&sftp, handle, path, &dest.path, many, log).await
            }
            (Operand::Remote(src), Operand::Local(dest)) => {
                transfer::down(&sftp, handle, &src.path, dest, many, log).await
            }
            (Operand::Remote(src), Operand::Remote(dest)) => {
                transfer::within(&sftp, handle, &src.path, &dest.path, log).await
            }
            (Operand::Local(_), Operand::Local(_)) => unreachable!("a plan has a server"),
        };
        match result {
            Ok(mut done) => {
                if let Some(name) = &named {
                    done.source = name.clone();
                }
                outcome.done.push(done);
            }
            Err(failed) => {
                let name = match source {
                    Operand::Local(p) => p.clone(),
                    Operand::Remote(r) => r.path.clone(),
                };
                // A session that broke serves no further file.
                let session_gone = failed.fault == Fault::SessionFault;
                outcome.failed.get_or_insert((named.clone().unwrap_or(name), failed));
                if session_gone {
                    break;
                }
            }
        }
    }
    let _ = sftp.close_session();
    podssh_ssh::run::disconnect_all(&handles).await;
    Some(outcome)
}
