//! `podssh cp` and `podssh mv`: files between this host and a server, over
//! SFTP (T-133), or by exec when the server has no SFTP ([`byexec`]); `mv`
//! removes each source once its copy is verified ([`moving`], T-138). A copy
//! whose connection breaks goes on over a new one, at its offset
//! ([`resume`], T-136).
//!
//! **The destination's name never holds a file that was not verified**
//! ([`transfer`]): the bytes go to a temporary name beside it, the SHA-256 of
//! what was sent is compared with the far side's, and only then is the file
//! renamed onto the destination. The whole copy, the login included, has the
//! `--timeout` deadline.
//!
//! **Exit codes are sysexits**, as `proxy`'s: 64 a usage error; 66 a source
//! that is missing or cannot be read, or that changed during a move; 69 no
//! server to copy with (the relay or the host cannot be reached, or the
//! server has neither SFTP nor a copy by exec); 70 a copy that went wrong
//! (the digests differ, the session broke), or a verified move whose source
//! could not be removed; 73 a destination that cannot be written; 75 the
//! `--timeout` passed; 77 a login or a host key refused; 78 a setting of the
//! environment. With several files, the first failure's code.

pub mod byexec;
mod bysftp;
mod digest;
mod link;
mod moving;
pub mod operand;
pub mod plan;
mod resume;
mod session;
mod transfer;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use clap::ArgMatches;
use podssh_ssh::Log;

use crate::exitmap::Fault;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved};
use moving::After;
use operand::{Operand, Remote};
use plan::{Direction, Plan};
use resume::Before;
use session::session;
use transfer::{Done, Failed};

/// `cp`'s or `mv`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpArgs {
    /// SRC... DST, as typed.
    pub paths: Vec<String>,
    /// The connection flags, read as `ssh` reads them: `cp`'s rows share
    /// their ids. The destination comes from the operands.
    pub ssh: SshArgs,
    /// `mv`: each source goes once its copy is verified.
    pub moving: bool,
}

impl CpArgs {
    /// Read the values out of `cp`'s or `mv`'s matches.
    pub fn from_matches(m: &ArgMatches, moving: bool) -> Self {
        let paths = if m.try_contains_id("paths").unwrap_or(false) {
            m.get_many::<String>("paths").map(|v| v.cloned().collect()).unwrap_or_default()
        } else {
            Vec::new()
        };
        CpArgs { paths, ssh: SshArgs::from_matches(m), moving }
    }
}

/// What a run ended with: each file done, and the first failure.
#[derive(Default)]
struct Outcome {
    done: Vec<Done>,
    failed: Option<(String, Failed)>,
    /// The first leg of a move between servers: each source as it was.
    recorded: Vec<Before>,
}

/// Run `podssh cp` or `podssh mv`; returns the process exit code.
pub fn run_cp(args: &CpArgs, deadline: Option<Duration>, jsonl: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let verb = if args.moving { "mv" } else { "cp" };
    let plan = match plan::plan(&args.paths, cfg!(windows)) {
        Ok(plan) => plan,
        Err(why) => {
            let _ = writeln!(err, "podssh {verb}: {why}.\n  Nothing has been attempted.");
            return Fault::Usage.code();
        }
    };
    if let Some(why) = args.moving.then(|| moving::same_text(&plan)).flatten() {
        let _ = writeln!(err, "podssh mv: {why}.\n  Nothing has been attempted.");
        return Fault::Usage.code();
    }
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report(verb, err);
    }
    let resolve_for = |server: &Remote| {
        let mut ssh = args.ssh.clone();
        ssh.destination = Some(server.destination());
        resolve::resolve_or_refuse(&ssh, &Env::from_process())
    };
    let servers: Vec<Remote> = match (&plan.sources[0], &plan.destination) {
        (Operand::Remote(a), Operand::Remote(b)) => vec![a.clone(), b.clone()],
        _ => plan.server().cloned().into_iter().collect(),
    };
    let mut resolved = Vec::new();
    for server in &servers {
        match resolve_for(server) {
            Ok(mut r) => {
                // Each new connection of this run meets the first one's host
                // key (T-136), and logs in as the first did, with no second
                // question (T-137).
                r.options.host_key_pin = Some(podssh_ssh::hostkey::Pin::default());
                r.options.remembered = Some(podssh_ssh::remember::Remembered::default());
                resolved.push(r);
            }
            Err(refusal) => return refusal.report(verb, err),
        }
    }
    let log = Arc::new(Log::new(resolved[0].options.log_level));
    // Before any byte moves, and before the first line of -v.
    if let Some(text) = args.moving.then(|| moving::notice(&args.paths, &plan)).flatten() {
        log.info(&text);
    }
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
    let after = if args.moving { After::Remove } else { After::Keep };
    let run = run_plan(&plan, &resolved, &log, after);
    let outcome = runtime.block_on(async {
        match deadline {
            Some(limit) => tokio::time::timeout(limit, run).await.unwrap_or_else(|_| Outcome {
                failed: Some((
                    String::new(),
                    Failed::new(Fault::TimedOut, format!("the --timeout of {} s passed", limit.as_secs())),
                )),
                ..Outcome::default()
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
        let sha256 = done.sum.as_ref().map(digest::hex);
        if jsonl {
            let mut line = serde_json::json!({
                "event": "done",
                "source": done.source,
                "destination": done.destination,
                "bytes": done.bytes,
                "sha256": sha256,
                "verified_by": done.verified_by,
                "atomic": !done.not_atomic,
            });
            if let Some(removed) = done.removed {
                line["source_removed"] = removed.into();
            }
            let _ = writeln!(out, "{line}");
        } else {
            let how = match &sha256 {
                Some(hex) => format!("{} bytes, SHA-256 {hex} (far side: {})", done.bytes, done.verified_by),
                None => format!("{} bytes, renamed on the server", done.bytes),
            };
            let source = match done.removed {
                Some(true) => "; the source is gone",
                Some(false) => "; the source stays",
                None => "",
            };
            log.verbose(&format!("{} -> {}: {how}{source}", done.source, done.destination));
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

/// Run each copy of the plan; `after` says what becomes of each source.
async fn run_plan(plan: &Plan, resolved: &[Resolved], log: &Arc<Log>, after: After) -> Outcome {
    match plan.direction {
        Direction::Up | Direction::Down => {
            session(plan, &resolved[0], log, None, after).await.expect("up and down need no copy-data")
        }
        Direction::Across => across(plan, resolved, log, after).await,
    }
}

/// Server to server. Within one server, a move is the server's rename, and a
/// copy on a server with `copy-data` stays there; else down to a local
/// temporary file, then up from it, one connection at a time (`AGENTS.md`,
/// rule 2), each copy verified; a move then removes the source in a third.
async fn across(plan: &Plan, resolved: &[Resolved], log: &Arc<Log>, after: After) -> Outcome {
    let (Operand::Remote(from), Operand::Remote(to)) = (&plan.sources[0], &plan.destination) else {
        unreachable!("a copy across has a remote source and a remote destination")
    };
    let moving = after == After::Remove;
    if from.same_server(to) {
        if moving {
            if let Some(outcome) = rename_session(from, to, &resolved[0], log).await {
                return outcome;
            }
            log.info(&format!(
                "{}: the server could not rename it, so this is a copy, a digest check, then a delete; \
                 it is not atomic",
                from.path
            ));
        }
        if let Some(outcome) = session(plan, &resolved[0], log, None, after).await {
            return outcome;
        }
        log.verbose("the server has no copy-data: the copy goes through this host");
    }
    let name = from.path.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
    let dir = std::env::temp_dir().join(format!("podssh-cp-{:016x}", rand::random::<u64>()));
    if let Err(e) = std::fs::create_dir(&dir) {
        let failed = Failed::new(Fault::CantCreate, format!("{}: {e}", dir.display()));
        return Outcome { failed: Some((from.path.clone(), failed)), ..Outcome::default() };
    }
    let local = dir.join(if name.is_empty() { "file" } else { &name });
    let leg = |source: Operand, destination: Operand, direction| Plan { direction, sources: vec![source], destination };
    let down = leg(Operand::Remote(from.clone()), Operand::Local(local.display().to_string()), Direction::Down);
    let first = if moving { After::Record } else { After::Keep };
    let mut outcome = session(&down, &resolved[0], log, None, first).await.expect("a copy down needs no copy-data");
    let recorded = std::mem::take(&mut outcome.recorded);
    if outcome.failed.is_none() {
        // The local copy has the source's name, so a directory or an empty
        // path on the far side takes that name, as a copy up does.
        let up = leg(Operand::Local(local.display().to_string()), Operand::Remote(to.clone()), Direction::Up);
        outcome = session(&up, &resolved[1], log, Some(from.path.clone()), After::Keep)
            .await
            .expect("a copy up needs no copy-data");
    }
    let _ = std::fs::remove_dir_all(&dir);
    let copied = outcome.done.last().cloned();
    if let (true, true, Some(before), Some(copied)) = (moving, outcome.failed.is_none(), recorded.first(), copied) {
        let removed = remove_session(from, before, &copied, &resolved[0], log).await;
        if let Some(done) = outcome.done.last_mut() {
            done.removed = Some(removed.is_ok());
        }
        if let Err(failed) = removed {
            outcome.failed = Some((from.path.clone(), failed));
        }
    }
    outcome
}

/// A move within one server: the server renames. `None` when it could not,
/// for a copy and a delete instead.
async fn rename_session(from: &Remote, to: &Remote, resolved: &Resolved, log: &Arc<Log>) -> Option<Outcome> {
    let mut outcome = Outcome::default();
    let link = match link::connect(resolved, log).await {
        Ok(link) => link,
        Err(failed) => {
            outcome.failed = Some((from.path.clone(), failed));
            return Some(outcome);
        }
    };
    let result = moving::rename(&link, &from.path, &to.path, log).await;
    link.close().await;
    match result {
        Ok(Some(done)) => outcome.done.push(done),
        Ok(None) => return None,
        Err(failed) => outcome.failed = Some((from.path.clone(), failed)),
    }
    Some(outcome)
}

/// The last step of a move between servers: remove the source on its
/// server, when it is still what was copied.
async fn remove_session(
    from: &Remote,
    before: &Before,
    done: &Done,
    resolved: &Resolved,
    log: &Arc<Log>,
) -> Result<(), Failed> {
    let link = link::connect(resolved, log).await.map_err(|f| moving::not_removed(&from.path, &f.message))?;
    let removed = moving::remove_far(&link, &from.path, before, done).await;
    link.close().await;
    removed
}
