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
pub(crate) mod bysftp;
pub(crate) mod chunks;
pub mod delta;
pub(crate) mod digest;
pub mod gauge;
pub mod in_place;
pub(crate) mod link;
pub mod meta;
mod mirror;
mod moving;
pub mod operand;
pub(crate) mod pipe;
pub mod plan;
pub mod rate;
mod report;
pub(crate) mod resume;
pub(crate) mod session;
pub(crate) mod transfer;
pub mod tree;
mod tree_copy;

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
use report::report;
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
    /// The verb that the user typed, for messages: `cp`, `mv` or `scp`.
    pub verb: &'static str,
    /// scp's `-X NAME=VALUE`, for its SFTP requests (T-140).
    pub sftp_options: Vec<String>,
    /// `--parallel K` of `cp` and `mv`: the tasks of one file (T-141).
    pub parallel: Option<String>,
    /// `--delta` of `cp` and `mv`: only the blocks that changed (T-142).
    pub delta: bool,
    /// `-r`, each `--exclude`, `--exclude-from` and `--dry-run` (T-143).
    pub recursive: bool,
    pub excludes: Vec<String>,
    pub exclude_from: Option<String>,
    pub dry_run: bool,
    /// `--delete` (T-144).
    pub delete: bool,
    /// `-l KBITS`: the bandwidth (T-145).
    pub limit: Option<String>,
    /// `-p`, `--owner` and `--sparse` (T-146).
    pub preserve: bool,
    pub owner: bool,
    pub sparse: bool,
    /// `--inplace` (T-147).
    pub inplace: bool,
}

impl CpArgs {
    /// Read the values out of the matches of `verb`: `cp`, `mv` or `scp`.
    pub fn from_matches(m: &ArgMatches, verb: &'static str) -> Self {
        let paths = if m.try_contains_id("paths").unwrap_or(false) {
            m.get_many::<String>("paths").map(|v| v.cloned().collect()).unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut ssh = SshArgs::from_matches(m);
        // scp's -B is OpenSSH's BatchMode.
        if m.try_get_one::<bool>("batch-mode").ok().flatten().copied().unwrap_or(false) {
            ssh.options.push("BatchMode=yes".into());
        }
        let sftp_options = if m.try_contains_id("sftp-option").unwrap_or(false) {
            m.get_many::<String>("sftp-option").map(|v| v.cloned().collect()).unwrap_or_default()
        } else {
            Vec::new()
        };
        let parallel = if m.try_contains_id("parallel").unwrap_or(false) {
            m.get_one::<String>("parallel").cloned()
        } else {
            None
        };
        let flag = |id: &str| m.try_get_one::<bool>(id).ok().flatten().copied().unwrap_or(false);
        let many = |id: &str| -> Vec<String> {
            if m.try_contains_id(id).unwrap_or(false) {
                m.get_many::<String>(id).map(|v| v.cloned().collect()).unwrap_or_default()
            } else {
                Vec::new()
            }
        };
        let exclude_from = many("exclude-from").pop();
        CpArgs {
            paths,
            ssh,
            moving: verb == "mv",
            verb,
            sftp_options,
            parallel,
            delta: flag("delta"),
            recursive: flag("recursive"),
            excludes: many("exclude"),
            exclude_from,
            dry_run: flag("dry-run"),
            delete: flag("delete"),
            limit: many("limit").pop(),
            preserve: flag("preserve"),
            owner: flag("owner"),
            sparse: flag("sparse"),
            inplace: flag("inplace"),
        }
    }
}

/// What a run ended with: each file done, and the first failure.
#[derive(Default)]
struct Outcome {
    done: Vec<Done>,
    failed: Option<(String, Failed)>,
    /// The first leg of a move between servers: each source as it was.
    recorded: Vec<Before>,
    /// The actions of a dry run (T-143), in their order.
    planned: Vec<tree_copy::Planned>,
    /// What `--delete` removed (T-144), and what waits for the end of the
    /// run.
    deleted: Vec<String>,
    pending: Vec<mirror::Pending>,
}

/// What `-r` and its flags ask for (T-143); `None` without `-r`. `scp -r`
/// follows links, as OpenSSH's does; `cp -r` copies them as links.
fn tree_of(args: &CpArgs) -> Result<Option<tree::Tree>, String> {
    if !args.recursive {
        if args.dry_run || args.delete || !args.excludes.is_empty() || args.exclude_from.is_some() {
            return Err("--dry-run, --delete, --exclude and --exclude-from go with -r".into());
        }
        return Ok(None);
    }
    let mut excludes = args.excludes.clone();
    if let Some(file) = &args.exclude_from {
        excludes.extend(
            tree::read_excludes(std::path::Path::new(file)).map_err(|e| format!("--exclude-from {file}: {e}"))?,
        );
    }
    Ok(Some(tree::Tree { excludes, dry_run: args.dry_run, follow: args.verb == "scp", delete: args.delete }))
}

/// `--inplace` down: a local destination that is a link or a directory,
/// refused before anything connects (T-147); `None` when each may be written.
fn inplace_before(plan: &Plan) -> Option<String> {
    let (Direction::Down, Operand::Local(dest)) = (plan.direction, &plan.destination) else { return None };
    if plan.tree.is_some() {
        return None;
    }
    let many = plan.sources.len() > 1;
    plan.sources.iter().find_map(|source| {
        let Operand::Remote(remote) = source else { return None };
        let name = remote.path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
        in_place::check_before(dest, name, many).err()
    })
}

/// Run `podssh cp` or `podssh mv`; returns the process exit code.
pub fn run_cp(args: &CpArgs, deadline: Option<Duration>, jsonl: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let verb = args.verb;
    let mut plan = match plan::plan(&args.paths, cfg!(windows)) {
        Ok(plan) => plan,
        Err(why) => {
            let _ = writeln!(err, "podssh {verb}: {why}.\n  Nothing has been attempted.");
            return Fault::Usage.code();
        }
    };
    let keep = meta::Keep { times: args.preserve, owner: args.owner, sparse: args.sparse };
    let shape = pipe::pipeline(None, None, &args.sftp_options).and_then(|pipe| {
        let tasks = pipe::tasks(args.parallel.as_deref())?;
        Ok(pipe::Shape { pipe, tasks, delta: args.delta, keep, inplace: args.inplace, mode: None })
    });
    plan.shape = match shape {
        Ok(shape) => shape,
        Err(why) => {
            let _ = writeln!(err, "podssh {verb}: {why}.\n  Nothing has been attempted.");
            return Fault::Usage.code();
        }
    };
    let limit = match args.limit.as_deref().map(|text| rate::parse("-l", text)).transpose() {
        Ok(limit) => limit,
        Err(why) => {
            let _ = writeln!(err, "podssh {verb}: {why}.\n  Nothing has been attempted.");
            return Fault::Usage.code();
        }
    };
    rate::set(limit);
    plan.tree = match tree_of(args) {
        Ok(tree) => tree,
        Err(why) => {
            let _ = writeln!(err, "podssh {verb}: {why}.\n  Nothing has been attempted.");
            return Fault::Usage.code();
        }
    };
    if let Some(why) = args.inplace.then(|| inplace_before(&plan)).flatten() {
        let _ = writeln!(err, "podssh {verb}: {why}.\n  Nothing has been attempted.");
        return Fault::Usage.code();
    }
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
        // A URI's port is that operand's own, over -P (T-139).
        if let Some(port) = server.port {
            ssh.port = Some(port.to_string());
        }
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
                // A copy runs nothing on the server that would use the agent
                // (T-036), so no agent channel is ever accepted.
                r.options.forward_agent = podssh_ssh::Agent::Off;
                resolved.push(r);
            }
            Err(refusal) => return refusal.report(verb, err),
        }
    }
    let log = Arc::new(Log::new(resolved[0].options.log_level));
    gauge::init(jsonl, resolved[0].options.log_level == podssh_ssh::LogLevel::Quiet);
    // Before any byte moves, and before the first line of -v.
    if let Some(text) = args.moving.then(|| moving::notice(&args.paths, &plan)).flatten() {
        log.info(&text);
    }
    if args.inplace {
        log.info(in_place::NOTICE);
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
    // On the heap: the copy's future is large, and Windows gives the main
    // thread 1 MiB of stack.
    let run = Box::pin(run_plan(&plan, &resolved, &log, after));
    let outcome = runtime.block_on(async {
        let run = async {
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
        };
        // The first SIGINT or SIGTERM (Ctrl-C on Windows) ends the copy in
        // flight and keeps what it made; a second one ends podssh at once.
        tokio::select! {
            outcome = run => Some(outcome),
            () = interrupted() => {
                tokio::spawn(async {
                    interrupted().await;
                    std::process::exit(130);
                });
                None
            }
        }
    });
    let Some(outcome) = outcome else {
        let kept = match resume::current() {
            Some((temp, side)) => {
                format!("; the partial copy stays at {temp}, and the same command goes on from it (its record: {side})")
            }
            None => String::new(),
        };
        let _ = writeln!(err, "podssh {verb}: interrupted{kept}");
        runtime.shutdown_background();
        return 130;
    };
    runtime.shutdown_background();
    report(&outcome, jsonl, out, &log)
}

/// A signal that asks the run to end: SIGINT or SIGTERM, or Ctrl-C on
/// Windows; never when none can be listened for. `podssh edit` waits for it
/// too.
pub(crate) async fn interrupted() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match (signal(SignalKind::interrupt()), signal(SignalKind::terminate())) {
            (Ok(mut int), Ok(mut term)) => {
                tokio::select! {
                    _ = int.recv() => {}
                    _ = term.recv() => {}
                }
            }
            _ => std::future::pending().await,
        }
    }
    #[cfg(windows)]
    {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
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
    let leg = |source: Operand, destination: Operand, direction| Plan {
        direction,
        sources: vec![source],
        destination,
        shape: plan.shape,
        tree: None,
    };
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
