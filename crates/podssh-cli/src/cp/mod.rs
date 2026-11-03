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

mod across;
pub mod byexec;
pub(crate) mod bysftp;
pub(crate) mod chunks;
pub mod clobber;
pub mod delta;
pub(crate) mod digest;
mod finish;
pub mod gauge;
pub mod in_place;
mod lanes;
pub(crate) mod link;
pub mod meta;
mod mirror;
mod moving;
pub mod operand;
mod outcome;
pub(crate) mod pipe;
pub mod plan;
pub mod rate;
mod report;
pub(crate) mod resume;
pub(crate) mod session;
pub(crate) mod summary;
pub(crate) mod sync;
pub(crate) mod transfer;
pub mod tree;
pub(crate) mod tree_conn;
mod tree_copy;
mod tree_items;

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
use outcome::Outcome;
use plan::{Direction, Plan};
use report::report;
use session::session;
use transfer::Failed;

// The tests of several files at once read the default (T-474).
pub use pipe::FILES_AT_ONCE;

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
    /// `--parallel K` of `cp` and `mv`: the files at once and the tasks of
    /// one file (T-141, T-297); with none, [`FILES_AT_ONCE`] files (T-474).
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
    /// `-n`, `-u`, `-b` and `--suffix SUFFIX` (T-473).
    pub no_clobber: bool,
    pub update: bool,
    pub backup: bool,
    pub suffix: Option<String>,
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
            no_clobber: flag("no-clobber"),
            update: flag("update"),
            backup: flag("backup"),
            suffix: many("suffix").pop(),
        }
    }
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
    let (dry_run, follow, delete) = (args.dry_run, args.verb == "scp", args.delete);
    Ok(Some(tree::Tree { excludes, dry_run, follow, delete, ..tree::Tree::default() }))
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
        let (files, tasks) = pipe::at_once(args.parallel.as_deref())?;
        let (inplace, suffix) = (args.inplace, args.suffix.as_deref());
        let clobber = clobber::of(args.no_clobber, args.update, args.backup, suffix, inplace)?;
        Ok(pipe::Shape { pipe, files, tasks, delta: args.delta, keep, inplace, mode: None, clobber })
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
    // scp keeps OpenSSH's output: no plain line in a pipe, and no summary.
    let scp = verb == "scp";
    gauge::init(jsonl, resolved[0].options.log_level == podssh_ssh::LogLevel::Quiet, !scp);
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
    let (started, mut timed_out) = (std::time::Instant::now(), false);
    // On the heap: the copy's future is large, and Windows gives the main
    // thread 1 MiB of stack.
    let run = Box::pin(run_plan(&plan, &resolved, &log, after));
    // A carrier that the copy's connections shared ends after it (T-595).
    let outcome = runtime.block_on(crate::ssh::transport::settled(async {
        let run = async {
            match deadline {
                Some(limit) => tokio::time::timeout(limit, run).await.unwrap_or_else(|_| {
                    timed_out = true;
                    let why = format!("the --timeout of {} s passed", limit.as_secs());
                    Outcome { failed: Some((String::new(), Failed::new(Fault::TimedOut, why))), ..Outcome::default() }
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
    }));
    let Some(outcome) = outcome else {
        // Several files at once leave a partial copy each (T-297).
        let kept = match resume::each_current().as_slice() {
            [] => String::new(),
            [(temp, side)] => {
                format!("; the partial copy stays at {temp}, and the same command goes on from it (its record: {side})")
            }
            many => {
                let (temps, sides): (Vec<&str>, Vec<&str>) =
                    many.iter().map(|(temp, side)| (temp.as_str(), side.as_str())).unzip();
                format!(
                    "; the partial copies stay at {}, and the same command goes on from each (their records: {})",
                    temps.join(", "),
                    sides.join(", ")
                )
            }
        };
        let _ = writeln!(err, "podssh {verb}: interrupted{kept}");
        runtime.shutdown_background();
        return 130;
    };
    runtime.shutdown_background();
    // After the --timeout the run's records went with its future, so a
    // summary would count nothing that it did (T-472).
    let took = (!scp && !args.dry_run && !timed_out).then(|| started.elapsed());
    report(&outcome, jsonl, out, &log, took)
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
        Direction::Across => across::across(plan, resolved, log, after).await,
    }
}
