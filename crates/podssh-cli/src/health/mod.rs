//! `podssh health [OPTIONS] [user@]host` (T-189): the facts of the far host
//! (load, CPUs, memory and swap, uptime, network bytes and their rate over
//! one second, disks, processes), from one command that only reads. The
//! host is resolved as `podssh ssh` resolves its destination, reached on the
//! same road, and logged in to by the same SSH client; then one exec runs a
//! fixed script ([`script`]), whose answer is read ([`parse`]) and shown,
//! one line for each fact or one JSON object ([`show`]).
//!
//! **Exit codes are those of `podssh ssh`**: 0 with the facts, also for a
//! host with no `/proc`, which gives its system's name only; 255 for a
//! failure (no connection, no login, no `sh`, no answer); 64 and 78 before
//! anything connects.

pub mod parse;
pub mod script;
pub mod show;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use clap::ArgMatches;
use podssh_ssh::Log;

use crate::exit_codes::EXIT_USAGE;
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved};
use parse::Facts;

/// The limit on the whole run: the road, the login and the script.
const RUN_LIMIT: Duration = Duration::from_secs(120);

/// What `podssh health` was given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthArgs {
    /// The connection flags and the destination, read as `ssh` reads them:
    /// the rows of `health` share their ids.
    pub ssh: SshArgs,
    pub json: bool,
    /// `(flag as written, what to use instead, why)`, as each verb carries
    /// them, so that a `Refused` row added later refuses.
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl HealthArgs {
    /// Read the values out of `health`'s matches.
    pub fn from_matches(m: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let json = m.try_get_one::<bool>("json").ok().flatten().copied().unwrap_or(false);
        HealthArgs { ssh: SshArgs::from_matches(m), json, refused }
    }
}

/// Why a run gave no facts, and its exit code.
struct Failure {
    code: i32,
    why: String,
}

impl Failure {
    fn new(why: impl Into<String>) -> Self {
        Failure { code: podssh_ssh::EXIT_FAILURE, why: why.into() }
    }
}

/// Run `podssh health`; the process exit code.
pub fn run(args: &HealthArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if args.ssh.destination.is_none() {
        return Refusal::usage("give the host: podssh health [user@]host").report("health", err);
    }
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("health", err);
    }
    // The script needs no terminal and no input.
    let mut ssh = args.ssh.clone();
    ssh.no_tty = true;
    ssh.stdin_null = true;
    let resolved = match resolve::resolve_or_refuse(&ssh, &Env::from_process()) {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal.report("health", err),
    };
    let opts = &resolved.options;
    let destination = format!("{}@{}", opts.user, opts.destination.host);
    let log = Arc::new(Log::new(opts.log_level));
    for note in &resolved.notes {
        log.verbose(note);
    }
    for warning in &resolved.warnings {
        log.info(warning);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh health: could not start the async runtime: {e}");
            return podssh_ssh::EXIT_FAILURE;
        }
    };
    // On the heap: the future of a road is large, and Windows gives the
    // main thread 1 MiB of stack.
    let asked = runtime.block_on(crate::ssh::transport::settled(async {
        tokio::time::timeout(RUN_LIMIT, Box::pin(ask(&resolved, &log))).await
    }));
    // A read of a helper thread may still wait; the run is over.
    runtime.shutdown_background();
    let late = format!("the run passed its limit of {} s", RUN_LIMIT.as_secs());
    let answer = asked.unwrap_or_else(|_| Err(Failure::new(late)));
    let code = match &answer {
        Ok(_) => 0,
        Err(failure) => {
            log.error(&format!("health {destination}: {}", failure.why));
            failure.code
        }
    };
    if args.json {
        let shown = answer.as_ref().map_err(|failure| failure.why.as_str());
        let _ = writeln!(out, "{}", show::json(&destination, shown, code));
    } else if let Ok(facts) = &answer {
        for line in show::lines(&destination, facts) {
            let _ = writeln!(out, "{line}");
        }
    }
    code
}

/// Reach the host, log in, run the script and read its answer.
async fn ask(resolved: &Resolved, log: &Arc<Log>) -> Result<Facts, Failure> {
    let reached = crate::ssh::transport::reach(resolved, log).await.map_err(|not| {
        let why = if not.lines.is_empty() { "no connection".to_string() } else { not.lines.join("; ") };
        // A target that the relay cannot carry is the command line's fault.
        let code = if not.code == EXIT_USAGE { EXIT_USAGE } else { podssh_ssh::EXIT_FAILURE };
        Failure { code, why }
    })?;
    crate::ssh::transport::keep(reached.layer);
    let handles = podssh_ssh::run::connect_hops(reached.stream, &resolved.options, log)
        .await
        .map_err(|e| Failure::new(e.to_string()))?;
    let handle = handles.last().expect("the destination");
    log.verbose("reading the facts: one exec of sh, which only reads");
    let got = podssh_ssh::exec::capture(handle, &script::command(), script::LIMIT, script::CAP).await;
    podssh_ssh::run::disconnect_all(&handles).await;
    let got = got.map_err(|e| Failure::new(format!("the facts: {e}")))?;
    parse::answer(&got).map_err(Failure::new)
}
