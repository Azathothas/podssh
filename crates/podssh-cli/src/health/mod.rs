//! `podssh health [OPTIONS] [user@]host` (T-189): the facts of the far host
//! (load, CPUs, memory and swap, uptime, network bytes and their rate over
//! one second, disks, processes, and the limits of its cgroup, T-480), from
//! one command that only reads. The
//! host is resolved as `podssh ssh` resolves its destination, reached on the
//! same road, and logged in to by the same SSH client; then one exec runs a
//! fixed script ([`script`]), whose answer is read ([`parse`]) and shown,
//! one line for each fact or one JSON object ([`show`]). With
//! `--preflight` (T-482), the same login then asks what the far server
//! allows of what a long command needs later ([`preflight`]).
//!
//! **Exit codes are those of `podssh ssh`**: 0 with the facts, also for a
//! host with no `/proc`, which gives its system's name only; 255 for a
//! failure (no connection, no login, no `sh`, no answer); 64 and 78 before
//! anything connects. With `--preflight`, once the login is done, those of
//! `doctor`: 1 when a check failed or the facts did not come, else 0.

pub mod cgroup;
pub mod parse;
pub mod preflight;
pub mod script;
pub mod show;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use clap::ArgMatches;
use podssh_ssh::{Connection, Log};
use serde_json::Value;

use crate::exit_codes::EXIT_USAGE;
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved};
use parse::Facts;

/// The limit on the whole run: the road, the login and the script; the
/// preflight has [`preflight::MORE`] past it.
const RUN_LIMIT: Duration = Duration::from_secs(120);

/// What `podssh health` was given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthArgs {
    /// The connection flags and the destination, read as `ssh` reads them:
    /// the rows of `health` share their ids.
    pub ssh: SshArgs,
    pub json: bool,
    /// `--preflight`: after the facts, what the far server allows (T-482).
    pub preflight: bool,
    /// `(flag as written, what to use instead, why)`, as each verb carries
    /// them, so that a `Refused` row added later refuses.
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl HealthArgs {
    /// Read the values out of `health`'s matches.
    pub fn from_matches(m: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let flag = |id: &str| m.try_get_one::<bool>(id).ok().flatten().copied().unwrap_or(false);
        HealthArgs { ssh: SshArgs::from_matches(m), json: flag("json"), preflight: flag("preflight"), refused }
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

/// What a run found: the facts or why none came, whether the login was
/// done, and the preflight's checks when they were asked for.
struct Asked {
    facts: Result<Facts, Failure>,
    logged_in: bool,
    checks: Option<preflight::Checks>,
}

impl Asked {
    /// A run that did not log in: with the preflight, its one line says why.
    fn not_logged_in(failure: Failure, preflight: bool) -> Asked {
        let checks = preflight.then(|| preflight::Checks::not_logged_in(&failure.why));
        Asked { facts: Err(failure), logged_in: false, checks }
    }

    /// The exit: `ssh`'s, but after a login with the preflight, `doctor`'s.
    fn code(&self) -> i32 {
        match (&self.checks, &self.facts) {
            (Some(checks), facts) if self.logged_in => {
                if checks.failed() || facts.is_err() {
                    crate::doctor::EXIT_FAILED
                } else {
                    0
                }
            }
            (_, Ok(_)) => 0,
            (_, Err(failure)) => failure.code,
        }
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
        log.warning(warning);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh health: could not start the async runtime: {e}");
            return podssh_ssh::EXIT_FAILURE;
        }
    };
    let limit = if args.preflight { RUN_LIMIT + preflight::MORE } else { RUN_LIMIT };
    // On the heap: the future of a road is large, and Windows gives the
    // main thread 1 MiB of stack.
    let asked = runtime.block_on(crate::ssh::transport::settled(async {
        tokio::time::timeout(limit, Box::pin(ask(&resolved, &destination, &log, args.preflight))).await
    }));
    // A read of a helper thread may still wait; the run is over.
    runtime.shutdown_background();
    let late = format!("the run passed its limit of {} s", limit.as_secs());
    let asked = asked.unwrap_or_else(|_| Asked::not_logged_in(Failure::new(late), args.preflight));
    let code = asked.code();
    if let Err(failure) = &asked.facts {
        log.error(&format!("health {destination}: {}", failure.why));
    }
    if args.json {
        let shown = asked.facts.as_ref().map_err(|failure| failure.why.as_str());
        let mut doc = show::json(&destination, shown, code);
        doc["preflight"] = asked.checks.as_ref().map_or(Value::Null, preflight::Checks::json);
        let _ = writeln!(out, "{doc}");
        return code;
    }
    let facts = asked.facts.as_ref().map(|facts| show::lines(&destination, facts)).unwrap_or_default();
    let checks = asked.checks.as_ref().map(preflight::Checks::lines).unwrap_or_default();
    for line in facts.iter().chain(&checks) {
        let _ = writeln!(out, "{line}");
    }
    code
}

/// Reach the host and log in: each hop's connection, the destination's
/// last, and the road that carried them, as the preflight says it.
async fn login(resolved: &Resolved, log: &Arc<Log>) -> Result<(Vec<Connection>, preflight::Road), Failure> {
    let reached = crate::ssh::transport::reach(resolved, log).await.map_err(|not| {
        let why = if not.lines.is_empty() { "no connection".to_string() } else { not.lines.join("; ") };
        // A target that the relay cannot carry is the command line's fault.
        let code = if not.code == EXIT_USAGE { EXIT_USAGE } else { podssh_ssh::EXIT_FAILURE };
        Failure { code, why }
    })?;
    let road = preflight::Road::of(resolved, &reached);
    crate::ssh::transport::keep(reached.layer);
    let handles = podssh_ssh::run::connect_hops(reached.stream, &resolved.options, log)
        .await
        .map_err(|e| Failure::new(e.to_string()))?;
    Ok((handles, road))
}

/// Log in, run the script and read its answer; with `preflight`, then
/// each check of the preflight on the same connection.
async fn ask(resolved: &Resolved, destination: &str, log: &Arc<Log>, preflight: bool) -> Asked {
    let (handles, road) = match login(resolved, log).await {
        Ok(logged_in) => logged_in,
        Err(failure) => return Asked::not_logged_in(failure, preflight),
    };
    let handle = handles.last().expect("the destination");
    log.verbose("reading the facts: one exec of sh, which only reads");
    let got = podssh_ssh::exec::capture(handle, &script::command(), script::LIMIT, script::CAP).await;
    let facts = match got {
        Ok(got) => parse::answer(&got).map_err(Failure::new),
        Err(e) => Err(Failure::new(format!("the facts: {e}"))),
    };
    let checks = match preflight {
        true => {
            let shown = facts.as_ref().map_err(|failure| failure.why.as_str());
            Some(preflight::run(handle, &road, destination, shown, log).await)
        }
        false => None,
    };
    podssh_ssh::run::disconnect_all(&handles).await;
    Asked { facts, logged_in: true, checks }
}
