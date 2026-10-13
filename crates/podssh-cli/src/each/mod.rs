//! `podssh each HOSTS -- COMMAND` (T-183): one command on many hosts at
//! once. Each host is resolved as `podssh ssh` resolves its destination,
//! before anything connects, so that a bad host fails the run with 64 and
//! nothing has run anywhere. Then one runtime runs a task for each host,
//! `--parallel` at once ([`fan`]), each on the road and the SSH client of
//! `podssh ssh` ([`host`]), with no terminal, no input and no prompt.
//!
//! **Each line names its host.** The far output becomes lines that start
//! with `HOST: ` on stdout and stderr, and podssh's own messages of a host
//! start with `podssh: HOST: `; with `--output-dir` the bytes go unchanged
//! into a host's files ([`out`]). A summary on stderr gives each host and
//! its status.
//!
//! **The exit status** is the largest of the hosts': 0 only when each host
//! gave 0, and 255 when one could not connect or log in, as `podssh ssh`
//! exits. A usage error is 64 and a bad setting 78, before anything
//! connects; a file of `--output-dir` that cannot be made is 73.

// `--interactive`: each line typed to the shells of many hosts (T-185).
pub mod broadcast;
pub mod fan;
mod host;
pub mod out;

use std::io::Write;

use clap::ArgMatches;
use podssh_ssh::LogLevel;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::Env;
use fan::Ended;
use host::Plan;
use out::Place;

/// `--parallel` when it is not given.
pub const PARALLEL: usize = 8;
/// The most hosts at once that `--parallel` takes.
pub const MOST_AT_ONCE: usize = 64;

/// `each`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EachArgs {
    /// The hosts, as typed.
    pub hosts: Option<String>,
    /// The connection flags and the command, read as `ssh` reads them:
    /// `each`'s rows share their ids. The destination is each host in turn.
    pub ssh: SshArgs,
    /// `--parallel N`, as typed.
    pub parallel: Option<String>,
    pub fail_fast: bool,
    pub output_dir: Option<String>,
    /// `--interactive` and `--confirm` (T-185).
    pub interactive: bool,
    pub confirm: bool,
    /// `(flag as written, what to use instead, why)`, as each verb carries
    /// them, so that a `Refused` row added later refuses.
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl EachArgs {
    /// Read the values out of `each`'s matches.
    pub fn from_matches(m: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let one = |id: &str| {
            if m.try_contains_id(id).unwrap_or(false) {
                m.get_one::<String>(id).cloned()
            } else {
                None
            }
        };
        let flag = |id: &str| m.try_get_one::<bool>(id).ok().flatten().copied().unwrap_or(false);
        EachArgs {
            hosts: one("hosts"),
            ssh: SshArgs::from_matches(m),
            parallel: one("parallel"),
            fail_fast: flag("fail-fast"),
            output_dir: one("output-dir"),
            interactive: flag("interactive"),
            confirm: flag("confirm"),
            refused,
        }
    }
}

/// The value of `--parallel`: 1 to [`MOST_AT_ONCE`], else a refusal.
pub fn parallel(text: Option<&str>) -> Result<usize, String> {
    let Some(text) = text else { return Ok(PARALLEL) };
    match text.parse::<usize>() {
        Ok(n) if (1..=MOST_AT_ONCE).contains(&n) => Ok(n),
        _ => Err(format!("--parallel {text}: give a number of hosts from 1 to {MOST_AT_ONCE}")),
    }
}

/// Run `podssh each`; the process exit code.
pub fn run_each(args: &EachArgs, err: &mut dyn Write) -> i32 {
    let usage = |err: &mut dyn Write, why: String| Refusal::usage(why).report("each", err);
    let Some(word) = args.hosts.as_deref() else {
        return usage(err, "give the hosts and the command: podssh each HOSTS -- COMMAND".into());
    };
    if args.ssh.command.is_empty() {
        return usage(err, "give the command to run on each host: podssh each HOSTS -- COMMAND".into());
    }
    let parallel = match parallel(args.parallel.as_deref()) {
        Ok(n) => n,
        Err(why) => return usage(err, why),
    };
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("each", err);
    }
    // The hosts, their braces and groups expanded (T-184), then each host
    // before anything connects: a bad one fails the run, and nothing has
    // run anywhere.
    let env = Env::from_process();
    let labels = match crate::hosts::expand(word, &env.settings.groups) {
        Ok(labels) => labels,
        Err(refusal) => return refusal.report("each", err),
    };
    let mut plans = Vec::with_capacity(labels.len());
    for label in &labels {
        match host::plan(label, &args.ssh, &env) {
            Ok(plan) => plans.push(plan),
            Err(refusal) => return refusal.report("each", err),
        }
    }
    let files = match out::prepare(&labels, args.output_dir.as_deref()) {
        Ok(files) => files,
        Err(refusal) => return refusal.report("each", err),
    };
    say_once(&plans);
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh each: could not start the async runtime: {e}");
            return podssh_ssh::EXIT_FAILURE;
        }
    };
    // On the heap: the future of each host is large, and Windows gives the
    // main thread 1 MiB of stack.
    let ends = runtime.block_on(Box::pin(fan_out(&plans, files, parallel, args.fail_fast)));
    // A read of a helper thread may still wait; the run is over.
    runtime.shutdown_background();
    if plans.iter().any(|p| p.resolved.options.log_level > LogLevel::Quiet) {
        for line in fan::summary(&labels, &ends) {
            let _ = writeln!(err, "podssh each: {line}");
        }
    }
    fan::exit_status(&ends)
}

/// The notes and the warnings of the hosts, each text once, with its host:
/// the same warning of fifty hosts is one line.
fn say_once(plans: &[Plan]) {
    let mut said: Vec<&str> = Vec::new();
    for plan in plans {
        for note in &plan.resolved.notes {
            if !said.contains(&note.as_str()) {
                said.push(note);
                plan.log.verbose(note);
            }
        }
        for warning in &plan.resolved.warnings {
            if !said.contains(&warning.as_str()) {
                said.push(warning);
                plan.log.info(warning);
            }
        }
    }
}

/// The fan-out, with one writer for the lines of each host.
async fn fan_out(plans: &[Plan], files: Vec<Option<out::Files>>, parallel: usize, fail_fast: bool) -> Vec<Ended> {
    if let Some(first) = plans.first() {
        host::first_token(&first.resolved, &first.log).await;
    }
    let (to, lines) = tokio::sync::mpsc::channel(64);
    let writer = tokio::spawn(out::writer(lines));
    let mut files = files;
    let ends = fan::fan_out(plans.len(), parallel, fail_fast, move |i| {
        let place = match files[i].take() {
            Some(files) => Place::Files(files),
            None => Place::Lines { label: plans[i].label.clone(), to: to.clone() },
        };
        host::run(&plans[i], place)
    })
    .await;
    // Each sender is gone with the closure: the writer ends with the last line.
    let _ = writer.await;
    ends
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_is_one_to_64() {
        assert_eq!(parallel(None), Ok(PARALLEL));
        assert_eq!(parallel(Some("1")), Ok(1));
        assert_eq!(parallel(Some("64")), Ok(64));
        for bad in ["0", "65", "-1", "x", ""] {
            assert!(parallel(Some(bad)).is_err(), "{bad:?}");
        }
    }
}
