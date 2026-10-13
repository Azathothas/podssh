//! `podssh job` (T-193): jobs on a far host that outlive the connection.
//! `start HOST -- COMMAND` starts the command in the host's tmux and prints
//! its ID; `list HOST` gives each job with its state and its exit status;
//! `log HOST ID` gives its output; `stop HOST ID` ends it and removes it.
//! The host is a plain POSIX host reached with SSH: nothing of podssh runs
//! there but the far script ([`far`]), under sh, with tmux, which it probes
//! before anything starts.
//!
//! **tmux holds each job.** The job outlives the connection, and `stop`
//! ends the tmux session of that exact name, so that no other process can
//! take its place, as a process ID given again could. With no tmux nothing
//! starts, and the exit is 255 with the reason. The output and the status
//! go to files of a private directory, so that they outlive the job too.
//!
//! **Exit codes are those of `podssh ssh`**: 64 a usage error and 78 a
//! setting, before anything connects; 255 a failure of podssh (no
//! connection, no login, no tmux, no such job); else 0.

pub mod far;
pub mod list;

use std::io::Write;
use std::sync::Arc;

use clap::ArgMatches;
use podssh_ssh::{Connection, Log, EXIT_FAILURE};

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved, Transport};

/// The subcommands, in the order of the manual.
pub const SUBCOMMANDS: &[&str] = &["start", "list", "log", "stop"];
/// The hex digits of an ID.
pub const ID_LEN: usize = 8;

/// `job`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobArgs {
    pub subcommand: Option<String>,
    pub host: Option<String>,
    /// The words after the host: an ID, or the command after `--`.
    pub words: Vec<String>,
    /// Whether `--` came on the command line: a command must follow it, so
    /// that no word of it is read as a flag of podssh.
    pub dashed: bool,
    /// The connection flags, read as `ssh` reads them: `job`'s rows share
    /// their ids. The destination is the host.
    pub ssh: SshArgs,
    /// `(flag as written, what to use instead, why)`, as each verb carries
    /// them, so that a `Refused` row added later refuses.
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl JobArgs {
    /// Read the values out of `job`'s matches; `dashed` when the command
    /// line held `--`.
    pub fn from_matches(m: &ArgMatches, dashed: bool, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let one = |id: &str| m.try_get_one::<String>(id).ok().flatten().cloned();
        let words =
            m.try_get_many::<String>("words").ok().flatten().map(|v| v.cloned().collect()).unwrap_or_default();
        JobArgs { subcommand: one("subcommand"), host: one("host"), words, dashed, ssh: SshArgs::from_matches(m), refused }
    }
}

/// What a command line of `job` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Start the command: its words joined with spaces, as OpenSSH joins
    /// them, for sh on the host.
    Start(String),
    List,
    Log(String),
    Stop(String),
}

/// An ID as `start` printed it: 8 hex digits, in either case.
pub fn id(text: &str) -> Result<String, String> {
    if text.len() == ID_LEN && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(text.to_ascii_lowercase())
    } else {
        Err(format!("{text}: an ID is the {ID_LEN} hex digits that podssh job start printed"))
    }
}

/// A new ID: 8 random hex digits.
pub fn new_id() -> String {
    format!("{:08x}", rand::random::<u32>())
}

/// The time now, in milliseconds since 1970, which orders the jobs.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The action of `args`, or why the command line is refused (64).
pub fn action(args: &JobArgs) -> Result<Action, String> {
    let Some(sub) = args.subcommand.as_deref() else {
        return Err(format!("give what to do and the host: podssh job {} HOST", SUBCOMMANDS.join("|")));
    };
    if !SUBCOMMANDS.contains(&sub) {
        return Err(format!("{sub} is not a command of podssh job: give {}", SUBCOMMANDS.join(", ")));
    }
    if args.host.is_none() {
        return Err(format!("give the host: podssh job {sub} HOST"));
    }
    let words = args.words.as_slice();
    match (sub, words) {
        ("start", []) => Err("give the command after --: podssh job start HOST -- COMMAND".into()),
        ("start", _) if !args.dashed => {
            Err("give the command after --, so that no word of it is read as a flag: podssh job start HOST -- COMMAND"
                .into())
        }
        ("start", _) => {
            let command = words.join(" ");
            if command.contains(['\n', '\0']) {
                return Err("the command holds a newline or a NUL, which no word of a far shell can carry".into());
            }
            Ok(Action::Start(command))
        }
        ("list", []) => Ok(Action::List),
        ("list", [extra, ..]) => Err(format!("list takes no word after the host: {extra}")),
        ("log", [one]) => Ok(Action::Log(id(one)?)),
        ("stop", [one]) => Ok(Action::Stop(id(one)?)),
        _ => Err(format!("give one ID: podssh job {sub} HOST ID")),
    }
}

/// The connection to `host`, resolved as `podssh ssh` resolves its
/// destination, with the `Host` blocks of ssh_config for it: no terminal and
/// no input, no agent and no forward. A `node://` or `iroh:` destination is
/// refused: a job needs the host's own sh.
pub(crate) fn plan(host: &str, args: &SshArgs, env: &Env) -> Result<Resolved, Refusal> {
    let mut ssh = args.clone();
    ssh.destination = Some(host.to_string());
    ssh.no_tty = true;
    ssh.stdin_null = true;
    let mut resolved = resolve::resolve_or_refuse(&ssh, env)?;
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
    let host = args.host.clone().unwrap_or_default();
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("job", err);
    }
    let resolved = match plan(&host, &args.ssh, &Env::from_process()) {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal.report("job", err),
    };
    let log = Arc::new(Log::new(resolved.options.log_level));
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
    // On the heap: the future of a connection is large, and Windows gives
    // the main thread 1 MiB of stack.
    let code = runtime.block_on(Box::pin(perform(&action, &host, &resolved, &log, out)));
    runtime.shutdown_background();
    code
}

/// Connect, act, and close: the exit code.
async fn perform(action: &Action, host: &str, resolved: &Resolved, log: &Arc<Log>, out: &mut dyn Write) -> i32 {
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

async fn act(action: &Action, host: &str, handle: &Connection, log: &Log, out: &mut dyn Write) -> Result<(), String> {
    match action {
        Action::Start(command) => {
            let id = new_id();
            let name = list::dir_name(now_ms(), &id);
            let lines = far::lines(handle, host, &["start", name.as_str(), command.as_str()]).await?;
            let first = first_line(host, &lines)?;
            if first != format!("started {id}") {
                return Err(unexpected(host, first));
            }
            let _ = writeln!(out, "{id}");
            log.verbose(&format!("job {id} runs on {host}: {command}"));
            Ok(())
        }
        Action::List => {
            let lines = far::lines(handle, host, &["list"]).await?;
            first_line(host, &lines)?;
            let jobs = list::parse(&lines).ok_or_else(|| format!("{host}: the list of its jobs came cut"))?;
            let _ = out.write_all(list::text(&jobs).as_bytes());
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
    }
}

#[cfg(test)]
mod tests;
