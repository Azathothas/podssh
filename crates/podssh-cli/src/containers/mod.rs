//! `podssh containers [OPTIONS] [user@]host` (T-190): the containers of a
//! host, each with the `podssh ssh` command that enters it. One login runs
//! one script ([`list`]), which probes the far `PATH` for docker, podman and
//! kubectl and lists what each has: no program runs here, and none runs
//! there that a probe did not find. `--exec NAME` then enters NAME on the
//! same connection, so that a password is asked once.
//!
//! **The exit status**: 0 when each tool found gave its whole list; 65 when
//! one listed a name that podssh does not take, which is left out; 69 when
//! no tool is there, one failed, or `--exec` names no container that one
//! lists; 255 when the connection or the login failed, as `podssh ssh`.
//! With `--exec`, the session's status, as `podssh ssh` gives it. A usage
//! error is 64 before anything connects.

pub mod list;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use clap::ArgMatches;
use podssh_ssh::exec::{self, Captured};
use podssh_ssh::{Connection, Log, Request, RequestTty, EXIT_FAILURE};

use crate::exitmap::sysexits::{EX_DATAERR, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved, Transport};
use crate::ssh::transport;
use list::{Listing, Tool};

/// How long the list may take: kubectl asks its cluster, and a daemon that
/// hangs must not hang podssh.
const LIST_LIMIT: Duration = Duration::from_secs(60);
/// What the list may print that is read.
const CAP: usize = 1024 * 1024;
/// The program that `--exec` starts when `--shell` names none.
pub const SHELL: &str = "sh";

/// `containers`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainersArgs {
    /// The destination and the connection flags, read as `ssh` reads them:
    /// the rows share their ids.
    pub ssh: SshArgs,
    pub exec: Option<String>,
    pub shell: Option<String>,
    pub tool: Option<String>,
    /// `(flag as written, what to use instead, why)`, as each verb carries
    /// them, so that a `Refused` row added later refuses.
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl ContainersArgs {
    /// Read the values out of `containers`'s matches.
    pub fn from_matches(m: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let one = |id: &str| {
            if m.try_contains_id(id).unwrap_or(false) {
                m.get_one::<String>(id).cloned()
            } else {
                None
            }
        };
        ContainersArgs {
            ssh: SshArgs::from_matches(m),
            exec: one("exec"),
            shell: one("shell"),
            tool: one("tool"),
            refused,
        }
    }
}

/// The command line, checked before anything connects.
struct Plan {
    tools: Vec<Tool>,
    /// `--exec NAME` and the program to start in it.
    enter: Option<(String, String)>,
    /// The destination and the connection flags, as each line shows them.
    shown: String,
    /// `-tt`: a pty for `--exec` also with no terminal here.
    force_tty: bool,
}

fn plan(args: &ContainersArgs) -> Result<Plan, Refusal> {
    let Some(destination) = args.ssh.destination.as_deref() else {
        return Err("give the host: podssh containers [OPTIONS] [user@]host".into());
    };
    let tools = match args.tool.as_deref() {
        None => Tool::ALL.to_vec(),
        Some(word) => vec![Tool::parse(word).ok_or_else(|| format!("--tool {word}: give docker, podman or kubectl"))?],
    };
    let enter = match args.exec.as_deref() {
        Some(name) => {
            list::check_name(name)?;
            let shell = args.shell.clone().unwrap_or_else(|| SHELL.to_string());
            list::check_shell(&shell)?;
            Some((name.to_string(), shell))
        }
        None if args.shell.is_some() => return Err("--shell is the program of --exec; give --exec NAME too".into()),
        None if args.ssh.tty > 0 => return Err("-t asks for a pty for --exec; give --exec NAME too".into()),
        None => None,
    };
    let mut shown = list::flags(&args.ssh);
    shown.push(list::word(destination));
    Ok(Plan { tools, enter, shown: shown.join(" "), force_tty: args.ssh.tty > 1 })
}

/// The run of `ssh` for the list: its command, and nothing that a session
/// of `podssh ssh` would open beside it.
fn resolved(args: &ContainersArgs, plan: &Plan, env: &Env) -> Result<Resolved, Refusal> {
    let mut ssh = args.ssh.clone();
    ssh.command = vec![list::command(&plan.tools)];
    let mut resolved = resolve::resolve_or_refuse(&ssh, env)?;
    if matches!(resolved.transport, Transport::Node { .. } | Transport::Iroh { .. }) {
        return Err(Refusal::usage(
            "podssh containers reaches a host through the relay, with --direct or cf://; a node:// or iroh: \
             destination is for podssh ssh",
        ));
    }
    let forwards = !resolved.local.is_empty() || !resolved.options.remote_forwards.is_empty();
    if forwards || resolved.x11.is_some() || resolved.control.path.is_some() {
        let note = "podssh containers opens no forward, no X11 and no control socket: ssh_config's are not used";
        resolved.notes.push(note.to_string());
    }
    resolved.options.remote_forwards.clear();
    // Only podssh ssh runs a LocalCommand (T-191).
    if resolved.options.local_command.take().is_some() {
        resolved.notes.push("podssh containers runs no LocalCommand: the one of ssh_config is not used".to_string());
    }
    Ok(resolved)
}

/// Run `podssh containers`; the process exit code.
pub fn run_containers(args: &ContainersArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let plan = match plan(args) {
        Ok(plan) => plan,
        Err(refusal) => return refusal.report("containers", err),
    };
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("containers", err);
    }
    let resolved = match resolved(args, &plan, &Env::from_process()) {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal.report("containers", err),
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
    // On the heap: the future of a session is large, and Windows gives the
    // main thread 1 MiB of stack.
    let ended = runtime.block_on(Box::pin(run(&resolved, &plan, &log)));
    // A read on stdin may still wait in a helper thread; the run is over.
    runtime.shutdown_background();
    match ended {
        Ended::Lines(lines, code) => {
            for line in lines {
                let _ = writeln!(out, "{line}");
            }
            code
        }
        Ended::Code(code) => code,
    }
}

/// How the run ended: the lines of the list and the exit code, or the code
/// alone.
enum Ended {
    Lines(Vec<String>, i32),
    Code(i32),
}

async fn run(resolved: &Resolved, plan: &Plan, log: &Arc<Log>) -> Ended {
    let host = resolved.options.destination.host.clone();
    let reached = match transport::reach(resolved, log).await {
        Ok(reached) => reached,
        Err(failure) => {
            for line in &failure.lines {
                log.error(line);
            }
            return Ended::Code(EXIT_FAILURE);
        }
    };
    let relay = reached.relay;
    let handles = match podssh_ssh::upgrade::login(reached.stream, &resolved.options, relay.as_ref(), log).await {
        Ok(handles) => handles,
        Err(lines) => {
            for line in &lines {
                log.error(line);
            }
            return Ended::Code(EXIT_FAILURE);
        }
    };
    let listing = match listed(&handles, &plan.tools, &host, log).await {
        Ok(listing) => listing,
        Err(code) => {
            podssh_ssh::run::disconnect_all(&handles).await;
            return Ended::Code(code);
        }
    };
    let Some((name, shell)) = &plan.enter else {
        podssh_ssh::run::disconnect_all(&handles).await;
        return shown(&listing, plan, &host, log);
    };
    for listed in listing.tools.iter().filter(|t| !t.ok()) {
        say_failed(listed, log);
    }
    let holders = list::holders(&listing, name);
    let Some((first, full)) = holders.first() else {
        log.error(&format!("no container {name} on {host}: {}", found(&listing, &plan.tools)));
        podssh_ssh::run::disconnect_all(&handles).await;
        return Ended::Code(EX_UNAVAILABLE);
    };
    for (other, _) in &holders[1..] {
        log.info(&format!(
            "{} lists {name} too; podssh enters the one of {}, and --tool {} enters the other",
            other.tool.name(),
            first.tool.name(),
            other.tool.name()
        ));
    }
    // docker refuses -t when its input is no terminal: the pty and -it go
    // together.
    let pty = plan.force_tty || podssh_ssh::terminal::stdin_is_terminal();
    let line = list::enter(first.tool, full, shell, pty).join(" ");
    log.verbose(&format!("{host}: {line}"));
    let mut opts = resolved.options.clone();
    opts.request = Request::Exec(line);
    opts.request_tty = if pty { RequestTty::Force } else { RequestTty::No };
    Ended::Code(podssh_ssh::upgrade::request(handles, &opts, relay.as_ref(), log.clone()).await)
}

/// The script's listing on the destination of `handles`; else the exit
/// code, its cause said.
async fn listed(handles: &[Connection], tools: &[Tool], host: &str, log: &Log) -> Result<Listing, i32> {
    let Some(handle) = handles.last() else { return Err(EXIT_FAILURE) };
    let out = match exec::capture(handle, &list::command(tools), LIST_LIMIT, CAP).await {
        Ok(out) => out,
        Err(e) => {
            log.error(&format!("{host}: the list of containers: {e}"));
            return Err(EXIT_FAILURE);
        }
    };
    let listing = list::parse(&out.stdout, &out.stderr);
    if !listing.whole {
        log.error(&format!(
            "{host}: the list of containers did not run to its end ({}); it needs sh on the PATH of a command",
            said(&out)
        ));
        return Err(EX_UNAVAILABLE);
    }
    if listing.tools.is_empty() {
        log.error(&format!("{host}: {}", found(&listing, tools)));
        return Err(EX_UNAVAILABLE);
    }
    Ok(listing)
}

/// The lines of the list, and the exit code: 69 when a tool failed, 65 when
/// one listed a name that is left out.
fn shown(listing: &Listing, plan: &Plan, host: &str, log: &Log) -> Ended {
    let width = listing.tools.iter().flat_map(|t| t.names.iter().map(String::len)).max().unwrap_or(0);
    let mut out = Vec::new();
    for listed in &listing.tools {
        if !listed.ok() {
            say_failed(listed, log);
        } else {
            for line in &listed.errors {
                log.verbose(&format!("{}: {line}", listed.tool.name()));
            }
        }
        for refused in &listed.refused {
            log.error(&format!(
                "{} lists {refused:?}, which is no name that podssh passes to a shell; it is left out",
                listed.tool.name()
            ));
        }
        for name in &listed.names {
            // The pty of -t here, and -it there, for a person at a terminal.
            let enter = list::enter(listed.tool, name, SHELL, true).join(" ");
            let command = format!("podssh ssh -t {} -- {enter}", plan.shown);
            out.push(list::line(listed.tool, name, width, &command));
        }
    }
    let whole = listing.tools.iter().all(list::Listed::ok);
    if out.is_empty() && whole {
        log.info(&format!("{host}: no container in the lists of {}", found(listing, &plan.tools)));
    }
    let code = if !whole {
        EX_UNAVAILABLE
    } else if listing.tools.iter().any(|t| !t.refused.is_empty()) {
        EX_DATAERR
    } else {
        0
    };
    Ended::Lines(out, code)
}

/// A tool that gave no whole list: each line that it wrote, and its status.
fn say_failed(listed: &list::Listed, log: &Log) {
    let tool = listed.tool.name();
    for line in &listed.errors {
        log.error(&format!("{tool}: {line}"));
    }
    match listed.status {
        Some(status) => log.error(&format!("{tool} failed with exit status {status}; the other tools go on")),
        None => log.error(&format!("{tool}: its list was cut before its end")),
    }
}

/// Which tools the host has, or that it has none of those asked.
fn found(listing: &Listing, asked: &[Tool]) -> String {
    let names = |tools: Vec<&'static str>| match tools.as_slice() {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    if listing.tools.is_empty() {
        return match asked {
            [one] => format!("{} is not on the PATH of a command", one.name()),
            _ => format!("none of {} is on the PATH of a command", names(asked.iter().map(|t| t.name()).collect())),
        };
    }
    names(listing.tools.iter().map(|t| t.tool.name()).collect())
}

/// A command's end in a few words: its status, and its last line of error.
fn said(out: &Captured) -> String {
    let status = out.status.map_or_else(|| "no exit status".to_string(), |s| format!("exit {s}"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    match stderr.lines().rev().map(podssh_ws::text::one_line).find(|l| !l.is_empty()) {
        Some(line) => format!("{status}: {line}"),
        None => status,
    }
}
