//! `podssh run [OPTIONS] [user@]host[:DIR] [--] COMMAND...` (T-192): copy a
//! project to a stronger host, then run a command in it, with the exit
//! status of the command. The copy is that of `podssh cp -r -p`
//! ([`crate::cp::sync`]): each file to a temporary name, verified by its
//! digest, then renamed, with its times kept; so the next run sends only
//! the files whose size or time changed. `target/`, `node_modules/` and
//! `.git/` never go, nor what the project's `.podsshignore`, `--exclude` and
//! `--exclude-from` leave out. Then `cd DIR && COMMAND` runs on the same
//! connection, as `podssh ssh` runs a command; near the relay's limits, on a
//! new session (T-137). DIR is `~/.podssh/run/NAME` by default, NAME the
//! name of the local directory.
//!
//! **Exit codes are those of `podssh ssh`**: the command's status; 255 for a
//! failure of podssh, a copy that failed included, which runs nothing; 64 a
//! usage error and 78 a setting, before anything connects.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::ArgMatches;
use podssh_ssh::{Connection, Log, Request, EXIT_FAILURE};

use crate::cp::operand::{self, Operand, Remote};
use crate::cp::{link, sync, tree};
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved, Transport};

/// What is never copied, at any depth: the output of a build, the packages
/// of node, and the history of git.
pub const DEFAULT_EXCLUDES: &[&str] = &["target/", "node_modules/", ".git/"];
/// The project's own ignore file, read when it is there.
pub const IGNORE_FILE: &str = ".podsshignore";
/// The far directory of the projects, under the home directory, when the
/// command line names none.
pub const RUN_ROOT: &str = ".podssh/run";
/// The bytes that the relay session must still carry for the command; with
/// fewer, the command runs on a new session (T-137).
pub const SPARE: u64 = 16 << 20;

/// `run`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunArgs {
    /// `[user@]host[:DIR]`, as typed.
    pub target: Option<String>,
    /// `--from DIR`: the project here, else the working directory.
    pub from: Option<String>,
    pub excludes: Vec<String>,
    pub exclude_from: Option<String>,
    /// The connection flags and the command, read as `ssh` reads them:
    /// `run`'s rows share their ids. The destination is the target's host.
    pub ssh: SshArgs,
    /// `(flag as written, what to use instead, why)`, as each verb carries
    /// them, so that a `Refused` row added later refuses.
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl RunArgs {
    /// Read the values out of `run`'s matches.
    pub fn from_matches(m: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let one = |id: &str| m.try_get_one::<String>(id).ok().flatten().cloned();
        let excludes =
            m.try_get_many::<String>("exclude").ok().flatten().map(|v| v.cloned().collect()).unwrap_or_default();
        RunArgs {
            target: one("target"),
            from: one("from"),
            excludes,
            exclude_from: one("exclude-from"),
            ssh: SshArgs::from_matches(m),
            refused,
        }
    }
}

/// What a run copies, where, and what it runs there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The server, and the far directory: relative to the home directory,
    /// or absolute.
    pub far: Remote,
    /// The project here.
    pub local: PathBuf,
    pub tree: tree::Tree,
    /// `cd DIR && COMMAND`, for the login shell.
    pub command: String,
}

/// The far side of `[user@]host[:DIR]`: a host alone, or with the DIR of an
/// scp operand (`scp://` too). `~` and `~/` name the home directory, where
/// a relative DIR starts as well.
pub fn target(text: &str) -> Result<Remote, String> {
    let remote = match operand::parse(text, false)? {
        Operand::Remote(remote) => remote,
        Operand::Local(_) => match operand::parse(&format!("{text}:"), false)? {
            Operand::Remote(remote) => remote,
            Operand::Local(_) => return Err(format!("{text} names no host: give [user@]host[:DIR]")),
        },
    };
    let path = match remote.path.as_str() {
        "~" => ".".to_string(),
        path => path.strip_prefix("~/").unwrap_or(path).to_string(),
    };
    Ok(Remote { path, ..remote })
}

/// The project here: `--from DIR`, else the working directory; and its
/// name, which the far directory takes by default.
fn local_dir(from: Option<&str>) -> Result<(PathBuf, String), String> {
    let dir = match from {
        Some(dir) => PathBuf::from(dir),
        None => std::env::current_dir().map_err(|e| format!("the working directory: {e}"))?,
    };
    if !dir.is_dir() {
        return Err(format!("{} is no directory here; --from names the project to copy", dir.display()));
    }
    let real = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
    let name = real.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
    Ok((dir, name))
}

/// The plan of `args`, or why the command line is refused (64).
pub fn plan(args: &RunArgs) -> Result<Plan, String> {
    let text = args.target.as_deref().ok_or("give the host and the command: podssh run [user@]host[:DIR] -- COMMAND")?;
    if args.ssh.command.is_empty() {
        return Err("give the command to run there: podssh run [user@]host[:DIR] -- COMMAND".into());
    }
    let mut far = target(text)?;
    let (local, name) = local_dir(args.from.as_deref())?;
    if far.path.is_empty() {
        tree::check_name(&name, false)
            .map_err(|why| format!("the project's name: {why}; name the far directory, as host:DIR"))?;
        far.path = format!("{RUN_ROOT}/{name}");
    }
    // A copy onto the home directory or the root would mix the project
    // with what is there.
    if matches!(far.path.trim_end_matches('/'), "" | ".") || far.path.trim_matches('/').is_empty() {
        return Err(format!("{text}: the far directory is the home directory or the root; name one below it"));
    }
    let mut excludes: Vec<String> = DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();
    let ignore = local.join(IGNORE_FILE);
    if ignore.is_file() {
        excludes.extend(tree::read_excludes(&ignore).map_err(|e| format!("{}: {e}", ignore.display()))?);
    }
    if let Some(file) = &args.exclude_from {
        excludes.extend(tree::read_excludes(Path::new(file)).map_err(|e| format!("--exclude-from {file}: {e}"))?);
    }
    excludes.extend(args.excludes.iter().cloned());
    let dir = podssh_ssh::exec::shell_word(&far.path)
        .ok_or_else(|| format!("{}: a newline or a NUL has no word for a far shell", far.path))?;
    let command = format!("cd {dir} && {}", args.ssh.command.join(" "));
    let tree = tree::Tree { excludes, onto: true, changed_only: true, ..tree::Tree::default() };
    Ok(Plan { far, local, tree, command })
}

/// Run `podssh run`; the process exit code.
pub fn run_run(args: &RunArgs, err: &mut dyn Write) -> i32 {
    let plan = match plan(args) {
        Ok(plan) => plan,
        Err(why) => return Refusal::usage(why).report("run", err),
    };
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("run", err);
    }
    let mut ssh = args.ssh.clone();
    ssh.destination = Some(plan.far.destination());
    // A URI's port is the target's own, over -p.
    if let Some(port) = plan.far.port {
        ssh.port = Some(port.to_string());
    }
    let mut resolved = match resolve::resolve_or_refuse(&ssh, &Env::from_process()) {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal.report("run", err),
    };
    if matches!(resolved.transport, Transport::Node { .. } | Transport::Iroh { .. }) {
        let why = "podssh run reaches a host through the relay or with --direct; a node:// or iroh: destination is for \
                   podssh ssh";
        return Refusal::usage(why).report("run", err);
    }
    resolved.options.request = Request::Exec(plan.command.clone());
    // Each new connection of the run meets the first one's host key, and
    // logs in as the first did, with no second question (T-136, T-137).
    resolved.options.host_key_pin = Some(podssh_ssh::hostkey::Pin::default());
    resolved.options.remembered = Some(podssh_ssh::remember::Remembered::default());
    let log = Arc::new(Log::new(resolved.options.log_level));
    for note in &resolved.notes {
        log.verbose(note);
    }
    for warning in &resolved.warnings {
        log.info(warning);
    }
    crate::cp::gauge::init(false, resolved.options.log_level == podssh_ssh::LogLevel::Quiet);
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log.error(&format!("could not start the async runtime: {e}"));
            return EXIT_FAILURE;
        }
    };
    // On the heap: the copy's future is large, and Windows gives the main
    // thread 1 MiB of stack.
    let code = runtime.block_on(Box::pin(copy_then_run(&plan, &resolved, &log)));
    runtime.shutdown_background();
    code
}

/// The copy, then the command: its exit status, or 255.
async fn copy_then_run(plan: &Plan, resolved: &Resolved, log: &Arc<Log>) -> i32 {
    let first = match link::connect(resolved, log).await {
        Ok(first) => first,
        Err(failed) => {
            log.error(&failed.message);
            return EXIT_FAILURE;
        }
    };
    if let Err(failed) = sync::parents(&first, &plan.far.path).await {
        first.close().await;
        log.error(&format!("{}: {}; the command did not run", plan.far.path, failed.message));
        return EXIT_FAILURE;
    }
    let mut link = Some(first);
    let local = plan.local.display().to_string();
    match sync::up(&mut link, resolved, &local, &plan.far, &plan.tree, log).await {
        Ok(done) => log.verbose(&format!("{}: files sent {}, unchanged {}", plan.far.path, done.sent, done.unchanged)),
        Err(_) => {
            // Each failure was said as it came.
            if let Some(link) = link {
                link.close().await;
            }
            log.error(&format!("the copy to {} failed, so the command did not run", plan.far.path));
            return EXIT_FAILURE;
        }
    }
    let spent = link.as_ref().is_none_or(|l| l.meter.through_relay() && l.meter.left() < SPARE);
    if spent {
        if let Some(link) = link.take() {
            link.close().await;
        }
        log.verbose("the copy used most of the relay session: the command runs on a new one");
        let Some(handles) = crate::job::far::connect(resolved, log).await else { return EXIT_FAILURE };
        let code = command(handles.last().expect("the destination's connection"), resolved, log).await;
        podssh_ssh::run::disconnect_all(&handles).await;
        return code;
    }
    let link = link.expect("a connection, as the copy kept it");
    let code = command(link.handle(), resolved, log).await;
    link.close().await;
    code
}

/// The command on `handle`, as `podssh ssh` runs one: its exit status, or
/// 255 when the session ended with none.
async fn command(handle: &Connection, resolved: &Resolved, log: &Arc<Log>) -> i32 {
    let host = resolved.options.destination.host.clone();
    match podssh_ssh::session::run(handle, &resolved.options, &host, log).await {
        Ok(code) => code,
        Err(why) => {
            log.error(&why);
            EXIT_FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
