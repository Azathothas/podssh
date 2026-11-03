//! `podssh edit [user@]host:PATH` (T-149): one file of a server, changed in
//! an editor here. The file comes down as `podssh cp` copies one, into a new
//! private directory of the cache ([`local`]); the connection closes while
//! the editor runs ([`editor`]), with no time limit and no relay session
//! held; then, when the copy changed, a new connection checks that the far
//! file is still the one that came, and the copy goes up as `podssh cp`
//! sends one, with the far file's mode ([`far`]).
//!
//! **A change on the server is never lost**: when the far file's size, time
//! of change or SHA-256 is not the one fetched, nothing is sent, and the
//! exit is 73. **A change here is never lost either**: after a failure, a
//! copy that holds a change stays and is named, with its directory to
//! remove once it is merged; a copy with no change goes. A later run says
//! once which kept copies are more than 7 days old, and removes none.
//!
//! **`--no-terminal`** (T-510) runs an editor that needs no terminal, a
//! script as `sed -i`, with no input and its output on stderr; with no
//! terminal it needs `--timeout` (or `PODSSH_TIMEOUT`), which bounds the
//! editor's run, as `cp` needs one.
//!
//! **Exit codes are the sysexits of `cp`**: 64 a usage error or no terminal;
//! 78 no editor, an editor that does not start, or `PODSSH_CACHE_DIR` set to
//! none; 73 the far file changed, or no cache directory takes the copy; the
//! status of an editor that failed; 75 the `--timeout` passed while the
//! editor ran; 130 an interruption while a file moves, or while an editor
//! with no terminal runs; else the code of the copy that failed.

pub mod editor;
pub mod far;
pub mod local;

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;

use clap::ArgMatches;
use podssh_ssh::Log;
use tokio::runtime::Runtime;

use crate::cp::operand::{self, Operand, Remote};
use crate::cp::{digest, resume, transfer};
use crate::exitmap::Fault;
use crate::pager::Tty;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved};
use editor::Editor;
use local::Local;

/// `edit`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EditArgs {
    /// `[user@]host:path`, as typed.
    pub file: Option<String>,
    /// The connection flags, read as `ssh` reads them: `edit`'s rows share
    /// their ids. The destination comes from the file's operand.
    pub ssh: SshArgs,
    /// `(flag as written, what to use instead, why)`, as each verb carries
    /// them, so that a `Refused` row added later refuses.
    pub refused: Vec<(String, &'static str, &'static str)>,
    /// `--no-terminal` and its `--timeout` (T-510).
    pub no_terminal: bool,
    pub timeout: Option<String>,
}

impl EditArgs {
    /// Read the values out of `edit`'s matches.
    pub fn from_matches(m: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let file = if m.try_contains_id("file").unwrap_or(false) { m.get_one::<String>("file").cloned() } else { None };
        let no_terminal = m.try_get_one::<bool>("no-terminal").ok().flatten().copied().unwrap_or(false);
        let timeout = m.try_get_one::<String>("timeout").ok().flatten().cloned();
        EditArgs { file, ssh: SshArgs::from_matches(m), refused, no_terminal, timeout }
    }
}

/// How the editor runs, from the command line and the terminal: with no
/// `--no-terminal`, on the terminal and with no limit, as a person decides,
/// so `--timeout` goes with `--no-terminal` alone; with it, a bound that is
/// required with no terminal, `PODSSH_TIMEOUT` its default, as `cp`'s.
pub fn how_of(args: &EditArgs, tty: Tty, var: impl Fn(&str) -> Option<String>) -> Result<editor::How, (Fault, String)> {
    let terminal = tty.stdin && tty.stdout;
    if !args.no_terminal {
        if args.timeout.is_some() {
            let why = "podssh edit: --timeout goes with --no-terminal: on a terminal a person decides how long an \
                       edit takes.\n  Nothing has been attempted.";
            return Err((Fault::Usage, why.to_string()));
        }
        if !terminal {
            let why = "podssh edit: it needs a terminal on stdin and stdout, where the editor runs; \
                       --no-terminal runs an editor that needs none, as EDITOR='sed -i s/a/b/', with --timeout.\n  \
                       Nothing has been attempted.";
            return Err((Fault::Usage, why.to_string()));
        }
        return Ok(editor::How { terminal: true, limit: None });
    }
    let attachment = crate::non_interactive::resolve(tty.stdin, tty.stdout, false);
    match crate::non_interactive::require_timeout_or_env("edit", attachment, args.timeout.as_deref(), var) {
        Ok(limit) => Ok(editor::How { terminal: false, limit }),
        Err(refusal) => Err((refusal.fault, refusal.message)),
    }
}

/// The far file that the operand names: a server, and a path that names a
/// file there.
pub fn far_file(text: Option<&str>) -> Result<Remote, String> {
    let Some(text) = text else { return Err("give the file to edit: [user@]host:path".into()) };
    let remote = match operand::parse(text, cfg!(windows))? {
        Operand::Remote(remote) => remote,
        Operand::Local(_) => {
            return Err(format!("{text} is a path here; podssh edit edits a file of a server: [user@]host:path"))
        }
    };
    let (_, name) = transfer::split_remote(&remote.path);
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!("{text} names no file"));
    }
    Ok(remote)
}

/// Run `podssh edit`; the process exit code.
pub fn run_edit(args: &EditArgs, tty: Tty, err: &mut dyn Write) -> i32 {
    let refuse = |err: &mut dyn Write, fault: Fault, why: &str| {
        let _ = writeln!(err, "podssh edit: {why}.\n  Nothing has been attempted.");
        fault.code()
    };
    let remote = match far_file(args.file.as_deref()) {
        Ok(remote) => remote,
        Err(why) => return refuse(err, Fault::Usage, &why),
    };
    // The editor before the terminal: each refuses before anything is
    // attempted, and so a test of the binary with no terminal reaches both.
    let editor = match editor::choose(&editor::EditorEnv::from_process()) {
        Ok(editor) => editor,
        Err(why) => return refuse(err, Fault::Config, &why),
    };
    // A terminal, or --no-terminal and its bound (T-510).
    let how = match how_of(args, tty, |n| std::env::var(n).ok()) {
        Ok(how) => how,
        Err((fault, message)) => {
            let _ = writeln!(err, "{message}");
            return fault.code();
        }
    };
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("edit", err);
    }
    let mut ssh = args.ssh.clone();
    ssh.destination = Some(remote.destination());
    // A URI's port is the operand's own, over -P (T-139).
    if let Some(port) = remote.port {
        ssh.port = Some(port.to_string());
    }
    let mut resolved = match resolve::resolve_or_refuse(&ssh, &Env::from_process()) {
        Ok(resolved) => resolved,
        Err(refusal) => return refusal.report("edit", err),
    };
    // The second connection meets the first one's host key, and logs in as
    // the first did, with no second question (T-136, T-137); a copy runs
    // nothing that would use the agent (T-036).
    resolved.options.host_key_pin = Some(podssh_ssh::hostkey::Pin::default());
    resolved.options.remembered = Some(podssh_ssh::remember::Remembered::default());
    resolved.options.forward_agent = podssh_ssh::Agent::Off;
    let dirs = podssh_relay::cache::candidate_dirs();
    let local = match Local::make_in(&dirs, &remote.path) {
        Ok(local) => local,
        Err((fault, why)) => return refuse(err, fault, &why),
    };
    let log = Arc::new(Log::new(resolved.options.log_level));
    // No plain line in a pipe: an edit's copies are its own (T-472).
    crate::cp::gauge::init(false, resolved.options.log_level == podssh_ssh::LogLevel::Quiet, false);
    for note in &resolved.notes {
        log.verbose(note);
    }
    for warning in &resolved.warnings {
        log.info(warning);
    }
    // The copies that earlier runs kept, each with a change: said once,
    // and none removed.
    let old = self::local::stale(&dirs, std::time::SystemTime::now(), self::local::STALE);
    if let Some(line) = self::local::stale_line(&old) {
        log.info(&line);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            local.remove();
            log.error(&format!("could not start the async runtime: {e}"));
            return Fault::SessionFault.code();
        }
    };
    let code = edit(&runtime, &remote, &resolved, &local, &editor, how, &log);
    runtime.shutdown_background();
    code
}

/// Fetch, edit, check and send; the exit code. The copy here goes after a
/// success, and after a failure it stays, named, when it holds a change,
/// with the directory to remove once it is merged.
fn edit(
    runtime: &Runtime,
    remote: &Remote,
    resolved: &Resolved,
    local: &Local,
    editor: &Editor,
    how: editor::How,
    log: &Arc<Log>,
) -> i32 {
    let kept = |why: &str| {
        let (file, dir) = (local.file.display(), local.dir.display());
        format!("{why}; your copy stays at {file}; rm -r {dir} once you merged it")
    };
    log.verbose(&format!("{}: the copy here is {}", remote.path, local.file.display()));
    let (target, record) = match until_interrupted(runtime, Box::pin(far::fetch(resolved, remote, &local.file, log))) {
        Some(Ok(fetched)) => fetched,
        Some(Err(failed)) => {
            forget_partial();
            local.remove();
            log.error(&far::in_edit_words(&failed.message));
            return failed.fault.code();
        }
        None => {
            forget_partial();
            local.remove();
            log.error("interrupted while the file came; nothing was changed");
            return 130;
        }
    };
    if let Err(e) = local::private_file(&local.file) {
        local.remove();
        log.error(&format!("{}: {e}", local.file.display()));
        return Fault::CantCreate.code();
    }
    log.verbose(&format!("the editor: {} (from {})", editor.shown(), editor.from));
    let ended = match editor::run(runtime, editor, &local.file, how) {
        Ok(ended) => ended,
        Err(e) => {
            local.remove();
            log.error(&format!("{} names {}, which did not start: {e}; nothing was sent", editor.from, editor.shown()));
            return Fault::Config.code();
        }
    };
    let changed = match digest::of_file(&local.file) {
        Ok(sum) => sum != record.sum,
        Err(e) => {
            log.error(&format!("{}: {e}; nothing was sent, and {} stays", local.file.display(), local.dir.display()));
            return Fault::NoInput.code();
        }
    };
    // The editor that podssh ended: its bound passed, or a signal came with
    // no terminal (T-510). Nothing is sent of a copy that it may have left
    // half written.
    let status = match ended {
        editor::Ended::Status(status) => status,
        stopped => {
            let (code, why) = match stopped {
                editor::Ended::TimedOut(limit) => (
                    Fault::TimedOut.code(),
                    format!("the --timeout of {} s passed while the editor ran", limit.as_secs()),
                ),
                _ => (130, "interrupted while the editor ran".to_string()),
            };
            if changed {
                log.error(&kept(&format!("{why}, so nothing was sent")));
            } else {
                local.remove();
                log.error(&format!("{why}; nothing was changed"));
            }
            return code;
        }
    };
    if !status.success() {
        let code = editor::code_of(status);
        // The editor's status is the editor's, no failure of podssh (T-195).
        crate::error_program::not_a_failure();
        if changed {
            log.error(&kept(&format!("the editor ended with {code}, so nothing was sent")));
        } else {
            local.remove();
            log.error(&format!("the editor ended with {code}; nothing was changed"));
        }
        return code;
    }
    if !changed {
        local.remove();
        log.info(&format!("{}: no change, so nothing was sent", target.path));
        return 0;
    }
    match until_interrupted(runtime, Box::pin(far::send(resolved, &target, &local.file, &record, log))) {
        Some(Ok(done)) => {
            let sum = done.sum.as_ref().map(digest::hex).unwrap_or_default();
            log.verbose(&format!("{}: {} bytes sent, SHA-256 {sum}", done.destination, done.bytes));
            local.remove();
            0
        }
        Some(Err(failed)) => {
            log.error(&kept(&format!("{}{}", far::in_edit_words(&failed.message), partial())));
            failed.fault.code()
        }
        None => {
            log.error(&kept(&format!("interrupted while the file went{}", partial())));
            130
        }
    }
}

/// Run `work` until it ends, or until the first SIGINT or SIGTERM (Ctrl-C
/// on Windows): `None` then. The future is on the heap, as `cp`'s is: a
/// copy's future is large, and Windows gives the main thread 1 MiB of
/// stack.
fn until_interrupted<T>(runtime: &Runtime, work: Pin<Box<dyn Future<Output = T> + '_>>) -> Option<T> {
    runtime.block_on(async {
        tokio::select! {
            done = work => Some(done),
            () = crate::cp::interrupted() => None,
        }
    })
}

/// The far side's partial copy that a send left, for the message: the
/// server keeps it under its temporary name.
fn partial() -> String {
    match resume::current() {
        Some((temp, _)) => format!("; the partial copy on the server is {temp}"),
        None => String::new(),
    }
}

/// The record of a fetch that ended before its end: its temporary file goes
/// with the private directory, so the record names nothing.
fn forget_partial() {
    if let Some((_, side)) = resume::current() {
        let _ = std::fs::remove_file(side);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operand_is_one_file_of_a_server() {
        let far = far_file(Some("u@host:dir/notes.txt")).expect("a far file");
        assert_eq!((far.user.as_deref(), far.host.as_str(), far.path.as_str()), (Some("u"), "host", "dir/notes.txt"));
        assert_eq!(far_file(Some("scp://host:2222/notes.txt")).expect("a URI").port, Some(2222));
        for (text, says) in [
            (None, "give the file to edit"),
            (Some("notes.txt"), "is a path here"),
            (Some("./a:b"), "is a path here"),
            (Some("host:"), "names no file"),
            (Some("host:dir/"), "names no file"),
            (Some("host:.."), "names no file"),
            (Some("@host:f"), "empty user"),
        ] {
            let why = far_file(text).expect_err("a refusal");
            assert!(why.contains(says), "{text:?}: {why}");
        }
    }

    /// `--no-terminal` (T-510): a bound required with no terminal, the
    /// flag's or `PODSSH_TIMEOUT`'s; on a terminal none, and `--timeout`
    /// without the flag refused; no terminal without the flag refused by
    /// its name.
    #[test]
    fn no_terminal_takes_a_bound_and_a_terminal_takes_none() {
        let args = |no_terminal, timeout: Option<&str>| EditArgs {
            no_terminal,
            timeout: timeout.map(str::to_string),
            ..EditArgs::default()
        };
        let (pipe, terminal) = (Tty { stdin: false, stdout: false }, Tty { stdin: true, stdout: true });
        let none = |_: &str| None;
        let thirty = |name: &str| (name == "PODSSH_TIMEOUT").then(|| "30s".to_string());
        let secs = |s| Some(std::time::Duration::from_secs(s));
        assert_eq!(how_of(&args(false, None), terminal, thirty), Ok(editor::How { terminal: true, limit: None }));
        let (fault, why) = how_of(&args(false, None), pipe, none).unwrap_err();
        assert!(fault == Fault::Usage && why.contains("--no-terminal"), "{why}");
        let (fault, why) = how_of(&args(false, Some("5s")), terminal, none).unwrap_err();
        assert!(fault == Fault::Usage && why.contains("goes with --no-terminal"), "{why}");
        assert_eq!(how_of(&args(true, Some("5s")), pipe, none), Ok(editor::How { terminal: false, limit: secs(5) }));
        assert_eq!(how_of(&args(true, None), pipe, thirty), Ok(editor::How { terminal: false, limit: secs(30) }));
        assert_eq!(how_of(&args(true, None), terminal, none), Ok(editor::How { terminal: false, limit: None }));
        let (fault, why) = how_of(&args(true, None), pipe, none).unwrap_err();
        assert!(fault == Fault::Usage && why.contains("--timeout DURATION is required"), "{why}");
    }
}
