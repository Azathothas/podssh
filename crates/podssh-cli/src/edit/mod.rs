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
//! copy that holds a change stays and is named; a copy with no change goes.
//!
//! **Exit codes are the sysexits of `cp`**: 64 a usage error or no terminal;
//! 78 no editor, an editor that does not start, or `PODSSH_CACHE_DIR` set to
//! none; 73 the far file changed, or no cache directory takes the copy; the
//! status of an editor that failed; 130 an interruption while a file moves;
//! else the code of the copy that failed.

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
}

impl EditArgs {
    /// Read the values out of `edit`'s matches.
    pub fn from_matches(m: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let file = if m.try_contains_id("file").unwrap_or(false) { m.get_one::<String>("file").cloned() } else { None };
        EditArgs { file, ssh: SshArgs::from_matches(m), refused }
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
    if !(tty.stdin && tty.stdout) {
        return refuse(err, Fault::Usage, "it needs a terminal on stdin and stdout, where the editor runs");
    }
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
    let local = match Local::make(&remote.path) {
        Ok(local) => local,
        Err((fault, why)) => return refuse(err, fault, &why),
    };
    let log = Arc::new(Log::new(resolved.options.log_level));
    crate::cp::gauge::init(false, resolved.options.log_level == podssh_ssh::LogLevel::Quiet);
    for note in &resolved.notes {
        log.verbose(note);
    }
    for warning in &resolved.warnings {
        log.info(warning);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            local.remove();
            log.error(&format!("could not start the async runtime: {e}"));
            return Fault::SessionFault.code();
        }
    };
    let code = edit(&runtime, &remote, &resolved, &local, &editor, &log);
    runtime.shutdown_background();
    code
}

/// Fetch, edit, check and send; the exit code. The copy here goes after a
/// success, and after a failure it stays, named, when it holds a change.
fn edit(
    runtime: &Runtime,
    remote: &Remote,
    resolved: &Resolved,
    local: &Local,
    editor: &Editor,
    log: &Arc<Log>,
) -> i32 {
    let kept = |why: &str| format!("{why}; your copy stays at {}", local.file.display());
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
    let status = match editor::run(runtime, editor, &local.file) {
        Ok(status) => status,
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
    if !status.success() {
        let code = editor::code_of(status);
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
}
