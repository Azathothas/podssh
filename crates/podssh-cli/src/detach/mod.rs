//! `--detach` (T-380, `docs/detach.md`): a run sent into the background by
//! podssh itself, where `&` and `nohup` fail. The parent starts this binary
//! again with [`CHILD_FLAG`] first, its stdout a pipe back, its stdin and
//! stderr the caller's, and waits. The child runs the command as in the
//! foreground, its prompts on the caller's terminal, until it is ready; then
//! it leaves the terminal and the caller's streams ([`ready`]) and says so on
//! the pipe, and the parent exits 0. A child that ends first gives the parent
//! its code, its lines already on the caller's stderr.
//!
//! This binary started again is no helper: the rule against helpers is about
//! podssh's own shims (Q22), and `podssh session start` does the same (T-186).
//! A fork once the runtime runs is unsafe, and Windows has none.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

mod child;
mod hazards;

pub use child::{prepare_process, ready};

/// The first word of a detached child's command line, which podssh alone
/// writes: the child is the run that the user typed, after it.
pub const CHILD_FLAG: &str = "--detach-child";
/// The line of a child that is ready, on its stdout, the pipe to its parent.
const READY: &str = "podssh-detached ready";

static CHILD: AtomicBool = AtomicBool::new(false);
static ARGS: OnceLock<Vec<OsString>> = OnceLock::new();

/// Whether this process is a detached child, before its ready or after it.
pub fn is_child() -> bool {
    CHILD.load(Ordering::SeqCst)
}

/// `args` without [`CHILD_FLAG`], which makes this process a child; the
/// words are kept, to start the run again.
pub fn take_child_flag(args: Vec<OsString>) -> Vec<OsString> {
    let (child, args) = split_child_flag(args);
    if child {
        CHILD.store(true, Ordering::SeqCst);
    }
    let _ = ARGS.set(args.clone());
    args
}

/// Whether `args` begin with [`CHILD_FLAG`], and the words after it.
fn split_child_flag(mut args: Vec<OsString>) -> (bool, Vec<OsString>) {
    let child = args.first().is_some_and(|a| a == CHILD_FLAG);
    if child {
        args.remove(0);
    }
    (child, args)
}

/// In a detached child of `podssh ssh`: ready once the run's request went
/// (`Phase::Requested`: after the login, `-L` and `-D` bound before it).
pub fn when_requested(verb: &'static str) {
    if !is_child() {
        return;
    }
    let _ = std::thread::Builder::new().name("detach-ready".into()).spawn(move || loop {
        if podssh_ssh::retry::phase() >= podssh_ssh::retry::Phase::Requested {
            ready(verb);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    });
}

/// In a detached child of `podssh node`: ready at its line `online`.
pub fn on_line(verb: &str, line: &str) {
    if line.starts_with("online") {
        ready(verb);
    }
}

/// The ways to start this binary again: `/proc/self/exe`, which runs this
/// image even when `podssh update` replaced its file; the path that the
/// system gives; the name that started it, when it holds a directory.
pub(crate) fn binaries() -> Vec<PathBuf> {
    let mut out = Vec::new();
    #[cfg(target_os = "linux")]
    if std::path::Path::new("/proc/self/exe").exists() {
        out.push(PathBuf::from("/proc/self/exe"));
    }
    if let Ok(path) = std::env::current_exe() {
        if path.exists() && !out.contains(&path) {
            out.push(path);
        }
    }
    if let Some(first) = std::env::args_os().next().map(PathBuf::from) {
        if first.components().count() > 1 && first.exists() && !out.contains(&first) {
            out.push(first);
        }
    }
    out
}

/// Send the run of `verb` into the background: the parent's whole part.
/// Its code: 0 once the child is ready; the child's own when it ended
/// first; 69 where a detached run cannot outlive this one; 70 when this
/// binary cannot start itself.
pub fn start(verb: &str, err: &mut dyn Write) -> i32 {
    if let Some(why) = hazards::refusal() {
        let _ = writeln!(err, "podssh {verb}: --detach: {why}");
        return crate::exitmap::sysexits::EX_UNAVAILABLE;
    }
    for line in hazards::lines() {
        let _ = writeln!(err, "podssh {verb}: --detach: note: {line}");
    }
    let Some(args) = ARGS.get() else {
        let _ = writeln!(err, "podssh {verb}: --detach: the words of this run were not kept");
        return crate::exit_codes::EXIT_NOT_IMPLEMENTED;
    };
    let mut tried = Vec::new();
    for program in binaries() {
        let mut cmd = Command::new(&program);
        child::name_it(&mut cmd);
        cmd.arg(CHILD_FLAG).args(args);
        cmd.stdin(Stdio::inherit()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        match child::spawn(&mut cmd, &mut |line| {
            let _ = writeln!(err, "podssh {verb}: --detach: note: {line}");
        }) {
            Ok(started) => return wait_ready(started, verb, err),
            Err(e) => tried.push(format!("{}: {e}", program.display())),
        }
    }
    if tried.is_empty() {
        tried.push("no path of this program was found".to_string());
    }
    let _ = writeln!(err, "podssh {verb}: --detach: this program could not start itself again: {}", tried.join("; "));
    crate::exit_codes::EXIT_NOT_IMPLEMENTED
}

/// The parent's wait: the child's line of ready, or its end. A line before
/// it goes to this process's stdout, as the child wrote it.
fn wait_ready(mut started: std::process::Child, verb: &str, err: &mut dyn Write) -> i32 {
    if let Some(stdout) = started.stdout.take() {
        let mut out = std::io::stdout();
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Some(rest) = line.strip_prefix(READY) {
                let _ = writeln!(err, "podssh {verb}: in the background,{rest}");
                return 0;
            }
            let _ = writeln!(out, "{line}");
        }
    }
    match started.wait() {
        Ok(status) => code_of(status),
        Err(e) => {
            let _ = writeln!(err, "podssh {verb}: --detach: the background run: {e}");
            crate::exitmap::sysexits::EX_SOFTWARE
        }
    }
}

/// A child's code; 128 and its signal when a signal ended it, as a shell
/// says it.
fn code_of(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    podssh_ssh::EXIT_FAILURE
}

#[cfg(test)]
mod tests;
