//! `podssh session start` (T-186): `serve` in the background, as a child of
//! this binary that leaves this process's session (setsid; on Windows a
//! process with no console), and its stdout and stderr once it is ready
//! (`--detach`). Before the child starts, `start` makes the refusals of
//! `serve` itself (64, 78), and refuses a name that runs already (69). Then
//! it passes on what the child says on stderr until its line of ready, and
//! exits 0 with the socket's path on stdout; or with the child's own code,
//! when the child ended first: 77 for a bind that the host refuses, 255 for
//! a connection or a login that failed. When the child is not ready within
//! `--timeout`, it is stopped, and `start` exits 75.

use std::io::Write;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::process::ChildStderr;

use super::{place, wire, SessionArgs};
use crate::exitmap::sysexits::{EX_SOFTWARE, EX_TEMPFAIL, EX_UNAVAILABLE};

/// Run `podssh session start`; the exit code.
pub fn run(args: &SessionArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Err(refusal) = super::daemon::plan(args) {
        return refusal.report("session", err);
    }
    let timeout = match args.timeout.as_deref().map(|t| super::duration("--timeout", t)).transpose() {
        Ok(timeout) => timeout.unwrap_or(super::DEFAULT_TIMEOUT),
        Err(why) => return crate::relay_settings::Refusal::usage(why).report("session", err),
    };
    let Some(runtime) = super::runtime(err) else { return super::NO_RUNTIME };
    let code = runtime.block_on(start(args, timeout, out, err));
    // The child runs on; a read of its pipes may still wait.
    runtime.shutdown_background();
    code
}

async fn start(args: &SessionArgs, timeout: Duration, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let name = args.name();
    if let Some(path) = place::find(name, args.socket.as_deref()) {
        if let Ok(fields) = super::client::ask(&path, &wire::request(name, &wire::Op::Info), ASK_WAIT).await {
            let state = fields.get("state").and_then(|s| s.as_str()).unwrap_or("running");
            let _ = writeln!(err, "podssh session: {name} is there already ({state}), at {path}: stop it first");
            return EX_UNAVAILABLE;
        }
    }
    // Each way to start this binary again, `/proc/self/exe` first (T-380).
    let mut tried = Vec::new();
    let mut started = None;
    for binary in crate::detach::binaries() {
        let mut cmd = tokio::process::Command::new(&binary);
        // The child's first word (T-380): it releases each descriptor that it
        // inherited, as a caller's pipe that it kept would never end. The
        // words after start's own: the subcommand came first (`check`).
        cmd.arg(crate::detach::CHILD_FLAG).args(["session", "serve", "--detach"]).args(args.argv.iter().skip(1));
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        detach_child(&mut cmd);
        keep_own_handles();
        match spawn(&mut cmd, err) {
            Ok(child) => {
                started = Some(child);
                break;
            }
            Err(e) => tried.push(format!("{}: {e}", binary.display())),
        }
    }
    let Some(mut child) = started else {
        let _ = writeln!(err, "podssh session: the session's podssh did not start: {}", tried.join("; "));
        return EX_SOFTWARE;
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.start_kill();
        return EX_SOFTWARE;
    };
    let mut lines = BufReader::new(stdout).lines();
    let mut said = BufReader::new(stderr).lines();
    let mut said_open = true;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(line)) => {
                    let Some(socket) = wire::ready_socket(&line) else { continue };
                    // What the child said before it was ready, then where it is.
                    pass_on(&mut said, err, Duration::from_millis(300)).await;
                    let _ = writeln!(out, "{socket}");
                    return 0;
                }
                // The child ended before it was ready: what it said, and its code.
                Ok(None) | Err(_) => {
                    pass_on(&mut said, err, Duration::from_secs(5)).await;
                    return match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                        Ok(Ok(status)) => status.code().unwrap_or(podssh_ssh::EXIT_FAILURE),
                        _ => podssh_ssh::EXIT_FAILURE,
                    };
                }
            },
            line = said.next_line(), if said_open => match line {
                Ok(Some(line)) => {
                    let _ = writeln!(err, "{line}");
                }
                _ => said_open = false,
            },
            () = tokio::time::sleep_until(deadline) => {
                let _ = child.start_kill();
                let _ = writeln!(
                    err,
                    "podssh session: the session was not ready within {} s, and is stopped",
                    timeout.as_secs_f32()
                );
                return EX_TEMPFAIL;
            }
        }
    }
}

/// How long `start` waits for a session that may be there already.
const ASK_WAIT: Duration = Duration::from_secs(5);

/// Copy the child's lines to `err`, until its stderr ends or `limit`.
async fn pass_on(said: &mut Lines<BufReader<ChildStderr>>, err: &mut dyn Write, limit: Duration) {
    let copy = async {
        while let Ok(Some(line)) = said.next_line().await {
            let _ = writeln!(err, "{line}");
        }
    };
    let _ = tokio::time::timeout(limit, copy).await;
}

/// The child stays in this process's session until it is ready (T-382):
/// a password, a passphrase or a host key is asked on this terminal, as
/// `podssh ssh` asks them, and Ctrl-C before ready reaches it too. It leaves
/// the session at ready ([`leave_terminal`]), so the terminal's hangup and
/// its signals then reach it no more.
#[cfg(unix)]
fn detach_child(_: &mut tokio::process::Command) {}

/// The same on Windows (T-383): the child shares this console until it is
/// ready, and frees it then. It leaves the caller's job, as a job of
/// Win32-OpenSSH's session that ends would end it; with no console window
/// here, it gets none either, as Windows would open one.
#[cfg(windows)]
fn detach_child(cmd: &mut tokio::process::Command) {
    use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;
    cmd.creation_flags(CREATE_BREAKAWAY_FROM_JOB | podssh_ssh::terminal::child_console_flags());
}

#[cfg(not(any(unix, windows)))]
fn detach_child(_: &mut tokio::process::Command) {}

/// Start the child. A job of Windows that allows no breakaway refuses it
/// with `ERROR_ACCESS_DENIED`: the child starts again in the job, and the
/// user is told that the session ends with that job.
fn spawn(cmd: &mut tokio::process::Command, err: &mut dyn Write) -> std::io::Result<tokio::process::Child> {
    #[cfg(not(windows))]
    let _ = err;
    match cmd.spawn() {
        #[cfg(windows)]
        Err(e) if e.raw_os_error() == Some(5) => {
            cmd.creation_flags(podssh_ssh::terminal::child_console_flags());
            let child = cmd.spawn()?;
            let _ = writeln!(
                err,
                "podssh session: the caller's job of Windows allows no process to leave it: the session ends with \
                 that job"
            );
            Ok(child)
        }
        other => other,
    }
}

/// This process's own standard handles stay out of the child: a program
/// that reads them to their end, as an agent reads a command's, would wait
/// for the daemon too. Windows hands each handle that may be inherited to
/// a child; on Unix the child's 0, 1 and 2 are its own, and the child closes
/// each other descriptor at its start, as podssh's own close on exec but one
/// that podssh inherited does not (T-380).
#[cfg(windows)]
fn keep_own_handles() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    let (stdin, stdout, stderr) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
    for handle in [stdin.as_raw_handle(), stdout.as_raw_handle(), stderr.as_raw_handle()] {
        // SAFETY: a standard handle of this process, or none; the call
        // changes only whether a child inherits it.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    }
}

#[cfg(not(windows))]
fn keep_own_handles() {}

/// Just before its line of ready, a daemon that `start` runs leaves the
/// starter's session and terminal (T-382): `setsid`, and SIGHUP ignored, as
/// a session's leader that a terminal would still reach. Before the line,
/// so that no signal of the terminal reaches it once `start` has gone.
#[cfg(unix)]
pub(super) fn leave_terminal() {
    // SAFETY: setsid has no precondition (a group's leader, which this
    // child is not, would only see it fail); the action of one signal.
    unsafe {
        libc::setsid();
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
}

/// On Windows it frees the console that it shared (T-383): the console's
/// Ctrl-C and its close reach it no more.
#[cfg(windows)]
pub(super) fn leave_terminal() {
    // SAFETY: FreeConsole only detaches this process from its console.
    unsafe { windows_sys::Win32::System::Console::FreeConsole() };
}

#[cfg(not(any(unix, windows)))]
pub(super) fn leave_terminal() {}

/// After its line of ready, a daemon that `start` runs writes nothing more
/// on stdout and stderr: `start` has gone, and a program that reads them to
/// their end would wait for the daemon. Both go to the null device.
#[cfg(unix)]
pub(super) fn leave() {
    use std::os::fd::AsRawFd;
    let Ok(null) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null") else { return };
    for fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: dup2 of an open file onto a standard descriptor of this
        // process; a failure leaves that descriptor as it was.
        unsafe { libc::dup2(null.as_raw_fd(), fd) };
    }
}

#[cfg(windows)]
pub(super) fn leave() {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
    for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let Ok(null) = std::fs::OpenOptions::new().write(true).open("NUL") else { continue };
        // SAFETY: the handle of NUL, open for the process's life as its
        // standard handle; the standard library writes through the handle of
        // the moment. The pipe's handle stays open, and nothing writes to it.
        unsafe { SetStdHandle(which, null.into_raw_handle()) };
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn leave() {}

/// The daemon reads no stdin: its input comes from `send`. Stdin goes to
/// the null device first, so that a `serve` started on a terminal does not
/// take that terminal for its session's: no raw mode, no escape, no ZMODEM.
#[cfg(unix)]
pub(super) fn no_stdin() {
    use std::os::fd::AsRawFd;
    let Ok(null) = std::fs::File::open("/dev/null") else { return };
    // SAFETY: dup2 of an open file onto this process's stdin; a failure
    // leaves stdin as it was.
    unsafe { libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO) };
}

#[cfg(windows)]
pub(super) fn no_stdin() {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_INPUT_HANDLE};
    let Ok(null) = std::fs::File::open("NUL") else { return };
    // SAFETY: the handle of NUL, open for the process's life as its stdin.
    unsafe { SetStdHandle(STD_INPUT_HANDLE, null.into_raw_handle()) };
}

#[cfg(not(any(unix, windows)))]
pub(super) fn no_stdin() {}
