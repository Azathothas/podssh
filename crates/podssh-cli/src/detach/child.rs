//! The detached child's own steps: at its start, each inherited descriptor
//! released and its signals reset; at ready, the caller's terminal and
//! streams left, then the line of ready to the parent. And how the parent
//! starts it: its name, and on Windows its group and its job.

use std::ffi::OsString;
use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use super::log::log_file;

static SENT: AtomicBool = AtomicBool::new(false);

/// At the start of the process, before any thread: when `args` begin with
/// the child's flag, each descriptor from 3 up is closed, as a caller's
/// pipe that the child kept would never see its end, and the signal mask
/// and the actions of INT, TERM and QUIT are reset, as a child inherits
/// them. Elsewhere nothing.
pub fn prepare_process(args: &[OsString]) {
    if args.first().is_some_and(|a| a == super::CHILD_FLAG || a == super::supervise::SUPERVISE_FLAG) {
        #[cfg(unix)]
        unix::prepare();
    }
}

/// The run is ready: in a detached child, once. Stdin goes to the null
/// device and stdout and stderr to the log; the child leaves the caller's
/// session and terminal (Unix: `setsid()`, SIGHUP ignored; Windows: its
/// console freed); then the line of ready goes to the parent. A parent that
/// is gone (the user stopped it before ready) ends the child too.
pub fn ready(verb: &str) {
    if !super::is_child() || SENT.swap(true, Ordering::SeqCst) {
        return;
    }
    let log = log_file(verb);
    let path = log.as_ref().map(|(path, _)| path.clone());
    let shown = path.as_ref().map_or_else(|| "none".to_string(), |p| p.display().to_string());
    if let Some(path) = &path {
        super::lock::logged(path);
    }
    let supervised = std::env::var_os(super::lock::SUPERVISOR_VARIABLE).is_some();
    // The caller's working directory, left unless the run needs it (T-397);
    // a supervisor learns it from the line.
    let leaves = super::run_words().is_some_and(|words| super::cwd::leaves(words));
    let left = if leaves && supervised { super::cwd::LEFT } else { "" };
    // The log last: a reader takes the rest of the line for its path.
    let named = super::lock::name().map_or_else(String::new, |name| format!(", named {name}"));
    let line = format!("{} pid {}{named}{left}, its log {shown}\n", super::READY, std::process::id());
    let file = log.map(|(_, file)| file);
    if !leave(file.as_ref(), line.as_bytes()) {
        std::process::exit(crate::exitmap::sysexits::EX_TEMPFAIL);
    }
    // A run of a supervisor writes the supervisor's log, which the
    // supervisor alone cuts (T-397).
    if let (Some(path), Some(file)) = (path, file) {
        super::log::keep(path, file, !supervised);
    }
    if leaves {
        super::cwd::to_root();
    }
    // Out of the login session's scope, beside the run (T-381): with its
    // supervisor when it has one, whose runs then start there.
    #[cfg(target_os = "linux")]
    {
        let mut pids = vec![std::process::id()];
        if supervised {
            pids.push(std::os::unix::process::parent_id());
        }
        let _ = std::thread::Builder::new().name("detach-scope".into()).spawn(move || {
            if let Some(line) = super::scope::leave_session(&pids) {
                let _ = writeln!(std::io::stderr(), "podssh: {line}");
            }
        });
    }
}

/// The step of ready: the caller's terminal and streams left (stdin to the
/// null device, stdout and stderr to `log`), then `line` to the parent on
/// the pipe that was stdout. Whether the line went.
pub(super) fn leave(log: Option<&std::fs::File>, line: &[u8]) -> bool {
    // What the run wrote on stdout before ready goes to the parent first.
    let _ = std::io::stdout().flush();
    #[cfg(unix)]
    let said = unix::leave(log, line);
    #[cfg(windows)]
    let said = windows::leave(log, line);
    #[cfg(not(any(unix, windows)))]
    let said = std::io::stdout().write_all(line).is_ok();
    said
}

/// The child's name in a list of processes: the name that started podssh,
/// not `/proc/self/exe`.
pub fn name_it(cmd: &mut Command) {
    #[cfg(unix)]
    if let Some(first) = std::env::args_os().next() {
        use std::os::unix::process::CommandExt;
        cmd.arg0(first);
    }
    #[cfg(not(unix))]
    let _ = cmd;
}

/// This process's own standard handles stay out of a child that outlives
/// it: a program that reads them to their end, as an agent or a CI's step
/// reads a command's, would wait for the child too. Windows hands each
/// handle that may be inherited to a child, besides the standard handles
/// that the child is given, which the child closes at ready; on Unix the
/// child's 0, 1 and 2 are its own, and the child closes each other
/// descriptor at its start (T-380).
#[cfg(windows)]
pub fn keep_own_handles() {
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
pub fn keep_own_handles() {}

/// Start the child. On Windows out of the caller's job where the job allows
/// it; where it does not, again in the job, said by `note`, as the run then
/// ends with the job. It shares the caller's console until ready, so that
/// Ctrl-C before ready reaches it too, and a prompt it asks gets an answer;
/// it frees the console before its line of ready (T-383). With no console
/// window here, it gets none either, as Windows would open one.
pub fn spawn(cmd: &mut Command, note: &mut dyn FnMut(&str)) -> std::io::Result<std::process::Child> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;
        let console = podssh_ssh::terminal::child_console_flags();
        cmd.creation_flags(CREATE_BREAKAWAY_FROM_JOB | console);
        match cmd.spawn() {
            // ERROR_ACCESS_DENIED: the job allows no breakaway.
            Err(e) if e.raw_os_error() == Some(5) => {
                cmd.creation_flags(console);
                let child = cmd.spawn()?;
                note("the caller's job of Windows allows no process to leave it: the run ends with that job");
                Ok(child)
            }
            other => other,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = note;
        cmd.spawn()
    }
}

#[cfg(unix)]
mod unix {
    use std::os::fd::AsRawFd;

    /// Each descriptor from 3 up closed: `close_range` where Linux has it,
    /// else each of `/proc/self/fd` or `/dev/fd`, else each up to the limit.
    pub(super) fn prepare() {
        if !close_range() {
            close_listed();
        }
        // Started through /proc/self/exe, the process's name would be
        // "exe"; `pgrep podssh` finds it by this one.
        #[cfg(target_os = "linux")]
        // SAFETY: a name of 6 bytes and its NUL, for this thread's process.
        unsafe {
            libc::prctl(libc::PR_SET_NAME, c"podssh".as_ptr());
        }
        // SAFETY: an empty set, and the default action of three signals; no
        // thread runs yet.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT] {
                libc::signal(signal, libc::SIG_DFL);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn close_range() -> bool {
        // SAFETY: the system call closes descriptors of this process alone.
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) == 0 }
    }

    #[cfg(not(target_os = "linux"))]
    fn close_range() -> bool {
        false
    }

    fn close_listed() {
        let listed = ["/proc/self/fd", "/dev/fd"].iter().find_map(|dir| {
            let fds: Vec<i32> =
                std::fs::read_dir(dir).ok()?.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect();
            Some(fds)
        });
        let fds = listed.unwrap_or_else(|| {
            // SAFETY: a read of this process's limit.
            let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
            let max = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
                limit.rlim_cur.min(65_536) as i32
            } else {
                1024
            };
            (3..max).collect()
        });
        for fd in fds.into_iter().filter(|fd| *fd >= 3) {
            // SAFETY: a descriptor of this process, which nothing uses yet; the
            // one of the listing is closed already, and closing it again fails.
            unsafe { libc::close(fd) };
        }
    }

    /// Stdin to the null device, stderr to the log; `setsid()` and SIGHUP
    /// ignored; the line to the parent; stdout to the log. A sandbox may
    /// have no `/dev/null` (T-397), which ended a run that had logged in:
    /// stdin is then a pipe whose writer is closed, which reads as its end,
    /// and with no log either, the outputs a pipe whose reader is closed,
    /// whose writes fail and are dropped. Whether the line went.
    pub(super) fn leave(log: Option<&std::fs::File>, line: &[u8]) -> bool {
        let null = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null").ok();
        let empty = if null.is_none() { pipe().map(|(read, _closed)| read) } else { None };
        let deaf = if null.is_none() && log.is_none() { pipe().map(|(_closed, write)| write) } else { None };
        let input = null.as_ref().map(|f| f.as_raw_fd()).or_else(|| empty.as_ref().map(|f| f.as_raw_fd()));
        let sink = log
            .map(|f| f.as_raw_fd())
            .or_else(|| null.as_ref().map(|f| f.as_raw_fd()))
            .or_else(|| deaf.as_ref().map(|f| f.as_raw_fd()));
        let (Some(input), Some(sink)) = (input, sink) else { return false };
        // SAFETY: dup2 of open files onto this process's standard
        // descriptors; setsid has no precondition, and a group's leader,
        // which a child is not, would only see it fail; SIGHUP's action.
        unsafe {
            libc::dup2(input, libc::STDIN_FILENO);
            libc::dup2(sink, libc::STDERR_FILENO);
            libc::setsid();
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }
        let said = write_all(libc::STDOUT_FILENO, line);
        // SAFETY: as above.
        unsafe { libc::dup2(sink, libc::STDOUT_FILENO) };
        said
    }

    /// A pipe: its reading end and its writing end.
    fn pipe() -> Option<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
        use std::os::fd::{FromRawFd, OwnedFd};
        let mut fds = [0; 2];
        // SAFETY: pipe() fills two descriptors that this process then owns.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: each is open, and owned by nothing else.
        Some(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    fn write_all(fd: i32, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            // SAFETY: a write of a live slice to a descriptor of this process.
            let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if n <= 0 {
                return false;
            }
            bytes = &bytes[n as usize..];
        }
        true
    }
}

#[cfg(windows)]
mod windows {
    use std::io::Write;
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Console::{
        FreeConsole, GetStdHandle, SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    /// The standard handle `which` as it is now: the caller's, before ready.
    fn standard(which: u32) -> Option<HANDLE> {
        // SAFETY: GetStdHandle has no precondition.
        let handle = unsafe { GetStdHandle(which) };
        (!handle.is_null() && handle != INVALID_HANDLE_VALUE).then_some(handle)
    }

    /// Stdin to NUL and stderr to the log; the console freed; the line to
    /// the parent; stdout to the log. Then each handle that it replaced is
    /// closed: SetStdHandle closes none, and the caller's pipe, which the
    /// child was given, would stay open as long as the child lives, so that
    /// a caller that reads it to its end would wait for the child.
    pub(super) fn leave(log: Option<&std::fs::File>, line: &[u8]) -> bool {
        let given = [STD_INPUT_HANDLE, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE].map(standard);
        let sink = || -> Option<std::fs::File> {
            match log {
                Some(file) => file.try_clone().ok(),
                None => std::fs::OpenOptions::new().write(true).open("NUL").ok(),
            }
        };
        // SAFETY: handles of open files, kept open for the process's life as
        // its standard handles; FreeConsole only detaches this process.
        unsafe {
            if let Ok(null) = std::fs::File::open("NUL") {
                SetStdHandle(STD_INPUT_HANDLE, null.into_raw_handle());
            }
            if let Some(file) = sink() {
                SetStdHandle(STD_ERROR_HANDLE, file.into_raw_handle());
            }
            FreeConsole();
        }
        let mut out = std::io::stdout();
        let said = out.write_all(line).and_then(|()| out.flush()).is_ok();
        // SAFETY: as above.
        unsafe {
            if let Some(file) = sink() {
                SetStdHandle(STD_OUTPUT_HANDLE, file.into_raw_handle());
            }
        }
        for (handle, which) in given.into_iter().zip([STD_INPUT_HANDLE, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE]) {
            // Only a handle that is no longer the standard one: where a
            // replacement failed, the old one is still in use.
            if let Some(handle) = handle.filter(|h| standard(which) != Some(*h)) {
                // SAFETY: a handle that this process was given and no longer
                // names as a standard handle; nothing else of podssh holds it.
                unsafe { CloseHandle(handle) };
            }
        }
        said
    }
}
