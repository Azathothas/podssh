//! `--detach --restart` (T-390): a small process in the background that
//! starts the detached run again whenever it ends, so that a crash, an
//! abort or a kill of the run does not leave a server that only this tunnel
//! reaches locked out. The parent starts it in the child's place; it starts
//! the child, passes on the child's lines and its ready, then leaves the
//! terminal itself and waits. It holds no runtime and no connection.
//!
//! What it never does: give up (a cap that counts the run's whole life, as
//! d-mon's, ends supervision a week later); kill the run when it dies
//! itself (PDEATHSIG would make the supervisor one more way to lose the
//! tunnel); restart before the first ready (a failure then is the user's to
//! see, with its code, as without `--restart`).

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{binaries, child, code_of, CHILD_FLAG, READY};

/// The first word of a supervisor's command line, which podssh alone
/// writes, in the child's place.
pub const SUPERVISE_FLAG: &str = "--detach-supervise";
/// Where each child of a supervisor writes its log: the supervisor's, so
/// that each restart goes on in one file.
pub const LOG_VARIABLE: &str = "PODSSH_DETACH_LOG";
/// A run that lasted this long starts the count of restarts again.
pub const STEADY: Duration = Duration::from_secs(30);
/// How long a stopped run has for its end before SIGKILL.
#[cfg(unix)]
const STOP_GRACE: Duration = Duration::from_secs(10);
/// How often the supervisor looks at its child and its stop.
const TICK: Duration = Duration::from_millis(200);
/// A run that ends this soon after its start failed to start.
const QUICK: Duration = Duration::from_secs(10);
/// Failed starts in a row after which the binary of before an update, which
/// `podssh update` kept, is started in this one's place (T-396).
const FAILED_STARTS: u32 = 5;

static STOP: AtomicBool = AtomicBool::new(false);

/// The codes after which a restart would end the same way: a usage error,
/// a refusal of the relay that a new start does not change, a setting.
pub fn is_final(code: i32) -> bool {
    use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_USAGE};
    matches!(code, EX_USAGE | EX_NOPERM | EX_CONFIG)
}

/// The supervisor's whole run: `args` are the words of the run, after the
/// flag. Its code: the first child's before ready; after it, 0 on a stop,
/// or the code of a child that ended for good.
pub fn run(args: &[OsString]) -> i32 {
    let verb = args.first().and_then(|w| w.to_str()).unwrap_or("podssh").to_string();
    let log = child::log_file(&verb);
    let log_path = log.as_ref().map(|(path, _)| path.clone());
    let started = Instant::now();
    let mut first = match start(args, true, log_path.as_ref()) {
        Ok(first) => first,
        Err(why) => {
            let _ = writeln!(std::io::stderr(), "podssh {verb}: --restart: {why}");
            return crate::exit_codes::EXIT_NOT_IMPLEMENTED;
        }
    };
    // The child's own words after its ready name its pid and the same log,
    // which the supervisor's line says too.
    if pass_until_ready(&mut first).is_none() {
        // The first run ended before ready: its code, as without --restart.
        return first.wait().map(code_of).unwrap_or(podssh_ssh::EXIT_FAILURE);
    }
    let shown = log.as_ref().map_or_else(|| "none".to_string(), |(p, _)| p.display().to_string());
    let line =
        format!("{READY} pid {}, which restarts the run of pid {}, its log {shown}\n", std::process::id(), first.id());
    if !child::leave(log.as_ref().map(|(_, f)| f), line.as_bytes()) {
        let _ = first.kill();
        return crate::exitmap::sysexits::EX_TEMPFAIL;
    }
    drain(&mut first, None);
    catch_stop();
    keep(args, &verb, first, started, log_path)
}

/// The child started: this binary with the child's flag and `args`. The
/// first takes the caller's stdin and stderr, for its prompts and lines; a
/// restart takes none, its lines going to the log.
fn start(args: &[OsString], first: bool, log: Option<&PathBuf>) -> Result<Child, String> {
    start_with(args, first, log, None)
}

/// [`start`], with `program` tried first: the binary of before an update.
fn start_with(
    args: &[OsString],
    first: bool,
    log: Option<&PathBuf>,
    program: Option<&PathBuf>,
) -> Result<Child, String> {
    // The supervisor's own standard handles stay out of the run: Windows
    // hands a child each handle that may be inherited, and a copy of the
    // caller's pipe in the run would hold a caller that reads it to its end
    // (T-383's defect, met again by the supervisor in CI's Windows job).
    child::keep_own_handles();
    let mut tried = Vec::new();
    let programs = program.cloned().into_iter().chain(binaries());
    for program in programs {
        let mut cmd = Command::new(&program);
        child::name_it(&mut cmd);
        cmd.arg(CHILD_FLAG).args(args).stdout(Stdio::piped());
        if let Some(path) = log {
            cmd.env(LOG_VARIABLE, path);
        }
        if first {
            cmd.stdin(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            cmd.stdin(Stdio::null());
            let err = log.and_then(|p| std::fs::OpenOptions::new().append(true).open(p).ok());
            cmd.stderr(err.map_or_else(Stdio::null, Stdio::from));
        }
        match child::spawn(&mut cmd, &mut |line| podssh_ssh::err_line!("podssh: --restart: note: {line}")) {
            Ok(started) => return Ok(started),
            Err(e) => tried.push(format!("{}: {e}", program.display())),
        }
    }
    if tried.is_empty() {
        tried.push("no path of this program was found".into());
    }
    Err(format!("this program could not start itself again: {}", tried.join("; ")))
}

/// The first child's lines to this process's stdout, the parent's pipe,
/// until its line of ready: what follows it, or `None` when it ended first.
fn pass_until_ready(first: &mut Child) -> Option<String> {
    let stdout = first.stdout.as_mut()?;
    let mut out = std::io::stdout();
    let mut lines = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        match lines.read_line(&mut line) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        if let Some(rest) = line.trim_end().strip_prefix(READY) {
            return Some(rest.to_string());
        }
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }
}

/// A child's stdout read to its end on a thread of its own, each line to
/// this process's log (its stdout after ready): a child must never wait on
/// a pipe that nobody reads.
fn drain(child: &mut Child, tag: Option<u32>) {
    let Some(stdout) = child.stdout.take() else { return };
    let _ = std::thread::Builder::new().name("restart-lines".into()).spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            match tag {
                Some(n) => podssh_ssh::out_line!("podssh: --restart: run {n}: {line}"),
                None => podssh_ssh::out_line!("{line}"),
            }
        }
    });
}

/// After ready: wait for the child, and start it again after each end that
/// is not final, until a stop.
fn keep(args: &[OsString], verb: &str, mut child: Child, mut began: Instant, log: Option<PathBuf>) -> i32 {
    let mut tries = 0u32;
    let mut runs = 1u32;
    // The binary that started this run, before an update could replace it.
    let exe = std::env::current_exe().ok();
    let (mut failed_starts, mut fallback) = (0u32, None::<PathBuf>);
    loop {
        let status = match wait_or_stop(&mut child) {
            Ok(status) => status,
            Err(code) => return code,
        };
        let code = code_of(status);
        if is_final(code) {
            podssh_ssh::err_line!(
                "podssh {verb}: --restart: the run ended with {code}, which a new start would repeat; no restart"
            );
            return code;
        }
        if began.elapsed() >= STEADY {
            tries = 0;
        }
        failed_starts = if began.elapsed() < QUICK { failed_starts.saturating_add(1) } else { 0 };
        if fallback.is_none() && falls_back(failed_starts) {
            fallback = exe.as_deref().and_then(crate::update::keep::fallback);
            if let Some(prev) = &fallback {
                podssh_ssh::err_line!(
                    "podssh {verb}: --restart: the run failed to start {failed_starts} times in a row; the binary of \
                     before the update, {}, starts it from now on",
                    prev.display()
                );
            }
        }
        loop {
            tries = tries.saturating_add(1);
            let wait = podssh_relay::open::backoff(tries);
            podssh_ssh::err_line!(
                "podssh {verb}: --restart: the run ended ({}); starting it again in {:.1} s (restart {tries} since it last ran {} s)",
                ended(status),
                wait.as_secs_f64(),
                STEADY.as_secs()
            );
            if sleep_or_stop(wait) {
                return 0;
            }
            runs = runs.saturating_add(1);
            match start_with(args, false, log.as_ref(), fallback.as_ref()) {
                Ok(mut next) => {
                    podssh_ssh::err_line!("podssh {verb}: --restart: run {runs} started, pid {}", next.id());
                    drain(&mut next, Some(runs));
                    child = next;
                    began = Instant::now();
                    break;
                }
                // A start that fails (no memory, no process left) is
                // tried again, never the end of the supervision.
                Err(why) => podssh_ssh::err_line!("podssh {verb}: --restart: {why}"),
            }
        }
    }
}

/// How the run ended, in words.
fn ended(status: std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("code {code}");
    }
    format!("signal {}", code_of(status) - 128)
}

/// The child's end; or, on a stop, the child stopped and `Err` with the
/// supervisor's code.
fn wait_or_stop(child: &mut Child) -> Result<std::process::ExitStatus, i32> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            // The child cannot be waited for: it is taken for ended.
            Err(_) => return Ok(fake_end()),
        }
        if STOP.load(Ordering::SeqCst) {
            stop(child);
            return Err(0);
        }
        std::thread::sleep(TICK);
    }
}

/// An end of no code, for a child that cannot be waited for.
fn fake_end() -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(podssh_ssh::EXIT_FAILURE << 8)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(podssh_ssh::EXIT_FAILURE as u32)
    }
}

/// Wait `wait`; whether a stop came meanwhile.
fn sleep_or_stop(wait: Duration) -> bool {
    let until = Instant::now() + wait;
    while Instant::now() < until {
        if STOP.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(TICK.min(until.saturating_duration_since(Instant::now())));
    }
    STOP.load(Ordering::SeqCst)
}

/// The child stopped: SIGTERM, then SIGKILL after [`STOP_GRACE`]; on
/// Windows at once.
fn stop(child: &mut Child) {
    #[cfg(unix)]
    {
        // SAFETY: a signal to this process's own child, which it has not
        // waited for yet, so its pid is not reused.
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let until = Instant::now() + STOP_GRACE;
        while Instant::now() < until {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(TICK);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// SIGTERM and SIGINT stop the supervisor and its run; on Windows a stop
/// is the end of the supervisor's process, which leaves the run alone.
fn catch_stop() {
    #[cfg(unix)]
    {
        extern "C" fn on_stop(_: libc::c_int) {
            STOP.store(true, Ordering::SeqCst);
        }
        // SAFETY: the handler only stores to an atomic, which is safe in a
        // handler of a signal.
        unsafe {
            libc::signal(libc::SIGTERM, on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t);
            libc::signal(libc::SIGINT, on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t);
        }
    }
}

/// Whether `failed_starts` in a row call for the binary of before.
fn falls_back(failed_starts: u32) -> bool {
    failed_starts >= FAILED_STARTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_failed_starts_in_a_row_call_for_the_binary_of_before() {
        assert!(!falls_back(0) && !falls_back(FAILED_STARTS - 1));
        assert!(falls_back(FAILED_STARTS) && falls_back(u32::MAX));
    }

    #[test]
    fn a_usage_error_a_refusal_and_a_setting_are_final() {
        assert!(is_final(64) && is_final(77) && is_final(78));
        for code in [0, 1, 2, 69, 70, 75, 101, 128 + 6, 128 + 9, 128 + 15, 255] {
            assert!(!is_final(code), "{code} is restarted");
        }
    }

    #[test]
    fn a_wait_ends_early_on_a_stop() {
        STOP.store(true, Ordering::SeqCst);
        let began = Instant::now();
        assert!(sleep_or_stop(Duration::from_secs(30)));
        assert!(began.elapsed() < Duration::from_secs(1));
        STOP.store(false, Ordering::SeqCst);
        assert!(!sleep_or_stop(Duration::from_millis(10)));
    }
}
