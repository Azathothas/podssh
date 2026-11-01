//! `podssh detached` (T-392): the runs that `--detach` and `-f` sent into
//! the background, by their names: `list`, `status NAME` and `stop NAME`.
//! Each reads the locks of a name, never a pid alone: a run that ended
//! leaves its record, and the system gives its pid to another process. A
//! pid is sent a signal only while the lock of its run is held, and it is
//! the pid that the holder wrote.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::lock::{self, Holder};
use crate::exitmap::sysexits::{EX_SOFTWARE, EX_TEMPFAIL, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;

/// How long a stopped run has for its end before it is killed: the time
/// that a supervisor gives its own run.
#[cfg(unix)]
const STOP_GRACE: Duration = Duration::from_secs(10);
/// How long a killed run has to let its locks go.
const KILL_GRACE: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(100);

const SUBCOMMANDS: &str = "list, status or stop";

/// `detached`'s command line as parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetachedArgs {
    pub subcommand: Option<String>,
    pub args: Vec<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// Run `podssh detached`; the process exit code: 0 for a list, a run that
/// runs, or one stopped; 69 for a name that runs nothing; 75 for a run that
/// holds its lock after SIGKILL.
pub fn run(args: &DetachedArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let sub = match args.subcommand.as_deref() {
        Some(sub) => sub,
        None => return Refusal::usage(format!("give a subcommand: {SUBCOMMANDS}")).report("detached", err),
    };
    let name = match (sub, args.args.as_slice()) {
        ("list", []) => None,
        ("list", _) => return Refusal::usage("list takes no name: it names each run").report("detached", err),
        ("status" | "stop", [name]) => Some(name.as_str()),
        ("status" | "stop", _) => {
            return Refusal::usage(format!("{sub} takes one name: podssh detached {sub} NAME")).report("detached", err)
        }
        (other, _) => return Refusal::usage(format!("no subcommand {other:?}: {SUBCOMMANDS}")).report("detached", err),
    };
    if let Some(name) = name {
        if let Err(why) = lock::check_name(name) {
            return Refusal::usage(why).report("detached", err);
        }
    }
    let Some(dir) = lock::dir() else {
        let _ =
            writeln!(err, "podssh detached: no directory of the cache is there, so no run in the background is known");
        return if name.is_none() { 0 } else { EX_UNAVAILABLE };
    };
    match (sub, name) {
        ("status", Some(name)) => status(&dir, name, out, err),
        ("stop", Some(name)) => stop(&dir, name, err),
        _ => list(&dir, out),
    }
}

/// What the locks and the record of a name say.
struct Seen {
    main: Holder,
    run: Holder,
    record: Option<Value>,
}

impl Seen {
    fn of(dir: &Path, name: &str) -> Seen {
        Seen {
            main: lock::holder(&lock::lock_path(dir, name)),
            run: lock::holder(&lock::run_lock_path(dir, name)),
            record: lock::read_record(dir, name),
        }
    }

    fn running(&self) -> bool {
        matches!(self.main, Holder::Held(_)) || matches!(self.run, Holder::Held(_))
    }

    fn state(&self) -> String {
        match (&self.main, &self.run) {
            (Holder::Held(_), _) => "running".into(),
            (_, Holder::Held(_)) => "running, its supervisor gone".into(),
            (Holder::Unknown(why), _) | (_, Holder::Unknown(why)) => format!("unknown: {why}"),
            _ => "ended".into(),
        }
    }

    /// The pid of a held lock: the one in its file, else the record's,
    /// which its holder wrote after it took the lock.
    fn pid(&self, which: &Holder, field: &str) -> Option<u32> {
        match which {
            Holder::Held(pid) => pid.or_else(|| self.record.as_ref().and_then(|r| lock::pid_field(r, field))),
            _ => None,
        }
    }

    fn holder_pid(&self) -> Option<u32> {
        self.pid(&self.main, "pid")
    }

    fn run_pid(&self) -> Option<u32> {
        self.pid(&self.run, "run")
    }

    fn text(&self, field: &str) -> String {
        match self.record.as_ref().and_then(|r| r.get(field)) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(words)) => words.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "),
            Some(Value::Number(n)) => n.to_string(),
            _ => "-".into(),
        }
    }
}

/// The names of the runs in `dir`: each record's and each lock's.
fn names(dir: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return found };
    for entry in entries.flatten() {
        let Ok(file) = entry.file_name().into_string() else { continue };
        let name = file.strip_suffix(".json").or_else(|| file.strip_suffix(".lock"));
        if let Some(name) = name.filter(|n| !n.ends_with(".run") && lock::check_name(n).is_ok()) {
            found.insert(name.to_string());
        }
    }
    found
}

/// A line for each run: its name, its state, its pid and its words, with a
/// tab between them.
fn list(dir: &Path, out: &mut dyn Write) -> i32 {
    for name in names(dir) {
        let seen = Seen::of(dir, &name);
        let pid = seen.holder_pid().or(seen.run_pid()).map_or_else(|| "-".to_string(), |p| p.to_string());
        let _ = writeln!(out, "{name}\t{}\t{pid}\t{}", seen.state(), seen.text("words"));
    }
    0
}

fn status(dir: &Path, name: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let seen = Seen::of(dir, name);
    if seen.record.is_none() && !seen.running() {
        let _ = writeln!(err, "podssh detached: no run named {name} is known in {}", dir.display());
        return EX_UNAVAILABLE;
    }
    let shown = |pid: Option<u32>| pid.map_or_else(|| "-".to_string(), |p| p.to_string());
    let supervised = seen.record.as_ref().and_then(|r| r.get("supervised")).and_then(Value::as_bool) == Some(true);
    let _ = writeln!(out, "name: {name}");
    let _ = writeln!(out, "state: {}", seen.state());
    let _ = writeln!(
        out,
        "pid: {}{}",
        shown(seen.holder_pid()),
        if supervised { " (the supervisor of --restart)" } else { "" }
    );
    if supervised {
        let _ = writeln!(out, "run: {}", shown(seen.run_pid()));
    }
    let _ = writeln!(out, "verb: {}", seen.text("verb"));
    let _ = writeln!(out, "words: {}", seen.text("words"));
    let _ = writeln!(out, "log: {}", seen.text("log"));
    let started = seen.record.as_ref().and_then(|r| r.get("started")).and_then(Value::as_i64);
    let _ = writeln!(out, "started: {}", started.map_or_else(|| "-".to_string(), crate::doctor::clock::format_utc));
    // The last beat of a supervisor's run (T-394), for a person to read.
    let beat = std::fs::metadata(super::beat::alive_path(dir, name)).and_then(|m| m.modified()).ok();
    if let Some(ago) = beat.and_then(|at| std::time::SystemTime::now().duration_since(at).ok()) {
        let _ = writeln!(out, "heartbeat: {} s ago", ago.as_secs());
    }
    if seen.running() {
        0
    } else {
        EX_UNAVAILABLE
    }
}

/// Stop the run `name`: SIGTERM to the holder of its name (a supervisor
/// passes it to its run), else to a run whose supervisor is gone; after
/// [`STOP_GRACE`], SIGKILL to each holder still there, the supervisor
/// first. On Windows, each is ended at once, the supervisor first, as it
/// would start its run again.
fn stop(dir: &Path, name: &str, err: &mut dyn Write) -> i32 {
    let seen = Seen::of(dir, name);
    if !seen.running() {
        let _ = writeln!(err, "podssh detached: no run named {name} runs ({})", seen.state());
        return EX_UNAVAILABLE;
    }
    let first = seen.holder_pid().or(seen.run_pid());
    let Some(first) = first.filter(|pid| killable(*pid)) else {
        let _ = writeln!(
            err,
            "podssh detached: the run {name} holds its lock, and neither its lock nor its record names its pid"
        );
        return EX_SOFTWARE;
    };
    #[cfg(unix)]
    {
        signal(first, libc::SIGTERM);
        // A stopped process acts on SIGTERM only once it goes on.
        signal(first, libc::SIGCONT);
        if ended(dir, name, STOP_GRACE) {
            let _ = writeln!(err, "podssh detached: {name} stopped (pid {first})");
            return 0;
        }
    }
    // Each holder that is still there, its pid read again: the supervisor
    // first, so that it starts no run again, then its run.
    let now = Seen::of(dir, name);
    for pid in [now.holder_pid(), now.run_pid()].into_iter().flatten().filter(|p| killable(*p)) {
        kill(pid);
    }
    if ended(dir, name, KILL_GRACE) {
        let _ = writeln!(err, "podssh detached: {name} stopped (pid {first}, killed)");
        return 0;
    }
    let _ = writeln!(
        err,
        "podssh detached: the run {name} still holds its lock after it was killed; podssh detached status {name} \
         says more"
    );
    EX_TEMPFAIL
}

/// Whether no lock of `name` is held within `wait`.
fn ended(dir: &Path, name: &str, wait: Duration) -> bool {
    let until = Instant::now() + wait;
    loop {
        if !Seen::of(dir, name).running() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(TICK);
    }
}

/// A pid that may be sent a signal: never 0, 1 or this process, which a
/// broken record could name.
fn killable(pid: u32) -> bool {
    pid > 1 && pid != std::process::id() && i32::try_from(pid).is_ok()
}

#[cfg(unix)]
fn signal(pid: u32, signal: libc::c_int) {
    // SAFETY: a signal to one process, a positive pid that [`killable`]
    // checked, which holds the lock of the run as its file or record says.
    unsafe { libc::kill(pid as libc::pid_t, signal) };
}

#[cfg(unix)]
fn kill(pid: u32) {
    signal(pid, libc::SIGKILL);
}

#[cfg(windows)]
fn kill(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    // SAFETY: the handle is checked, used once and closed once.
    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !process.is_null() {
            TerminateProcess(process, 1);
            CloseHandle(process);
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn kill(_pid: u32) {}
