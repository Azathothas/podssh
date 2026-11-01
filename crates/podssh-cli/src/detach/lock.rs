//! The name of a run in the background and its lock (T-392). A run of
//! `--detach` holds `detached/NAME.lock` in the cache for its life, so that a
//! second start of the same name (a cron line, a unit, a person) refuses with
//! 75 and names the pid that runs, where it would start a second copy, which
//! the relay refuses for a node of the same pair (409) and a `-R` forward
//! meets as a port in use. With `--restart` the supervisor holds it, so that
//! its restarts keep it, and each run that it starts holds `NAME.run.lock`,
//! so that a run whose supervisor died still holds its name. Beside them,
//! `NAME.json` records the run: its pid, its words, its log and its start.
//! `podssh detached` trusts the locks, never a pid alone, which the system
//! gives to another process once its own ended.
//!
//! The kernel lets a lock go when its process ends, however it ends, so no
//! stale file keeps a name taken. A lock that cannot be had (no cache, a file
//! system that takes none) lets the run go on with a line: a run with no lock
//! serves, and one that never starts locks its server out.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::exitmap::sysexits::EX_TEMPFAIL;
use crate::node_install::lock::{try_hold, Tried};

/// How the parent of `--detach` gives the run its name (`--detach-name`),
/// and a supervisor gives it to each run that it starts.
pub const NAME_VARIABLE: &str = "PODSSH_DETACH_NAME";
/// The supervisor's pid, in each run that it starts: such a run holds its
/// run's lock, not the name's, which its supervisor holds.
pub const SUPERVISOR_VARIABLE: &str = "PODSSH_DETACH_SUPERVISOR";
/// The longest name of a run.
pub const NAME_MAX: usize = 64;
/// The directory of the runs, in the cache.
pub const DIR: &str = "detached";
/// How long a start tries again a lock that `podssh detached` or a cleanup
/// holds for a moment, before it takes it for a run's.
const PATIENCE: Duration = Duration::from_secs(1);
const STEP: Duration = Duration::from_millis(100);

/// The locks of this process, kept open until it ends.
static HELD: OnceLock<File> = OnceLock::new();
static RUN_HELD: OnceLock<File> = OnceLock::new();
/// This run's name, once chosen.
static NAME: OnceLock<String> = OnceLock::new();
/// The record that this process wrote, and where, to write it again.
static RECORD: Mutex<Option<(PathBuf, Value)>> = Mutex::new(None);

/// A run's name: letters, digits, `_` and `-`, not first a `-`, 1 to
/// [`NAME_MAX`]; it names files, so nothing else is taken (a `.` would let
/// `x.run` meet the run's lock of `x`).
pub fn check_name(name: &str) -> Result<(), String> {
    let fits = !name.is_empty()
        && name.len() <= NAME_MAX
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if fits {
        Ok(())
    } else {
        Err(format!("{name:?}: a run's name has letters, digits, _ and -, not first a -, {NAME_MAX} at most"))
    }
}

/// The directory of the runs: `detached` in the first directory of the
/// cache that can be made private (mode 0700), as the logs choose it; none
/// with `PODSSH_CACHE_DIR=none`. Found once: the last directory of the
/// cache is in the working directory, which a run leaves at ready (T-397),
/// and its files must not move.
pub fn dir() -> Option<PathBuf> {
    static FOUND: OnceLock<Option<PathBuf>> = OnceLock::new();
    FOUND
        .get_or_init(|| {
            podssh_relay::cache::candidate_dirs()
                .into_iter()
                .map(|dir| dir.join(DIR))
                .find(|dir| podssh_relay::cache::private_dir(dir).is_ok())
        })
        .clone()
}

/// The files of the run `name` in `dir`.
pub fn lock_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.lock"))
}
pub fn run_lock_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.run.lock"))
}
pub fn record_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.json"))
}

/// This process's name for its run: the one that its parent or supervisor
/// gave, else its verb and its pid, which no other running holder has, so
/// that a run with no name is never refused.
pub fn own_name(verb: &str) -> String {
    NAME.get_or_init(|| {
        std::env::var(NAME_VARIABLE)
            .ok()
            .filter(|n| check_name(n).is_ok())
            .unwrap_or_else(|| format!("{verb}-{}", std::process::id()))
    })
    .clone()
}

/// The name chosen by [`own_name`], if any was.
pub fn name() -> Option<&'static str> {
    NAME.get().map(String::as_str)
}

/// Who holds a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    /// Nobody: no file, or a file that no process holds.
    Free,
    /// A run, with its pid where the file lets another process read it
    /// (Windows locks a held file against reads).
    Held(Option<u32>),
    /// The lock could not be tried.
    Unknown(String),
}

/// Who holds the lock at `path`, found by trying it shared, never by a
/// pid: a shared lock writes nothing, and two readers do not meet.
pub fn holder(path: &Path) -> Holder {
    let file = match File::open(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Holder::Free,
        Err(e) => return Holder::Unknown(e.to_string()),
        Ok(file) => file,
    };
    match file.try_lock_shared() {
        // Let go as the file closes.
        Ok(()) => Holder::Free,
        Err(std::fs::TryLockError::WouldBlock) => Holder::Held(read_pid(path)),
        Err(std::fs::TryLockError::Error(e)) => Holder::Unknown(e.to_string()),
    }
}

fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// The lock at `path` for this process, tried again for [`PATIENCE`] while
/// another holds it, as a reader holds it for a moment.
fn hold(path: &Path) -> Result<Tried, String> {
    let until = Instant::now() + PATIENCE;
    loop {
        let tried = try_hold(path)?;
        let late = Instant::now() >= until;
        match tried {
            Tried::Held(file) if late || still_named(&file, path) => return Ok(Tried::Held(file)),
            Tried::Taken(pid) if late => return Ok(Tried::Taken(pid)),
            // Taken for a moment; or held, but its file was removed and
            // made again meanwhile (a cleanup), so the new one is tried.
            _ => std::thread::sleep(STEP),
        }
    }
}

/// Whether `path` still names the open `file`: a lock of a file that a
/// cleanup removed would hold no name.
fn still_named(file: &File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (file.metadata(), std::fs::metadata(path)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        // On Windows a file removed while a process holds it open keeps
        // its name until it closes, so the name still names it.
        let _ = (file, path);
        true
    }
}

/// The holder's step, before anything connects: the plain run's or the
/// supervisor's. It takes the lock of the name, sees that no run of the name
/// whose supervisor ended still serves, and writes the record. `Some(75)`
/// when the name runs already, said on `err`, still the caller's.
pub fn enter(verb: &str, supervisor: bool, words: &[OsString], err: &mut dyn Write) -> Option<i32> {
    let name = own_name(verb);
    let Some(dir) = dir() else {
        let _ = writeln!(
            err,
            "podssh {verb}: --detach: no directory of the cache takes the lock of {name}: a second start of it would \
             run beside this one"
        );
        return None;
    };
    match hold(&lock_path(&dir, &name)) {
        Ok(Tried::Held(file)) => {
            let _ = HELD.set(file);
        }
        Ok(Tried::Taken(pid)) => {
            let pid = pid.or_else(|| read_record(&dir, &name).and_then(|r| pid_field(&r, "pid")));
            let by = pid.map_or_else(|| "a run".to_string(), |pid| format!("pid {pid}"));
            let _ = writeln!(
                err,
                "podssh {verb}: --detach: the run {name} runs already ({by}, which holds {}): podssh detached stop \
                 {name} ends it; this start ends",
                lock_path(&dir, &name).display()
            );
            return Some(EX_TEMPFAIL);
        }
        Err(why) => {
            let _ =
                writeln!(err, "podssh {verb}: --detach: no lock of {name} ({why}): a second start would run beside");
            return None;
        }
    }
    if let Holder::Held(pid) = holder(&run_lock_path(&dir, &name)) {
        let pid = pid.or_else(|| read_record(&dir, &name).and_then(|r| pid_field(&r, "run")));
        let by = pid.map_or_else(|| "a run".to_string(), |pid| format!("the run of pid {pid}"));
        let _ = writeln!(
            err,
            "podssh {verb}: --detach: {by}, whose supervisor of --restart ended, still serves as {name}: podssh \
             detached stop {name} ends it; this start ends"
        );
        return Some(EX_TEMPFAIL);
    }
    let record = json!({
        "name": name,
        "verb": verb,
        "pid": std::process::id(),
        "supervised": supervisor,
        "run": null,
        "words": words.iter().map(|w| w.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        "log": null,
        "started": crate::pairs::now_ms().div_euclid(1000),
    });
    keep_record(record_path(&dir, &name), record);
    None
}

/// A run that a supervisor started: its own lock beside the name's, which
/// its supervisor holds. Never refused: the supervisor is the one start of
/// the name, and a lock that a run before it still holds (a process the
/// system has not ended yet) is said, and the run goes on.
pub fn enter_run(verb: &str) {
    let name = own_name(verb);
    let Some(dir) = dir() else { return };
    match hold(&run_lock_path(&dir, &name)) {
        Ok(Tried::Held(file)) => {
            let _ = RUN_HELD.set(file);
        }
        Ok(Tried::Taken(pid)) => podssh_ssh::err_line!(
            "podssh {verb}: --restart: the lock of the run {name} is held{}; this run goes on without it",
            pid.map_or_else(String::new, |pid| format!(" by pid {pid}"))
        ),
        Err(why) => podssh_ssh::err_line!("podssh {verb}: --restart: no lock of the run {name} ({why}); it goes on"),
    }
}

/// In a detached child, before anything else of its run: the lock of its
/// name, or under a supervisor its run's lock. `Some(code)` ends it. A
/// session's daemon, which starts as a detached child too, has its own lock.
pub fn enter_child(argv: &[OsString]) -> Option<i32> {
    if !super::is_child() {
        return None;
    }
    let verb = argv.first().and_then(|w| w.to_str()).and_then(crate::flags::canonical_name)?;
    if !matches!(verb, "ssh" | "pipe" | "node") {
        return None;
    }
    if std::env::var_os(SUPERVISOR_VARIABLE).is_some() {
        enter_run(verb);
        return None;
    }
    enter(verb, false, argv, &mut std::io::stderr())
}

/// The record of the run `name` in `dir`, as its holder wrote it.
pub fn read_record(dir: &Path, name: &str) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(record_path(dir, name)).ok()?).ok()
}

/// A pid of a record: `pid`, the holder's, or `run`, its run's.
pub fn pid_field(record: &Value, field: &str) -> Option<u32> {
    record.get(field).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok())
}

/// Write `record` at `path` and keep it, to write it again with a change.
fn keep_record(path: PathBuf, record: Value) {
    write_record(&path, &record);
    if let Ok(mut kept) = RECORD.lock() {
        *kept = Some((path, record));
    }
}

/// The record changed by `change`, written again; nothing when this
/// process wrote none.
fn change_record(change: impl FnOnce(&mut Value)) {
    let Ok(mut kept) = RECORD.lock() else { return };
    if let Some((path, record)) = kept.as_mut() {
        change(record);
        write_record(path, record);
    }
}

/// The run's log, once it is ready.
pub fn logged(log: &Path) {
    change_record(|r| r["log"] = json!(log.display().to_string()));
}

/// The pid of the run that a supervisor started last.
pub fn ran(pid: u32) {
    change_record(|r| r["run"] = json!(pid));
}

/// A record in one rename, so that a reader never sees half of one; a
/// failure is no failure of the run, whose lock is what counts.
fn write_record(path: &Path, record: &Value) {
    let mut part = path.as_os_str().to_owned();
    part.push(format!(".{}.part", std::process::id()));
    let part = PathBuf::from(part);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&part).and_then(|mut f| f.write_all(format!("{record}\n").as_bytes()));
    if written.is_err() || std::fs::rename(&part, path).is_err() {
        let _ = std::fs::remove_file(&part);
    }
}

#[cfg(test)]
mod tests;
