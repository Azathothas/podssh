//! The log of the sessions of this host (T-056), when the user asks for it:
//! one JSON line for each run of `podssh ssh` and `podssh proxy` that named
//! a destination, at its end. `PODSSH_SESSION_LOG` turns it on (`1`, `yes`:
//! in the first usable directory of the cache; an absolute path: that file)
//! or off (`0`, `no`), over `SessionLog` in the settings file; it is off by
//! default. A line holds when the run started, how long it took, the verb,
//! the destination's host and port, the road (the relay host, or `direct`,
//! `node`, `iroh`, `cloudflare`), how it ended, its exit code, its bytes and
//! the relay's close code: never a command, an environment value, a token or
//! a password. The file is private (0600), opened to append with no
//! symbolic link followed, and each line goes in one write, so that two
//! processes do not mix theirs; past 1 MiB it becomes `sessions.1.jsonl`,
//! and a new file starts.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::relay_settings::Refusal;
use crate::settings::Defaults;

/// The variable that turns the log on or off.
pub const ENV: &str = "PODSSH_SESSION_LOG";
/// The file in the cache.
pub const FILE: &str = "sessions.jsonl";
/// The file that a full log becomes.
pub const OLD_FILE: &str = "sessions.1.jsonl";
/// The size at which the log is moved aside.
pub const LIMIT: u64 = 1 << 20;

/// Where the lines go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    Off,
    /// The first usable directory of the cache.
    Cache,
    File(PathBuf),
}

/// A value of the variable or of `SessionLog`: yes, no, or an absolute path
/// (`~` is the home).
pub fn parse(text: &str, home: Option<&Path>) -> Result<Place, String> {
    match text.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "on" => return Ok(Place::Cache),
        "0" | "no" | "off" => return Ok(Place::Off),
        _ => {}
    }
    let path = crate::ssh::tokens::tilde(text.trim(), home);
    match path.is_absolute() {
        true => Ok(Place::File(path)),
        false => Err(format!("{text:?}: give yes, no or the absolute path of a file")),
    }
}

/// Where the lines of this process go: the variable, else the settings file.
pub fn place() -> Result<Place, Refusal> {
    let home = crate::ssh::resolve::Env::from_process().home;
    place_from(std::env::var(ENV).ok(), crate::settings::here(), home.as_deref())
}

/// [`place`] with the variable, the settings and the home given. A value
/// that is not one is refused (78), as each variable's is.
pub fn place_from(var: Option<String>, file: &Defaults, home: Option<&Path>) -> Result<Place, Refusal> {
    if let Some(text) = var.filter(|v| !v.trim().is_empty()) {
        return parse(&text, home).map_err(|why| Refusal::config(format!("{ENV} {why}")));
    }
    match &file.session_log {
        Some(value) => {
            parse(&value.text, home).map_err(|why| Refusal::config(format!("{}: SessionLog {why}", value.at)))
        }
        None => Ok(Place::Off),
    }
}

/// What a run says of itself for its line, besides the record of `podssh
/// ssh` (T-054).
#[derive(Debug, Clone, Default)]
struct Run {
    host: Option<String>,
    port: Option<u16>,
    road: &'static str,
    relay_host: Option<String>,
    opened: bool,
    close_code: Option<u16>,
    carried: Option<(u64, u64)>,
}

static RUN: Mutex<Option<Run>> = Mutex::new(None);

fn run_mut<T>(f: impl FnOnce(&mut Run) -> T) -> Option<T> {
    RUN.lock().unwrap_or_else(|e| e.into_inner()).as_mut().map(f)
}

/// The destination of this run and its road: a run with none has no line.
pub fn target(host: &str, port: Option<u16>, road: &'static str) {
    *RUN.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(Run { host: Some(host.to_string()), port, road, ..Run::default() });
}

/// `podssh proxy`: its session opened, through this relay host when one.
pub fn opened(relay_host: Option<&str>) {
    run_mut(|run| {
        run.opened = true;
        run.relay_host = relay_host.map(str::to_string);
    });
}

/// `podssh proxy`: the relay's close code.
pub fn closed(code: Option<u16>) {
    run_mut(|run| run.close_code = run.close_code.or(code));
}

/// `podssh proxy`: the bytes sent and received.
pub fn carried(sent: u64, received: u64) {
    run_mut(|run| run.carried = Some((sent, received)));
}

/// The line of a run of `podssh ssh`, from its result (T-054); none when it
/// named no destination.
pub fn ssh_line(start_ms: i64, result: &Value) -> Option<Value> {
    let run = RUN.lock().unwrap_or_else(|e| e.into_inner()).clone()?;
    let relay = &result["relay"];
    let via = relay["host"].as_str().map(str::to_string).unwrap_or_else(|| run.road.to_string());
    Some(line(&run, start_ms, "ssh", via, result, relay["close_code"].clone()))
}

/// The line of a run of `podssh proxy` that exits with `exit`.
pub fn proxy_line(start_ms: i64, duration_ms: u64, exit: i32) -> Option<Value> {
    let run = RUN.lock().unwrap_or_else(|e| e.into_inner()).clone()?;
    let abnormal = run.close_code.is_some_and(|code| code != 1000);
    let failure = (!run.opened || abnormal || exit != 0).then_some("relay");
    let (sent, received) = run.carried.unwrap_or_default();
    let result = json!({
        "exit": exit,
        "end": if run.opened { "closed" } else { "failed" },
        "failure": failure,
        "bytes": { "stdin": sent, "stdout": received, "stderr": 0 },
        "duration_ms": duration_ms,
    });
    let via = run.relay_host.clone().unwrap_or_else(|| run.road.to_string());
    Some(line(&run, start_ms, "proxy", via, &result, json!(run.close_code)))
}

fn line(run: &Run, start_ms: i64, verb: &str, via: String, result: &Value, close_code: Value) -> Value {
    json!({
        "start": crate::pairs::utc(start_ms),
        "duration_ms": result["duration_ms"],
        "verb": verb,
        "host": run.host,
        "port": run.port,
        "via": via,
        "end": result["end"],
        "exit": result["exit"],
        "failure": result["failure"],
        "bytes": result["bytes"],
        "close_code": close_code,
    })
}

/// Append `line` where `place` says; the file it went to.
pub fn append(place: &Place, line: &Value) -> Result<PathBuf, String> {
    let mut text = line.to_string();
    text.push('\n');
    match place {
        Place::Off => Err("the session log is off".into()),
        Place::File(path) => append_to(path, text.as_bytes()).map(|()| path.clone()),
        Place::Cache => {
            let dirs = podssh_relay::cache::candidate_dirs();
            let mut refused = Vec::new();
            for dir in &dirs {
                let path = dir.join(FILE);
                let done = podssh_relay::cache::private_dir(dir).map_err(|e| e.to_string());
                match done.and_then(|()| append_to(&path, text.as_bytes())) {
                    Ok(()) => return Ok(path),
                    Err(why) => refused.push(format!("{}: {why}", dir.display())),
                }
            }
            Err(format!("no directory of the cache took {FILE} ({})", refused.join("; ")))
        }
    }
}

/// One line at the end of `path`, which is moved aside first when full.
fn append_to(path: &Path, line: &[u8]) -> Result<(), String> {
    let shown = path.display();
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() >= LIMIT) {
        std::fs::rename(path, aside(path)).map_err(|e| format!("{shown}: {e}"))?;
    }
    match podssh_relay::cache::create_new_private(path) {
        Ok(created) => drop(created),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{shown}: {e}")),
    }
    let mut file = open_to_append(path).map_err(|e| format!("{shown}: {e}"))?;
    own_and_private(path, &file)?;
    file.write_all(line).map_err(|e| format!("{shown}: {e}"))
}

/// The name that a full log takes: `sessions.1.jsonl` for `sessions.jsonl`.
fn aside(path: &Path) -> PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let name = match path.extension() {
        Some(ext) => format!("{stem}.1.{}", ext.to_string_lossy()),
        None => format!("{stem}.1"),
    };
    path.with_file_name(name)
}

#[cfg(unix)]
fn open_to_append(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().append(true).read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}

#[cfg(not(unix))]
fn open_to_append(path: &Path) -> std::io::Result<std::fs::File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "a symbolic link"));
    }
    std::fs::OpenOptions::new().append(true).read(true).open(path)
}

/// A regular file of this user that no other user may read.
fn own_and_private(path: &Path, file: &std::fs::File) -> Result<(), String> {
    let meta = file.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    podssh_relay::cache::closed(path, file, podssh_relay::cache::Others::NoAccess)
}

/// The file of the log, when it is on and holds a line.
pub fn file(place: &Place) -> Option<PathBuf> {
    match place {
        Place::Off => None,
        Place::File(path) => Some(path.clone()),
        Place::Cache => podssh_relay::cache::candidate_dirs().into_iter().map(|d| d.join(FILE)).find(|p| p.is_file()),
    }
}

/// The last line of `path`, read from its end.
pub fn last(path: &Path) -> Option<Value> {
    let mut file = open_to_append(path).ok()?;
    own_and_private(path, &file).ok()?;
    let len = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(16 * 1024))).ok()?;
    let mut tail = String::new();
    file.read_to_string(&mut tail).ok()?;
    tail.lines().rev().find_map(|line| serde_json::from_str(line).ok())
}

#[cfg(test)]
#[path = "session_log_tests.rs"]
mod tests;
