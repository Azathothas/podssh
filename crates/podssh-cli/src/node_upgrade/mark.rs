//! A node of `--detach` that takes the signal of an upgrade says so beside
//! its run's record (`detached/NAME.upgrade`, its pid), and `podssh update`
//! asks each such node of this user to take the binary that it put in
//! place (T-668). A node is sent the signal only while its run's lock is
//! held and its record names that pid, as `podssh detached stop` does: the
//! system gives a pid to another process once its own ended.

use std::io::Write;
use std::path::Path;

use crate::detach::lock::{self, Holder};

/// The name of the mark beside a run's record.
fn mark_path(dir: &Path, name: &str) -> std::path::PathBuf {
    dir.join(format!("{name}.upgrade"))
}

/// This process takes the signal of an upgrade: said beside its run's
/// record, when it is a run of `--detach`.
pub fn serving() {
    let (Some(dir), Some(name)) = (lock::dir(), lock::name()) else { return };
    let _ = std::fs::write(mark_path(&dir, name), format!("{}\n", std::process::id()));
}

/// The pid of a node that takes the signal, beside the record `name` in
/// `dir`, while its run's lock is held and its record names that pid; a
/// mark of a run that ended goes.
fn node_of(dir: &Path, name: &str) -> Option<u32> {
    let mark = mark_path(dir, name);
    let pid: u32 = std::fs::read_to_string(&mark).ok()?.trim().parse().ok()?;
    let record = lock::read_record(dir, name)?;
    let held = |path: &Path| matches!(lock::holder(path), Holder::Held(_));
    let by_itself = lock::pid_field(&record, "pid") == Some(pid) && held(&lock::lock_path(dir, name));
    let supervised = lock::pid_field(&record, "run") == Some(pid) && held(&lock::run_lock_path(dir, name));
    let node = record.get("verb").and_then(|v| v.as_str()) == Some("node");
    if !(by_itself || supervised) {
        let _ = std::fs::remove_file(&mark);
        return None;
    }
    node.then_some(pid)
}

/// Each detached node of this user that takes the signal is asked to take
/// the binary now in place, its sessions with it; a line for each.
pub fn ask_each(out: &mut dyn Write) {
    let Some(dir) = lock::dir() else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.strip_suffix(".upgrade").map(str::to_string))
        .collect();
    names.sort();
    for name in names {
        let Some(pid) = node_of(&dir, &name) else { continue };
        let _ = match send(pid) {
            Ok(()) => writeln!(
                out,
                "the node {name} (pid {pid}) takes the new binary, its sessions with it; its log says how it went"
            ),
            Err(why) => writeln!(out, "the node {name} (pid {pid}) was not asked to take the new binary: {why}"),
        };
    }
}

#[cfg(unix)]
fn send(pid: u32) -> Result<(), String> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| format!("pid {pid}"))?;
    // SAFETY: a signal to a process whose run's lock is held and whose
    // record names this pid, as `podssh detached stop` sends one.
    match unsafe { libc::kill(pid, libc::SIGUSR2) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error().to_string()),
    }
}

/// Windows has no such signal: its node goes on with its binary until it
/// starts again, as before.
#[cfg(not(unix))]
fn send(_: u32) -> Result<(), String> {
    Err("this system has no signal of an upgrade: the node goes on with its binary until it starts again".into())
}
