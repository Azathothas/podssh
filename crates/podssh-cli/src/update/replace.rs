//! The new binary in place of the running one (T-375): written beside it,
//! in its directory, so that a rename moves it; its mode copied; run once
//! there, with `--version`, so that a file that does not start on this host
//! never takes the old one's place (T-396, `trial`); then renamed over the
//! running file, which keeps running from the old inode, while the old file
//! stays as `podssh.prev` (`keep`). Windows refuses to write over a running
//! program and allows its rename, so there the running file is renamed to
//! `podssh.prev.exe` first, else to `podssh.exe.old`, which a later run
//! removes. A failure at any step leaves the old binary as it was, and
//! removes what this step wrote.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::keep;

/// The path of the running binary, through its links: the file that the
/// update replaces. Linux names the file of a binary that an update
/// replaced while it ran `PATH (deleted)`: its path is still the file.
pub fn running() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("the path of this binary: {e}"))?;
    fs::canonicalize(&exe).or_else(|e| {
        let text = exe.to_string_lossy();
        match text.strip_suffix(" (deleted)") {
            Some(path) => fs::canonicalize(path).map_err(|e| format!("{path}: {e}")),
            None => Err(format!("{}: {e}", exe.display())),
        }
    })
}

/// `path` as a user reads it: on Windows without the `\\?\` that the
/// canonical form of a path on a drive begins with.
pub fn shown(path: &Path) -> String {
    let text = path.display().to_string();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_string(),
        _ => text,
    }
}

/// Where a running binary is moved on Windows when its kept place refuses
/// it: `podssh.exe.old`.
pub fn aside(exe: &Path) -> PathBuf {
    let mut name = exe.as_os_str().to_owned();
    name.push(".old");
    PathBuf::from(name)
}

/// The old binary that an update on Windows moved aside, removed once it
/// runs no more: at the start of each run, and at no cost when there is
/// none. Elsewhere there is never one. The kept one, `podssh.prev.exe`,
/// stays.
pub fn remove_aside() {
    if cfg!(windows) {
        if let Ok(exe) = running() {
            let _ = fs::remove_file(aside(&exe));
        }
    }
}

/// A temporary name beside `exe` for the step `what`, which no other run
/// takes: `.podssh.update-RANDOM`, and `.exe` after it where `exe` has it,
/// so that Windows runs it as a program.
pub fn beside(exe: &Path, what: &str) -> Result<PathBuf, String> {
    let dir = exe.parent().ok_or_else(|| format!("{} has no directory", exe.display()))?;
    let (stem, ext) = name_parts(exe);
    Ok(dir.join(format!(".{stem}.{what}-{:016x}{ext}", rand::random::<u64>())))
}

/// `exe`'s name without `.exe`, and `.exe` when it has it: a dot in another
/// name, as in `podssh-1.0.0`, is no extension of a program.
pub fn name_parts(exe: &Path) -> (String, &'static str) {
    let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "podssh".into());
    let is_exe = exe.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe"));
    match (is_exe, exe.file_stem()) {
        (true, Some(stem)) => (stem.to_string_lossy().into_owned(), ".exe"),
        _ => (name, ""),
    }
}

/// `bytes` in a new file at `path`, on the disk before this returns.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// What a replacement did.
#[derive(Debug)]
pub struct Replaced {
    /// What the new binary said when it ran here.
    pub said: String,
    /// Where the binary before it is kept, or why it is not.
    pub prev: Result<PathBuf, String>,
}

/// Why a replacement stopped, the old binary as it was.
#[derive(Debug)]
pub enum Stopped {
    /// The new file did not run here, or named another version.
    Trial(String),
    /// A step of the disk failed.
    Disk(String),
}

/// The file at `exe` becomes `bytes`, with `exe`'s mode, once `trial`
/// passed on the new file; the file before it is kept beside it.
pub fn replace(exe: &Path, bytes: &[u8], trial: &dyn Fn(&Path) -> Result<String, String>) -> Result<Replaced, Stopped> {
    let old = fs::metadata(exe).map_err(|e| Stopped::Disk(format!("{}: {e}", exe.display())))?;
    let temp = beside(exe, "update").map_err(Stopped::Disk)?;
    let dir = temp.parent().map(Path::to_path_buf).unwrap_or_default();
    write_new(&temp, bytes).map_err(|e| {
        let _ = fs::remove_file(&temp);
        Stopped::Disk(format!("a new file in {}: {e}", dir.display()))
    })?;
    let undo = |why: String| {
        let _ = fs::remove_file(&temp);
        why
    };
    #[cfg(unix)]
    fs::set_permissions(&temp, old.permissions())
        .map_err(|e| Stopped::Disk(undo(format!("the mode of {}: {e}", temp.display()))))?;
    #[cfg(not(unix))]
    let _ = old;
    // Run where it will run, before anything of the old one moves.
    let said = trial(&temp).map_err(|why| Stopped::Trial(undo(why)))?;
    let prev = keep::prev_of(exe);
    let kept = if cfg!(windows) {
        let _ = fs::remove_file(&prev);
        let (moved, kept) = match fs::rename(exe, &prev) {
            Ok(()) => (prev.clone(), Ok(prev.clone())),
            // A kept binary that runs, as a supervisor may start one, stays.
            Err(e) => {
                let moved = aside(exe);
                let _ = fs::remove_file(&moved);
                fs::rename(exe, &moved).map_err(|e| Stopped::Disk(undo(format!("{} aside: {e}", exe.display()))))?;
                (moved, Err(format!("{}: {e}", shown(&prev))))
            }
        };
        if let Err(e) = fs::rename(&temp, exe) {
            let _ = fs::rename(&moved, exe);
            return Err(Stopped::Disk(undo(format!("{}: {e}", exe.display()))));
        }
        kept
    } else {
        // Before the rename, which unlinks the old file.
        let kept = keep::keep(exe, &prev);
        fs::rename(&temp, exe).map_err(|e| Stopped::Disk(undo(format!("{}: {e}", exe.display()))))?;
        kept
    };
    keep::sync_dir(exe);
    Ok(Replaced { said, prev: kept })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("podssh-replace-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn passes(_: &Path) -> Result<String, String> {
        Ok("podssh 9.9.9".into())
    }

    #[test]
    fn the_file_becomes_the_new_bytes_with_its_mode_and_the_old_one_is_kept_beside_it() {
        let dir = scratch("ok");
        let exe = dir.join(if cfg!(windows) { "podssh.exe" } else { "podssh" });
        fs::write(&exe, b"old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o751)).unwrap();
        }
        #[cfg(unix)]
        let inode = std::os::unix::fs::MetadataExt::ino(&fs::metadata(&exe).unwrap());
        let replaced = replace(&exe, b"new", &passes).unwrap();
        assert_eq!(replaced.said, "podssh 9.9.9");
        assert_eq!(fs::read(&exe).unwrap(), b"new");
        let prev = replaced.prev.unwrap();
        assert_eq!(prev, dir.join(if cfg!(windows) { "podssh.prev.exe" } else { "podssh.prev" }));
        assert_eq!(fs::read(&prev).unwrap(), b"old");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let now = fs::metadata(&exe).unwrap();
            assert_eq!(now.permissions().mode() & 0o777, 0o751);
            // A new file renamed over the old one: a running binary keeps its
            // own, where a write in place would change the program it runs.
            assert_ne!(now.ino(), inode, "the binary was written in place");
        }
        let left: Vec<_> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left.len(), 2, "the binary and the one before it: {left:?}");
        // Again: the kept one is the one before the last update.
        replace(&exe, b"newer", &passes).unwrap();
        assert_eq!(fs::read(&prev).unwrap(), b"new");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A new file that its trial refuses never takes the old one's place,
    /// and leaves nothing beside it, no kept one either.
    #[test]
    fn a_new_file_that_its_trial_refuses_leaves_the_old_binary_alone() {
        let dir = scratch("trial");
        let exe = dir.join("podssh");
        fs::write(&exe, b"old").unwrap();
        let refused = |_: &Path| -> Result<String, String> { Err("it ended with exit status: 1".to_string()) };
        match replace(&exe, b"new", &refused) {
            Err(Stopped::Trial(why)) => assert!(why.contains("exit status: 1"), "{why}"),
            other => panic!("refused by its trial, not {other:?}"),
        }
        assert_eq!(fs::read(&exe).unwrap(), b"old");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_is_shown_without_the_prefix_of_a_canonical_drive_path() {
        assert_eq!(shown(Path::new(r"\\?\D:\a\podssh.exe")), r"D:\a\podssh.exe");
        assert_eq!(shown(Path::new(r"\\?\UNC\host\share\podssh.exe")), r"\\?\UNC\host\share\podssh.exe");
        assert_eq!(shown(Path::new("/usr/local/bin/podssh")), "/usr/local/bin/podssh");
    }

    #[test]
    fn the_kept_and_the_temporary_names_keep_the_extension() {
        assert_eq!(keep::prev_of(Path::new("/b/podssh")), Path::new("/b/podssh.prev"));
        assert_eq!(keep::prev_of(Path::new("/b/podssh.exe")), Path::new("/b/podssh.prev.exe"));
        assert_eq!(keep::prev_of(Path::new("/b/podssh-1.0.0")), Path::new("/b/podssh-1.0.0.prev"));
        for (exe, ext) in [("/b/podssh.exe", true), ("/b/podssh", false)] {
            let temp = beside(Path::new(exe), "update").unwrap();
            assert_eq!(temp.parent(), Some(Path::new("/b")));
            let name = temp.file_name().unwrap().to_string_lossy().into_owned();
            assert!(name.starts_with(".podssh.update-") && name.ends_with(".exe") == ext, "{name}");
        }
    }

    #[test]
    fn a_binary_that_is_not_there_is_left_alone_and_nothing_is_written() {
        let dir = scratch("gone");
        let exe = dir.join("podssh");
        match replace(&exe, b"new", &passes) {
            Err(Stopped::Disk(why)) => assert!(why.contains("podssh"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A directory that refuses a new file leaves the old binary as it was.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_refuses_a_new_file_leaves_the_old_binary() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("refused");
        let exe = dir.join("podssh");
        fs::write(&exe, b"old").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let result = replace(&exe, b"new", &passes);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        // root writes in any directory: the check holds where it can.
        if let Err(Stopped::Disk(why)) = result {
            assert!(why.contains("a new file in"), "{why}");
            assert_eq!(fs::read(&exe).unwrap(), b"old");
            assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
