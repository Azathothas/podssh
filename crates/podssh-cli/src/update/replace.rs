//! The new binary in place of the running one (T-375): written beside it,
//! in its directory, so that a rename moves it; its mode copied; then
//! renamed over the running file, which keeps running from the old inode.
//! Windows refuses to write over a running program and allows its rename,
//! so there the running file is renamed aside first, and a later run removes
//! it. A failure at any step leaves the old binary as it was, and removes
//! what this step wrote.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The path of the running binary, through its links: the file that the
/// update replaces.
pub fn running() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("the path of this binary: {e}"))?;
    fs::canonicalize(&exe).map_err(|e| format!("{}: {e}", exe.display()))
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

/// Where a running binary is moved on Windows: `podssh.exe.old`.
pub fn aside(exe: &Path) -> PathBuf {
    let mut name = exe.as_os_str().to_owned();
    name.push(".old");
    PathBuf::from(name)
}

/// The old binary that an update on Windows moved aside, removed once it
/// runs no more: at the start of each run, and at no cost when there is
/// none. Elsewhere there is never one.
pub fn remove_aside() {
    if cfg!(windows) {
        if let Ok(exe) = running() {
            let _ = fs::remove_file(aside(&exe));
        }
    }
}

/// A temporary name beside `exe`, which no other run takes.
fn beside(exe: &Path) -> Result<PathBuf, String> {
    let dir = exe.parent().ok_or_else(|| format!("{} has no directory", exe.display()))?;
    let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "podssh".into());
    Ok(dir.join(format!(".{name}.update-{:016x}", rand::random::<u64>())))
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

/// The file at `exe` becomes `bytes`, with `exe`'s mode.
pub fn replace(exe: &Path, bytes: &[u8]) -> Result<(), String> {
    let old = fs::metadata(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    let temp = beside(exe)?;
    let dir = temp.parent().map(Path::to_path_buf).unwrap_or_default();
    write_new(&temp, bytes).map_err(|e| {
        let _ = fs::remove_file(&temp);
        format!("a new file in {}: {e}", dir.display())
    })?;
    let undo = |why: String| {
        let _ = fs::remove_file(&temp);
        why
    };
    #[cfg(unix)]
    fs::set_permissions(&temp, old.permissions()).map_err(|e| undo(format!("the mode of {}: {e}", temp.display())))?;
    #[cfg(not(unix))]
    let _ = old;
    if cfg!(windows) {
        let moved = aside(exe);
        let _ = fs::remove_file(&moved);
        fs::rename(exe, &moved).map_err(|e| undo(format!("{} aside: {e}", exe.display())))?;
        if let Err(e) = fs::rename(&temp, exe) {
            let _ = fs::rename(&moved, exe);
            return Err(undo(format!("{}: {e}", exe.display())));
        }
    } else {
        fs::rename(&temp, exe).map_err(|e| undo(format!("{}: {e}", exe.display())))?;
    }
    // The rename itself on the disk, where the system allows a directory
    // to be opened; it is in place either way.
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(&dir) {
        let _ = dir.sync_all();
    }
    Ok(())
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

    #[test]
    fn the_file_becomes_the_new_bytes_with_its_mode_and_nothing_is_left_beside_it() {
        let dir = scratch("ok");
        let exe = dir.join("podssh");
        fs::write(&exe, b"old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o751)).unwrap();
        }
        #[cfg(unix)]
        let inode = std::os::unix::fs::MetadataExt::ino(&fs::metadata(&exe).unwrap());
        replace(&exe, b"new").unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"new");
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
        let expected = if cfg!(windows) { 2 } else { 1 };
        assert_eq!(left.len(), expected, "{left:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_is_shown_without_the_prefix_of_a_canonical_drive_path() {
        assert_eq!(shown(Path::new(r"\\?\D:\a\podssh.exe")), r"D:\a\podssh.exe");
        assert_eq!(shown(Path::new(r"\\?\UNC\host\share\podssh.exe")), r"\\?\UNC\host\share\podssh.exe");
        assert_eq!(shown(Path::new("/usr/local/bin/podssh")), "/usr/local/bin/podssh");
    }

    #[test]
    fn a_binary_that_is_not_there_is_left_alone_and_nothing_is_written() {
        let dir = scratch("gone");
        let exe = dir.join("podssh");
        assert!(replace(&exe, b"new").unwrap_err().contains("podssh"));
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
        let result = replace(&exe, b"new");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        // root writes in any directory: the check holds where it can.
        if let Err(why) = result {
            assert!(why.contains("a new file in"), "{why}");
            assert_eq!(fs::read(&exe).unwrap(), b"old");
            assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
