//! Whether this host has an sshd, for a roost whose TARGET on the loopback
//! refused its dial, and for doctor's line `sshd` (T-590): sshd is the one
//! part of the reverse road that podssh does not bring, and the part that a
//! minimal image lacks. A look at PATH and the usual places, never assumed;
//! nothing is run or installed.

use std::ffi::OsString;
use std::path::PathBuf;

/// sshd's file name here.
const PROGRAM: &str = if cfg!(windows) { "sshd.exe" } else { "sshd" };

/// What the look found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// An sshd at this path.
    At(PathBuf),
    /// None; the command that installs one, when a probe found how.
    Absent(Option<String>),
}

/// Where a package puts sshd, looked in after PATH: a user's PATH often
/// lacks the sbin directories that hold it.
pub fn places() -> Vec<PathBuf> {
    if cfg!(windows) {
        // The OpenSSH server of Windows, an optional feature of the system.
        let root = std::env::var_os("SystemRoot").filter(|v| !v.is_empty());
        let root = root.map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        vec![root.join("System32").join("OpenSSH")]
    } else {
        ["/usr/sbin", "/usr/local/sbin", "/sbin"].map(PathBuf::from).to_vec()
    }
}

/// The look: sshd on `path` first, then in `places`; with none, the command
/// that installs one.
pub fn look(path: Option<OsString>, places: &[PathBuf]) -> Found {
    let on_path = crate::pager::find_program(PROGRAM, path.clone());
    let placed = || crate::pager::find_program(PROGRAM, std::env::join_paths(places).ok());
    match on_path.or_else(placed) {
        Some(at) => Found::At(at),
        None => Found::Absent(install(path.as_ref())),
    }
}

/// The command that installs an sshd: the package manager's, else, on
/// Windows, the system's own feature.
fn install(path: Option<&OsString>) -> Option<String> {
    let managed = crate::install_hint::command(&crate::install_hint::OPENSSH_SERVER, path);
    managed.or_else(|| {
        cfg!(windows).then(|| {
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0, in a PowerShell run as administrator"
                .to_string()
        })
    })
}

/// Where the look searched, for the words: "none on PATH or in ...".
pub fn searched(places: &[PathBuf]) -> String {
    let dirs: Vec<String> = places.iter().map(|p| p.display().to_string()).collect();
    format!("none on PATH or in {}", dirs.join(", "))
}

/// For a roost: what the look says of a TARGET on the loopback, `target`,
/// where nothing listens.
pub fn nothing_listens(target: &str, found: &Found, places: &[PathBuf]) -> String {
    match found {
        Found::At(at) => format!(
            "an sshd is installed at {}, and nothing listens at {target}: start it, or give the port that it \
             listens on",
            at.display()
        ),
        Found::Absent(Some(command)) => {
            format!("no sshd is installed on this host ({}); install one, as {command}, and start it", searched(places))
        }
        Found::Absent(None) => format!(
            "no sshd is installed on this host ({}), and no package manager was found on PATH; install an SSH \
             server, as OpenSSH's sshd, and start it",
            searched(places)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of the test's own with an empty runnable file for each
    /// name; and that directory as a PATH.
    #[cfg(unix)]
    fn dir_with(names: &[&str]) -> (PathBuf, OsString) {
        use std::os::unix::fs::PermissionsExt;
        // The count tells apart two calls that read the same clock.
        static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("podssh-local-sshd-{}-{call}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in names {
            let file = dir.join(name);
            std::fs::write(&file, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = OsString::from(dir.as_os_str());
        (dir, path)
    }

    #[cfg(unix)]
    #[test]
    fn path_comes_first_then_the_places_and_with_none_the_command() {
        let (bin, path) = dir_with(&["sshd"]);
        let (sbin, _) = dir_with(&["sshd"]);
        assert_eq!(look(Some(path), std::slice::from_ref(&sbin)), Found::At(bin.join("sshd")));
        let (tools, path) = dir_with(&["apt-get"]);
        assert_eq!(look(Some(path.clone()), std::slice::from_ref(&sbin)), Found::At(sbin.join("sshd")));
        let (empty, _) = dir_with(&[]);
        let absent = Found::Absent(Some("apt-get install -y openssh-server".into()));
        assert_eq!(look(Some(path), std::slice::from_ref(&empty)), absent);
        for dir in [bin, sbin, tools, empty] {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn the_words_name_the_sshd_or_what_installs_one() {
        let places = [PathBuf::from("/usr/sbin"), PathBuf::from("/sbin")];
        let at = nothing_listens("127.0.0.1:2222", &Found::At("/usr/sbin/sshd".into()), &places);
        assert_eq!(
            at,
            "an sshd is installed at /usr/sbin/sshd, and nothing listens at 127.0.0.1:2222: start it, or give the \
             port that it listens on"
        );
        let absent = Found::Absent(Some("apt-get install -y openssh-server".into()));
        assert_eq!(
            nothing_listens("127.0.0.1:2222", &absent, &places),
            "no sshd is installed on this host (none on PATH or in /usr/sbin, /sbin); install one, as apt-get \
             install -y openssh-server, and start it"
        );
        let unknown = nothing_listens("127.0.0.1:2222", &Found::Absent(None), &places);
        assert!(unknown.contains("no package manager was found on PATH"), "{unknown}");
    }
}
