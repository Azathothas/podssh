//! The command that installs a missing program on this host, from the first
//! package manager that a probe finds on PATH (T-590, for the sshd of a
//! roost; T-481 takes the same table for tmux). podssh names the command
//! and runs none: an install changes the host, which the user did not ask
//! for.

use std::ffi::OsString;
use std::path::Path;

/// The package managers in the order that the probe tries them, each with
/// the words that install a package with no question.
const MANAGERS: &[(&str, &str)] = &[
    ("apk", "apk add"),
    ("apt-get", "apt-get install -y"),
    ("dnf", "dnf install -y"),
    ("yum", "yum install -y"),
    ("zypper", "zypper install -y"),
    ("pacman", "pacman -S --noconfirm"),
    ("brew", "brew install"),
    ("pkg", "pkg install -y"),
];

/// A program's package: `default`, but where a manager names it otherwise.
pub struct Package {
    pub default: &'static str,
    pub by_manager: &'static [(&'static str, &'static str)],
}

/// FreeBSD's base has sshd, and its ports name OpenSSH's own release so;
/// Termux's `pkg` names it `openssh`.
#[cfg(target_os = "freebsd")]
const PKG_OPENSSH: &str = "openssh-portable";
#[cfg(not(target_os = "freebsd"))]
const PKG_OPENSSH: &str = "openssh";

/// OpenSSH's server: a package of its own on Debian's, Alpine's and Red
/// Hat's systems; a part of `openssh` on the others.
pub const OPENSSH_SERVER: Package = Package {
    default: "openssh-server",
    by_manager: &[("zypper", "openssh"), ("pacman", "openssh"), ("brew", "openssh"), ("pkg", PKG_OPENSSH)],
};

/// The command that installs `package` with the first manager on `path`,
/// or `None` when the probe found none.
pub fn command(package: &Package, path: Option<&OsString>) -> Option<String> {
    let found = |name: &str| crate::pager::find_program(name, path.cloned());
    let (manager, program) = MANAGERS.iter().find_map(|&(name, _)| found(name).map(|p| (name, p)))?;
    let how = if may_install(&program) {
        How::Own
    } else if found("sudo").is_some() {
        How::Sudo
    } else {
        How::AsRoot
    };
    Some(words(package, manager, how))
}

/// How this user can run the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum How {
    /// As it is: root, or a manager that this user owns.
    Own,
    /// Under sudo, which is on PATH.
    Sudo,
    /// Only as root, with no sudo found.
    AsRoot,
}

/// The words of the command, for `manager` (a name of [`MANAGERS`]).
fn words(package: &Package, manager: &str, how: How) -> String {
    let install = MANAGERS.iter().find(|(name, _)| *name == manager).map_or(manager, |(_, words)| *words);
    let name = package.by_manager.iter().find(|(m, _)| *m == manager).map_or(package.default, |(_, n)| *n);
    match how {
        How::Own => format!("{install} {name}"),
        // Homebrew refuses to run as root, and so under sudo.
        How::Sudo | How::AsRoot if manager == "brew" => format!("{install} {name}"),
        How::Sudo => format!("sudo {install} {name}"),
        How::AsRoot => format!("{install} {name} (as root)"),
    }
}

/// Whether this user can run the manager at `program` with no sudo: root,
/// or a manager whose file is this user's own, as Homebrew's and Termux's
/// are. Probed, never assumed from the name.
#[cfg(unix)]
fn may_install(program: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    uid == 0 || program.metadata().is_ok_and(|m| m.uid() == uid)
}

#[cfg(not(unix))]
fn may_install(_program: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_manager_has_its_words_and_its_name_of_the_package() {
        let sshd = |manager| words(&OPENSSH_SERVER, manager, How::Own);
        assert_eq!(sshd("apk"), "apk add openssh-server");
        assert_eq!(sshd("apt-get"), "apt-get install -y openssh-server");
        assert_eq!(sshd("dnf"), "dnf install -y openssh-server");
        assert_eq!(sshd("yum"), "yum install -y openssh-server");
        assert_eq!(sshd("zypper"), "zypper install -y openssh");
        assert_eq!(sshd("pacman"), "pacman -S --noconfirm openssh");
        assert_eq!(sshd("brew"), "brew install openssh");
        assert_eq!(sshd("pkg"), format!("pkg install -y {PKG_OPENSSH}"));
    }

    #[test]
    fn a_user_that_is_not_root_gets_sudo_or_is_told_to_be_root() {
        assert_eq!(words(&OPENSSH_SERVER, "apt-get", How::Sudo), "sudo apt-get install -y openssh-server");
        assert_eq!(words(&OPENSSH_SERVER, "dnf", How::AsRoot), "dnf install -y openssh-server (as root)");
        // Homebrew runs as its user, never under sudo.
        assert_eq!(words(&OPENSSH_SERVER, "brew", How::Sudo), "brew install openssh");
        assert_eq!(words(&OPENSSH_SERVER, "brew", How::AsRoot), "brew install openssh");
    }

    /// A directory of the test's own, with an empty runnable file for each
    /// name: the managers that the probe should find.
    #[cfg(unix)]
    fn path_with(names: &[&str]) -> (std::path::PathBuf, OsString) {
        use std::os::unix::fs::PermissionsExt;
        // The count tells apart two calls that read the same clock.
        static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("podssh-install-hint-{}-{call}-{nanos}", std::process::id()));
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
    fn the_first_manager_on_path_wins_and_none_gives_nothing() {
        let (dir, path) = path_with(&["pacman", "dnf"]);
        // The test owns the stand-ins, so no sudo comes before them.
        assert_eq!(command(&OPENSSH_SERVER, Some(&path)).as_deref(), Some("dnf install -y openssh-server"));
        std::fs::remove_dir_all(&dir).unwrap();
        let (dir, path) = path_with(&["sudo"]);
        assert_eq!(command(&OPENSSH_SERVER, Some(&path)), None);
        assert_eq!(command(&OPENSSH_SERVER, None), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
