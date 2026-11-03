//! What a far host that lacks a tool has that could install it (T-481): one
//! probe in sh finds the first package manager on its PATH, the `ID=` of
//! its `/etc/os-release`, and who may install there. The command is
//! podssh-cli's to name (`install_hint`, whose list of managers this
//! probe's is, as a test there holds); nothing here runs it, as an install
//! changes the host, which the user did not ask for.

use crate::exec::shell_word;

/// The managers that the probe looks for, in its order.
pub const MANAGERS: &str = "apk apt-get dnf yum zypper pacman brew pkg";

/// Who may install on the far host, as the probe found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    /// The login is root.
    Root,
    /// The login owns the manager's file, as Homebrew's and Termux's are.
    Own,
    /// The login is not root, and `sudo` is on its PATH.
    Sudo,
    /// The login is not root, and has no `sudo`.
    User,
}

/// What a probe found on a host that lacks a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The first manager of [`MANAGERS`] on PATH.
    pub manager: Option<String>,
    /// The `ID=` of `/etc/os-release`, without its quotes.
    pub system: Option<String>,
    pub who: Who,
}

impl Found {
    /// The words `PM ID WHO` of a probe, each `-` when unknown; `None` for
    /// words of another form. A manager that is not in the list, or an ID
    /// with a character that no ID has, is unknown.
    pub fn parse(words: &str) -> Option<Found> {
        let mut it = words.split_whitespace();
        let (pm, id, who) = (it.next()?, it.next()?, it.next()?);
        if it.next().is_some() {
            return None;
        }
        let who = match who {
            "root" => Who::Root,
            "own" => Who::Own,
            "sudo" => Who::Sudo,
            "user" => Who::User,
            _ => return None,
        };
        let manager = MANAGERS.split(' ').find(|name| *name == pm).map(str::to_string);
        let id = id.trim_matches(['"', '\'']);
        let plain = !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        let system = (plain && id != "-").then(|| id.to_string());
        Some(Found { manager, system, who })
    }

    /// Whether the login may run the manager as it is: root, or its owner.
    pub fn may_install(&self) -> bool {
        matches!(self.who, Who::Root | Who::Own)
    }
}

/// The probe, for the login shell: `sh -c 'SCRIPT' sh TOOL`. It exits 0
/// with nothing printed when TOOL is on PATH; else it prints `missing TOOL
/// PM ID WHO` and exits 1. One line, with no single quote and no backslash,
/// so that each login shell (fish and csh too) gives it to sh whole. `id
/// -u` gives the user, else the effective UID of `/proc/self/status`, which
/// the shell itself opens.
pub fn probe(tool: &str) -> Option<String> {
    Some(format!("sh -c {} sh {}", shell_word(&script())?, shell_word(tool)?))
}

/// The script of [`probe`], which reads TOOL as `$1`: also the end of a
/// script that asks more in the same sh (`health --preflight`, T-482).
pub fn script() -> String {
    format!(
        "command -v \"$1\" >/dev/null 2>&1 && exit 0; pm=-; for p in {MANAGERS}; do if command -v \"$p\" \
         >/dev/null 2>&1; then pm=$p; break; fi; done; os=-; if [ -r /etc/os-release ]; then while IFS= read -r \
         l; do case $l in ID=*) os=${{l#ID=}};; esac; done </etc/os-release; fi; u=; if command -v id >/dev/null \
         2>&1; then u=$(id -u 2>/dev/null); fi; if [ -z \"$u\" ] && [ -r /proc/self/status ]; then while read -r \
         f _ y _; do if [ \"$f\" = Uid: ]; then u=$y; fi; done </proc/self/status; fi; w=user; if [ \"$u\" = 0 ]; \
         then w=root; elif [ \"$pm\" != - ] && [ -O \"$(command -v \"$pm\")\" ] 2>/dev/null; then w=own; elif \
         command -v sudo >/dev/null 2>&1; then w=sudo; fi; echo \"missing $1 $pm $os $w\"; exit 1"
    )
}

/// What a probe of `tool` said, from its stdout: the last line `missing
/// TOOL PM ID WHO`; `None` when no such line came, as from a host whose
/// login gave no sh.
pub fn read(stdout: &[u8], tool: &str) -> Option<Found> {
    let head = format!("missing {tool} ");
    let text = String::from_utf8_lossy(stdout);
    text.lines().rev().find_map(|line| line.trim_end().strip_prefix(head.as_str()).and_then(Found::parse))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(pm: &str, id: &str, who: &str) -> Found {
        Found::parse(&format!("{pm} {id} {who}")).expect("the words of a probe")
    }

    #[test]
    fn the_words_of_a_probe_are_read_whole_or_not_at_all() {
        let f = found("yum", "'rhel'", "root");
        assert_eq!((f.manager.as_deref(), f.system.as_deref(), f.who), (Some("yum"), Some("rhel"), Who::Root));
        assert_eq!(found("dnf", "\"fedora\"", "user").system.as_deref(), Some("fedora"));
        assert_eq!(found("apk", "a;b", "root").system, None, "an ID with odd characters is unknown");
        assert_eq!(found("emerge", "gentoo", "root").manager, None, "a manager that is not in the list");
        assert!(found("brew", "-", "own").may_install() && !found("apt-get", "-", "sudo").may_install());
        for bad in ["apk alpine", "apk alpine root extra", "apk alpine admin"] {
            assert_eq!(Found::parse(bad), None, "{bad}");
        }
        let out = b"motd\nmissing tmux apk alpine user\n";
        assert_eq!(read(out, "tmux"), Some(found("apk", "alpine", "user")));
        assert_eq!(read(b"sh: not found\n", "tmux"), None);
        assert_eq!(read(b"missing screen apk alpine user\n", "tmux"), None);
    }

    /// The probe goes through each login shell whole: one line, no single
    /// quote and no backslash in its script, and each manager in order.
    #[test]
    fn the_probe_is_one_quoted_line_that_looks_for_each_manager() {
        let probe = probe("tmux").unwrap();
        assert!(probe.starts_with("sh -c '") && probe.ends_with("' sh 'tmux'"), "{probe}");
        let script = &probe["sh -c '".len()..probe.len() - "' sh 'tmux'".len()];
        assert!(!script.contains(['\'', '\\', '\n']), "{script}");
        assert!(script.contains(&format!("for p in {MANAGERS}; do")), "{script}");
        assert!(script.contains("echo \"missing $1 $pm $os $w\"; exit 1"), "{script}");
    }
}
