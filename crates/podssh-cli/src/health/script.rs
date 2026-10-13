//! The one command of `podssh health` (T-189) on the far host: a fixed
//! script, run as `sh -c 'SCRIPT' sh`, so that a login shell of fish or csh
//! only starts `sh`. It reads `/proc` with the shell's own `read`, and runs
//! `sleep`, `df` and `uname` only where `command -v` finds them: a host with
//! none of them still gives its facts. No text of the user goes into it.
//!
//! The answer is a first line, [`MARK`], then sections, each a line
//! `@ NAME` and the lines of what it read, and a last line `@ end`: the
//! files `loadavg`, `uptime`, `meminfo`, `stat` and `net/dev` of `/proc`,
//! the count of processes, after `sleep 1` a second `stat`, `uptime` and
//! `net/dev`, then `df -P -k` of `/` and of the home. A host with no `/proc`
//! gives the section `system`, with what `uname -s` printed.

use std::time::Duration;

/// The first line of the answer, with the number of its form.
pub const MARK: &str = "podssh-health 1";

/// The script: one line with no single quote, no `!` and no line break, as
/// each login shell reads `sh -c '...'` the same way then.
pub const SCRIPT: &str = concat!(
    "printf \"%s\\n\" \"podssh-health 1\"; ",
    "p() { [ -r \"/proc/$2\" ] || return 0; printf \"%s\\n\" \"@ $1\"; ",
    "while IFS= read -r l || [ -n \"$l\" ]; do printf \"%s\\n\" \"$l\"; done < \"/proc/$2\"; }; ",
    "if [ -r /proc/meminfo ]; then ",
    "p loadavg loadavg; p uptime uptime; p meminfo meminfo; p stat stat; p net/dev net/dev; ",
    "set -- /proc/[0-9]*; printf \"%s\\n\" \"@ processes\" \"$#\"; ",
    "if command -v sleep >/dev/null 2>&1 && sleep 1; then ",
    "p \"stat 2\" stat; p \"uptime 2\" uptime; p \"net/dev 2\" net/dev; fi; ",
    "if command -v df >/dev/null 2>&1; then ",
    "printf \"%s\\n\" \"@ df\"; df -P -k / ${HOME:+\"$HOME\"} 2>/dev/null; fi; ",
    "else printf \"%s\\n\" \"@ system\"; command -v uname >/dev/null 2>&1 && uname -s; fi; ",
    "printf \"%s\\n\" \"@ end\"",
);

/// How long the script may run, `sleep 1` and a slow `df` included.
pub const LIMIT: Duration = Duration::from_secs(30);

/// The bytes of the answer that are read: a host with a hundred interfaces
/// and as many CPUs writes some tens of KiB.
pub const CAP: usize = 1024 * 1024;

/// The command line that the server's login shell gets.
pub fn command() -> String {
    format!("sh -c '{SCRIPT}' sh")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each login shell reads the script as one word in single quotes: no
    /// quote ends it early, no line break splits it for csh, and no `!`
    /// meets the history of csh or bash.
    #[test]
    fn the_script_is_one_quoted_word_for_each_shell() {
        assert!(!SCRIPT.contains(['\'', '\n', '\r', '!']), "{SCRIPT}");
        assert!(SCRIPT.starts_with(&format!("printf \"%s\\n\" \"{MARK}\"; ")), "{SCRIPT}");
        assert!(SCRIPT.ends_with("printf \"%s\\n\" \"@ end\""), "{SCRIPT}");
        assert_eq!(command(), format!("sh -c '{SCRIPT}' sh"));
    }

    /// The tools that a host may lack run only where `command -v` finds
    /// them, and the files of `/proc` only where they can be read.
    #[test]
    fn each_tool_is_probed_before_it_runs() {
        for tool in ["sleep", "df", "uname"] {
            let probe = format!("command -v {tool} >/dev/null 2>&1");
            let at = SCRIPT.find(&probe).unwrap_or_else(|| panic!("{tool} is not probed"));
            let first_use = SCRIPT.find(&format!("{tool} -")).or_else(|| SCRIPT.find(&format!("{tool} 1")));
            assert!(first_use.is_some_and(|use_at| use_at > at), "{tool} runs before its probe");
        }
        assert!(SCRIPT.contains("[ -r \"/proc/$2\" ] || return 0"), "{SCRIPT}");
    }
}
