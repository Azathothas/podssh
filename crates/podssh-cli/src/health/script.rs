//! The one command of `podssh health` (T-189) on the far host: a fixed
//! script, run as `sh -c 'SCRIPT' sh`, so that a login shell of fish or csh
//! only starts `sh`. It reads `/proc` with the shell's own `read`, and runs
//! `sleep`, `df` and `uname` only where `command -v` finds them: a host with
//! none of them still gives its facts. No text of the user goes into it.
//!
//! The answer is a first line, [`MARK`], then sections, each a line
//! `@ NAME` and the lines of what it read, and a last line `@ end`: the
//! files `loadavg`, `uptime`, `meminfo`, `stat` and `net/dev` of `/proc`,
//! the count of processes, the cgroup of its own shell (T-480), after
//! `sleep 1` a second `stat`, `uptime`, `net/dev` and the cgroup's use of the
//! CPUs, then `df -P -k` of `/` and of the home. A host with no `/proc` gives
//! the section `system`, with what `uname -s` printed.
//!
//! The section `cgroup` holds a line for each line of each file, after its
//! key: `self` for `/proc/self/cgroup`; `v2 DIR`, the directory of cgroup v2
//! read, then its files and, as `upN FILE`, the limits of each parent up to
//! the mount's root, as a limit there binds too; or `v1 CONTROLLER DIR` for
//! each hierarchy of cgroup v1, then its files. A cgroup namespace shows the
//! container's own cgroup as `/`, and a container of cgroup v1 has its own
//! at the root of each mount, so a path that is not there is read at the
//! root (the kernel's cgroup-v2.rst, "Namespace"). Of `memory.stat` only the
//! lines that the reader takes come.

use std::time::Duration;

/// The first line of the answer, with the number of its form: a reader
/// takes each section by its name, so a new section keeps the number.
pub const MARK: &str = "podssh-health 1";

/// The script: one line with no single quote, no `!` and no line break, as
/// each login shell reads `sh -c '...'` the same way then.
pub const SCRIPT: &str = concat!(
    "printf \"%s\\n\" \"podssh-health 1\"; ",
    "p() { [ -r \"/proc/$2\" ] || return 0; printf \"%s\\n\" \"@ $1\"; ",
    "while IFS= read -r l || [ -n \"$l\" ]; do printf \"%s\\n\" \"$l\"; done < \"/proc/$2\"; }; ",
    // A file of the cgroup, each line after its key.
    "g() { [ -r \"$2\" ] || return 0; ",
    "while IFS= read -r l || [ -n \"$l\" ]; do printf \"%s\\n\" \"$1 $l\"; done < \"$2\"; }; ",
    // Of memory.stat, the cache that the kernel takes back first, and v1's
    // limit of the hierarchy.
    "s() { [ -r \"$2\" ] || return 0; while read -r x y || [ -n \"$x\" ]; do case $x in ",
    "inactive_file|total_inactive_file|hierarchical_memory_limit) printf \"%s\\n\" \"$1 $x $y\";; esac; ",
    "done < \"$2\"; }; ",
    // cgroup v1: the directory of a controller, at the path that
    // /proc/self/cgroup gives it, else at the root of its mount.
    "w() { r=; while IFS=: read -r n c q; do case \",$c,\" in *,$1,*) r=$q;; esac; done < /proc/self/cgroup; ",
    "d=/sys/fs/cgroup/$1$r; [ -d \"$d\" ] || d=/sys/fs/cgroup/$1; printf \"%s\\n\" \"v1 $1 $d\"; }; ",
    "u=; ",
    "if [ -r /proc/meminfo ]; then ",
    "p loadavg loadavg; p uptime uptime; p meminfo meminfo; p stat stat; p net/dev net/dev; ",
    "set -- /proc/[0-9]*; printf \"%s\\n\" \"@ processes\" \"$#\"; ",
    "if [ -r /proc/self/cgroup ]; then printf \"%s\\n\" \"@ cgroup\"; g self /proc/self/cgroup; ",
    "if [ -r /sys/fs/cgroup/cgroup.controllers ]; then ",
    "r=; while IFS=: read -r n c q; do [ \"$n\" = 0 ] && r=$q; done < /proc/self/cgroup; ",
    "d=/sys/fs/cgroup$r; [ -r \"$d/cgroup.controllers\" ] || d=/sys/fs/cgroup; printf \"%s\\n\" \"v2 $d\"; ",
    "for f in memory.max memory.current memory.swap.max cpu.max cpuset.cpus.effective cpu.stat io.max ",
    "pids.max pids.current cpu.pressure memory.pressure; do g $f \"$d/$f\"; done; s memory.stat \"$d/memory.stat\"; ",
    "u=$d/cpu.stat; k=cpu.stat; a=$d; i=0; ",
    "while :; do a=${a%/*}; case $a in /sys/fs/cgroup/?*) ;; *) break;; esac; i=$((i+1)); ",
    "g \"up$i memory.max\" \"$a/memory.max\"; g \"up$i memory.current\" \"$a/memory.current\"; ",
    "s \"up$i memory.stat\" \"$a/memory.stat\"; g \"up$i cpu.max\" \"$a/cpu.max\"; done; ",
    "elif [ -d /sys/fs/cgroup/memory ] || [ -d /sys/fs/cgroup/cpu ]; then ",
    "w memory; for f in memory.limit_in_bytes memory.usage_in_bytes; do g $f \"$d/$f\"; done; ",
    "s memory.stat \"$d/memory.stat\"; ",
    "w cpu; for f in cpu.cfs_quota_us cpu.cfs_period_us cpu.stat; do g $f \"$d/$f\"; done; ",
    "w cpuset; for f in cpuset.effective_cpus cpuset.cpus; do g $f \"$d/$f\"; done; ",
    "w pids; for f in pids.max pids.current; do g $f \"$d/$f\"; done; ",
    "w cpuacct; g cpuacct.usage \"$d/cpuacct.usage\"; u=$d/cpuacct.usage; k=cpuacct.usage; fi; fi; ",
    "if command -v sleep >/dev/null 2>&1 && sleep 1; then ",
    "p \"stat 2\" stat; p \"uptime 2\" uptime; p \"net/dev 2\" net/dev; ",
    "if [ -n \"$u\" ]; then printf \"%s\\n\" \"@ cgroup 2\"; g \"$k\" \"$u\"; fi; fi; ",
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

/// The longest command that each server takes: Dropbear refuses an exec
/// whose command passes its `MAX_CMD_LEN`, 9000 bytes (its `sysoptions.h`).
pub const COMMAND_MAX: usize = 9000;

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

    /// The cgroup's files are read with the shell's `read` too, each only
    /// where `[ -r ]` finds it, those of both versions, and its use of the
    /// CPUs once more after the `sleep 1` (T-480).
    #[test]
    fn the_cgroup_is_read_as_proc_is() {
        assert!(SCRIPT.contains("g() { [ -r \"$2\" ] || return 0; "), "{SCRIPT}");
        assert!(SCRIPT.contains("s() { [ -r \"$2\" ] || return 0; "), "{SCRIPT}");
        for file in [
            "/proc/self/cgroup",
            "memory.max",
            "memory.current",
            "cpu.max",
            "cpuset.cpus.effective",
            "cpu.stat",
            "io.max",
            "pids.max",
            "cpu.pressure",
            "memory.pressure",
            "memory.limit_in_bytes",
            "memory.usage_in_bytes",
            "cpu.cfs_quota_us",
            "cpu.cfs_period_us",
            "cpuset.effective_cpus",
            "cpuacct.usage",
        ] {
            assert!(SCRIPT.contains(file), "{file} is not read");
        }
        let sleep = SCRIPT.find("sleep 1").expect("the sleep");
        assert!(SCRIPT.find("\"@ cgroup 2\"").is_some_and(|at| at > sleep), "the second sample comes first");
        assert!(SCRIPT.find("\"@ cgroup\"").is_some_and(|at| at < sleep), "the first sample comes last");
    }

    /// The command fits each server's bound on a command, with room to spare.
    #[test]
    fn the_command_fits_dropbear() {
        assert!(command().len() < COMMAND_MAX / 2, "{} bytes", command().len());
    }
}
