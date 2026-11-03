//! The exec of the preflight (T-482): one command of sh that names each
//! tool on PATH that podssh's commands on a far host use (the copy by exec,
//! T-135; `job`, T-193; `cp --delta`; `ping` through the host), and, where
//! tmux is missing, what could install it, by T-481's probe in the same sh.
//! As each script of podssh's for a far host, one line with no single quote
//! and no backslash, so that each login shell gives it to sh whole.

use std::collections::BTreeSet;
use std::time::Duration;

use podssh_ssh::exec::{self, Captured};
use podssh_ssh::missing::{self, Found};
use podssh_ssh::Connection;
use podssh_ws::Verdict;

use super::judge::{fail, ok, unknown};

/// The first line of the answer, with the number of its form.
pub const MARK: &str = "podssh-preflight 1";
/// The most of the answer that is read.
const CAP: usize = 64 * 1024;

/// Each tool, whether a command cannot do without it, and what its lack
/// stops.
#[rustfmt::skip]
pub const TOOLS: &[(&str, bool, &str)] = &[
    ("cat", true, "podssh job and the copy by exec"),
    ("mv", true, "podssh job and the copy by exec"),
    ("rm", true, "podssh job and the copy by exec"),
    ("mkdir", true, "podssh job"),
    ("sleep", true, "podssh job"),
    ("wc", true, "the copy by exec, and the follow of podssh job log"),
    ("tail", false, "the follow of podssh job log, and the resume of a copy down by exec"),
    ("nohup", false, "podssh job --no-tmux"),
    ("setsid", false, "a session of its own for each job of podssh job --no-tmux"),
    ("base64", false, "a copy by exec where cat does not carry each byte"),
    ("stat", false, "the mode, times and owner of a copy down by exec with -p"),
    ("chmod", false, "the mode of a copy up by exec with -p"),
    ("touch", false, "the times of a copy up by exec with -p"),
    ("chown", false, "the owner of a copy up by exec with --owner"),
    ("dd", false, "the far blocks of podssh cp --delta, which then sends the whole file"),
    ("head", false, "the throughput of podssh ping through this host"),
];

/// The tools of a digest of a far file, any one of which `cp` uses.
pub const DIGESTS: &[&str] = &["sha256sum", "shasum", "openssl"];

/// What the exec of the tools found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probed {
    /// sh ran the script: the tools on PATH and, where tmux is missing,
    /// what could install it.
    Ran { tools: BTreeSet<String>, install: Option<Found> },
    /// The server ran no command, no sh answered, or the exec broke.
    Failed(String),
    /// The connection had ended before the probe.
    NotAsked,
}

/// Each name that the script looks for: [`TOOLS`], [`DIGESTS`] and tmux.
fn names() -> impl Iterator<Item = &'static str> {
    TOOLS.iter().map(|(name, ..)| *name).chain(DIGESTS.iter().copied()).chain(["tmux"])
}

/// The command: `sh -c 'SCRIPT' sh tmux`, the probe of T-481 reading tmux
/// as its `$1` at the end.
pub fn command() -> String {
    let names: Vec<&str> = names().collect();
    let script = format!(
        "echo {MARK}; for t in {}; do if command -v \"$t\" >/dev/null 2>&1; then echo \"have $t\"; fi; done; {}",
        names.join(" "),
        missing::script()
    );
    let word = exec::shell_word(&script).expect("a script of one line is one word");
    format!("sh -c {word} sh tmux")
}

/// The answer of [`command`]: the tools named after [`MARK`]'s line, and
/// the words of a missing tmux; `None` when no such line came, as from a
/// login that gave no sh. What a login prints first is not read.
pub fn parse(stdout: &[u8]) -> Option<(BTreeSet<String>, Option<Found>)> {
    let text = String::from_utf8_lossy(stdout);
    let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
    lines.by_ref().find(|l| *l == MARK)?;
    let rest: Vec<&str> = lines.collect();
    let known: BTreeSet<&str> = names().collect();
    let tools = rest.iter().filter_map(|l| l.strip_prefix("have ")).filter(|t| known.contains(t));
    let install = missing::read(rest.join("\n").as_bytes(), "tmux");
    Some((tools.map(str::to_string).collect(), install))
}

/// Why no answer came: the status of a host with no sh, and its first
/// words on stderr.
fn no_answer(got: &Captured) -> String {
    let said = podssh_ws::text::one_line(&String::from_utf8_lossy(&got.stderr));
    let said = if said.is_empty() { String::new() } else { format!(": {said}") };
    match got.status {
        Some(127) => format!("the server has no sh{said}"),
        Some(status) => format!("no answer of sh, and the status {status}{said}"),
        None => format!("no answer of sh, and no status{said}"),
    }
}

/// One exec of [`command`] on `handle`, within `limit`.
pub async fn probe(handle: &Connection, limit: Duration) -> Probed {
    match exec::capture(handle, &command(), limit, CAP).await {
        Err(e) => Probed::Failed(e.to_string()),
        Ok(got) => match parse(&got.stdout) {
            Some((tools, install)) => Probed::Ran { tools, install },
            None => Probed::Failed(no_answer(&got)),
        },
    }
}

/// The tools: `FAIL` when no sh ran the probe, or one that a command cannot
/// do without is missing; else `ok`, with what each missing one stops.
pub fn exec_tools(found: &Probed) -> Verdict {
    let tools = match found {
        Probed::NotAsked => return super::ended(),
        Probed::Failed(why) => return fail(format!("{why}: podssh job, run and the copy by exec need a POSIX sh")),
        Probed::Ran { tools, .. } => tools,
    };
    let missing = |needed: bool| -> Vec<String> {
        TOOLS
            .iter()
            .filter(|(name, n, _)| *n == needed && !tools.contains(*name))
            .map(|(name, _, stops)| format!("{name} ({stops})"))
            .collect()
    };
    let (needed, mut other) = (missing(true), missing(false));
    if !DIGESTS.iter().any(|d| tools.contains(*d)) {
        other.push("sha256sum, shasum and openssl (a copy by exec checks its bytes by a second read)".into());
    }
    if !needed.is_empty() {
        let also = if other.is_empty() { String::new() } else { format!("; also missing: {}", other.join(", ")) };
        return fail(format!("sh runs, and has no {}{also}", needed.join(", ")));
    }
    if other.is_empty() {
        ok("sh runs, with each tool that podssh job, the copy by exec and cp --delta use")
    } else {
        ok(format!("sh runs, with each tool that podssh job and the copy by exec need; missing: {}", other.join(", ")))
    }
}

/// tmux, from the same exec: `podssh job` keeps each job in it, and `ssh
/// --persist` its shell; where it is missing, what could install it
/// (T-481), and `job --no-tmux`.
pub fn tmux(found: &Probed) -> Verdict {
    match found {
        Probed::NotAsked => super::ended(),
        Probed::Failed(_) => unknown("no sh ran the probe, as exec tools says"),
        Probed::Ran { tools, .. } if tools.contains("tmux") => {
            ok("on PATH: podssh job and podssh ssh --persist keep their commands in it")
        }
        Probed::Ran { install, .. } => {
            let hint = install.as_ref().and_then(crate::job::far::install_sentence);
            let hint = hint.map(|s| format!("; {s}")).unwrap_or_default();
            fail(format!("no tmux on PATH: podssh ssh --persist cannot work, and podssh job needs --no-tmux{hint}"))
        }
    }
}
