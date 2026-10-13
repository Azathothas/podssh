//! Non-interactive operation: how podssh is attached, computed once at
//! startup, and the time limit that a run with nobody at a terminal needs.
//!
//! **The detection is the default; no flag is needed to avoid hanging.**
//! Requiring *both* fds to be terminals is the
//! stdout rule applied to input: stdin a terminal while stdout is a file is
//! exactly where a prompt lands in a script's output. A script that must pass
//! a flag to avoid hanging is a script that will hang.
//!
//! **This module asks nothing, and gates no prompt.** The prompts are in
//! podssh-ssh, which asks for host keys, passwords and passphrases, and
//! `podssh_ssh::prompt::can_ask` decides there whether anyone can answer; its
//! refusals name the real remedies (`docs/cli.md`, "Prompts and time limits").
//! A second gate here could disagree with it.
//!
//! **`--timeout` is parsed whole-string or not at all.** The sibling parses
//! its twin flag with `atoi`, so `--timeout 30x` is 0, and 0 means unbounded —
//! a script that hangs believing it is bounded. [`parse_timeout`] rejects
//! `30x`, rejects `0`, and rejects overflow, naming `--timeout` every time.
//!
//! **The exit codes.** A missing or malformed `--timeout`, and `--jsonl` where
//! its JSON would land in a byte stream, are [`Fault::Usage`] (64): the fault
//! is in the command line. A malformed `PODSSH_TIMEOUT` is [`Fault::Config`]
//! (78): the command line is right, and a setting is not. The stderr text
//! always names the flag or the variable, so no script has to branch on the
//! number alone.

use std::time::Duration;

use crate::exitmap::Fault;

/// How podssh is attached, computed once at startup and passed down.
///
/// **`Forced` is `--jsonl`.** Its answer is on stdout, and an answer with a
/// prompt mixed in cannot be parsed, so it is non-interactive on a terminal
/// too. No flag forces the other way: a flag that promised interaction where
/// nobody can answer would be a flag that hangs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attachment {
    /// `isatty(stdin) && isatty(stdout)`, and no `--jsonl`.
    Terminal,
    /// Either fd is not a TTY — the implicit case, and sufficient.
    Pipe,
    /// `--jsonl`, on a terminal or not.
    Forced,
}

impl Attachment {
    /// Whether `--timeout` is required: nobody may be there to stop a run.
    pub fn is_non_interactive(self) -> bool {
        !matches!(self, Attachment::Terminal)
    }
}

/// Compute the attachment from the two `isatty` answers and `--jsonl`.
pub fn resolve(stdin_tty: bool, stdout_tty: bool, jsonl: bool) -> Attachment {
    if jsonl {
        Attachment::Forced
    } else if stdin_tty && stdout_tty {
        Attachment::Terminal
    } else {
        Attachment::Pipe
    }
}

/// [`resolve`] over [`crate::pager::Tty`], the terminal state the caller
/// probed once where the real file descriptors live.
pub fn resolve_tty(tty: crate::pager::Tty, jsonl: bool) -> Attachment {
    resolve(tty.stdin, tty.stdout, jsonl)
}

/// A refusal: the fault for the exit code and the diagnostic for stderr.
///
/// **The message names what was wanted and what to type instead.** A bare
/// "refused" in a pipe is the hang wearing a smaller number — the job returns
/// but nobody knows why.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Refusal {
    /// The exit-code fault: `Usage` for `--timeout` and `--jsonl`, `Config`
    /// for `PODSSH_TIMEOUT` (see the module header).
    pub fault: Fault,
    /// One diagnostic block for stderr. Never carries a secret.
    pub message: String,
}

/// The variable that gives `--timeout` its default (GitHub #12).
pub const TIMEOUT_ENV: &str = "PODSSH_TIMEOUT";

/// Where the text of a timeout came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutFrom {
    Flag,
    Variable,
}

/// The text of the timeout: `--timeout`, else a `PODSSH_TIMEOUT` that is not
/// empty, else none. `var` looks a variable up, so a test can supply one.
pub fn timeout_text(flag: Option<&str>, var: impl Fn(&str) -> Option<String>) -> Option<(String, TimeoutFrom)> {
    match flag {
        Some(text) => Some((text.to_string(), TimeoutFrom::Flag)),
        None => var(TIMEOUT_ENV).filter(|v| !v.trim().is_empty()).map(|v| (v, TimeoutFrom::Variable)),
    }
}

/// As [`require_timeout`], with `PODSSH_TIMEOUT` as the default of the flag.
/// A bad value of the variable is a configuration error (78) that names it:
/// the command line is right, so a script must not look for the fault there.
pub fn require_timeout_or_env(
    verb: &str,
    attachment: Attachment,
    flag: Option<&str>,
    var: impl Fn(&str) -> Option<String>,
) -> Result<Option<Duration>, Refusal> {
    match timeout_text(flag, var) {
        Some((text, TimeoutFrom::Variable)) => parse_duration(TIMEOUT_ENV, &text)
            .map(Some)
            .map_err(|r| Refusal { fault: Fault::Config, message: r.message }),
        Some((text, TimeoutFrom::Flag)) => require_timeout(verb, attachment, Some(&text)),
        None => require_timeout(verb, attachment, None),
    }
}

/// Parse `--timeout DURATION`: `<n>`, `<n>s`, `<n>m`, `<n>h` or `<n>ms`.
///
/// Whole-string, checked, and greater than zero. `30x` is not 30 seconds and
/// `0` is not "no bound" — both are usage errors naming `--timeout`.
pub fn parse_timeout(raw: &str) -> Result<Duration, Refusal> {
    parse_duration("--timeout", raw)
}

/// [`parse_timeout`] for the setting called `name`, which its refusal names.
pub fn parse_duration(name: &str, raw: &str) -> Result<Duration, Refusal> {
    let refuse = |raw: &str, why: &str| -> Refusal {
        Refusal {
            fault: Fault::Usage,
            message: format!(
                "podssh: bad {name} {raw:?}: {why}.\n\
                 Want a whole duration like 30s, 2m or 1h (a bare 30 means 30s)."
            ),
        }
    };
    // The leading digit run; anything after it must be exactly one unit.
    let digits_len = raw.bytes().take_while(u8::is_ascii_digit).count();
    let (digits, suffix) = raw.split_at(digits_len);
    if digits.is_empty() {
        return Err(refuse(raw, "it names no number"));
    }
    enum Unit {
        Millis,
        Secs(u64),
    }
    let unit = match suffix {
        "" | "s" => Unit::Secs(1),
        "m" => Unit::Secs(60),
        "h" => Unit::Secs(3600),
        "ms" => Unit::Millis,
        _ => return Err(refuse(raw, "the unit is not one of ms, s, m, h")),
    };
    let value: u64 = digits.parse().map_err(|_| refuse(raw, "the number does not fit"))?;
    if value == 0 {
        return Err(refuse(raw, "it must be greater than zero"));
    }
    match unit {
        Unit::Millis => Ok(Duration::from_millis(value)),
        Unit::Secs(mult) => {
            value.checked_mul(mult).map(Duration::from_secs).ok_or_else(|| refuse(raw, "the duration overflows"))
        }
    }
}

/// The timeout for this run of `verb`: required outside `Terminal`,
/// optional inside.
///
/// `Terminal` with none means unbounded (a human can interrupt). Anywhere
/// else with none is [`Fault::Usage`]: the message names the verb, the reason
/// and an example of that verb. A provided value is always parsed, even on a
/// terminal: `30x` on a TTY is still a typo.
pub fn require_timeout(verb: &str, attachment: Attachment, raw: Option<&str>) -> Result<Option<Duration>, Refusal> {
    match (attachment, raw) {
        (_, Some(text)) => parse_timeout(text).map(Some),
        (Attachment::Terminal, None) => Ok(None),
        (_, None) => {
            let why = match attachment {
                Attachment::Forced => "--jsonl was given",
                _ => "stdin or stdout is not a terminal",
            };
            let example = match verb {
                "ts" => "podssh ts --timeout 30s -W HOST:PORT".to_string(),
                "chat" => "podssh chat --timeout 60s --send MESSAGE NAME".to_string(),
                _ => format!("podssh {verb} --timeout 30s ..."),
            };
            Err(Refusal {
                fault: Fault::Usage,
                message: format!(
                    "podssh {verb}: --timeout DURATION is required when {why}: nobody may be there to \
                     stop a run that waits.\n\
                     Example: {example}"
                ),
            })
        }
    }
}

/// `--jsonl` with `ts -W`: refused, reason on stderr.
///
/// Stdout there is the byte stream to the peer; a JSON line lands in it.
pub fn refuse_jsonl_with_ts_w() -> Refusal {
    Refusal {
        fault: Fault::Usage,
        message: "podssh: --jsonl is refused with ts -W.\n\
                  Stdout there is the byte stream to the peer, and a JSON line would \
                  land in it. Diagnostics stay on stderr."
            .into(),
    }
}

/// `--jsonl` under ProxyCommand: refused, reason on stderr.
///
/// Stdout there is the SSH stream; a JSON line lands mid-version-string.
pub fn refuse_jsonl_in_proxy() -> Refusal {
    Refusal {
        fault: Fault::Usage,
        message: "podssh: --jsonl is refused in ProxyCommand mode.\n\
                  Stdout there is the SSH byte stream, and a JSON line would land \
                  mid-version-string. Diagnostics stay on stderr."
            .into(),
    }
}
