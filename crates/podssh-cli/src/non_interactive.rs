//! E33: non-interactive operation — one value computed once at startup.
//!
//! ⛔ **The detection is the default; no flag is needed to avoid hanging.**
//! `docs/TODO/cli/non-interactive.md`:104-111 — requiring *both* fds is the
//! stdout rule applied to input: stdin a terminal while stdout is a file is
//! exactly where a prompt lands in a script's output. A script that must pass
//! a flag to avoid hanging is a script that will hang.
//!
//! ⛔ **One function gates every prompt; nothing else may ask.**
//! [`gate_prompt`] is the only path from "wants a secret" to "asks the user",
//! and outside [`Attachment::Terminal`] it returns [`Refusal`] instead. The
//! nine [`PromptSite`] rows are E33's audit table as code — an enumerated
//! list, not a review — so a tenth prompt cannot be added without a row here.
//!
//! ⛔ **`--timeout` is parsed whole-string or not at all.** The sibling parses
//! its twin flag with `atoi`, so `--timeout 30x` is 0, and 0 means unbounded —
//! a script that hangs believing it is bounded. [`parse_timeout`] rejects
//! `30x`, rejects `0`, and rejects overflow, naming `--timeout` every time.
//!
//! ⛔ **Provisional fault mapping, owned elsewhere.** `--timeout` problems are
//! [`Fault::Usage`] (E33's own Prove check 6: a missing `--timeout` is a USAGE
//! error). Every prompt-gate refusal is [`Fault::SessionFault`] **until the
//! owning entry names its value** — E13 for host keys, E12/E23 for token and
//! relay, E30 for channel and nick, E01 for the passphrase. A refused prompt
//! is not a usage error (the command line was fine), and 70 reads "the session
//! did not deliver what was asked for", which is the least-wrong bucket while
//! the owners decide. The stderr text always names the site and the remedy, so
//! no script has to branch on the number alone.

use std::time::Duration;

use crate::exitmap::Fault;

/// How podssh is attached, computed once at startup and passed down.
///
 /// ⛔ **Four variants because the dangerous override exists.** `Forced` is
/// `--non-interactive` or `--jsonl`; `ForcedInteractive` is `--interactive`,
/// which is refused unless both fds are TTYs — a flag promising interaction
/// podssh cannot deliver is a flag that hangs. Neither flag is in the tree
/// yet (the flag-table gate needs a spec row first), so `Forced` today comes
/// from `--jsonl` and `ForcedInteractive` from [`force_interactive`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attachment {
    /// `isatty(stdin) && isatty(stdout)`, and no forcing flag.
    Terminal,
    /// Either fd is not a TTY — the implicit case, and sufficient.
    Pipe,
    /// `--non-interactive`, or `--jsonl`.
    Forced,
    /// `--interactive`: refused unless both fds are TTYs.
    ForcedInteractive,
}

impl Attachment {
    /// Whether `--timeout` is required and prompts are refused.
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

/// The `--interactive` override: allowed only where interaction is possible.
pub fn force_interactive(stdin_tty: bool, stdout_tty: bool) -> Result<Attachment, Refusal> {
    if stdin_tty && stdout_tty {
        Ok(Attachment::ForcedInteractive)
    } else {
        let missing = match (stdin_tty, stdout_tty) {
            (false, _) => "stdin",
            (_, false) => "stdout",
            _ => unreachable!("both TTYs return above"),
        };
        Err(Refusal {
            fault: Fault::Usage,
            message: format!(
                "podssh: --interactive needs a terminal on both ends, but {missing} is not a TTY.\n\
                 A flag promising interaction podssh cannot deliver is a flag that hangs."
            ),
        })
    }
}

/// A refusal: the fault for the exit code and the diagnostic for stderr.
///
/// ⛔ **The message names what was wanted and what to type instead.** A bare
/// "refused" in a pipe is the hang wearing a smaller number — the job returns
/// but nobody knows why.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Refusal {
    /// The exit-code fault. `--timeout` problems are `Usage`; every prompt
    /// gate is provisionally `SessionFault` (see the module header).
    pub fault: Fault,
    /// One diagnostic block for stderr. Never carries a secret.
    pub message: String,
}

/// One row of E33's audit table: every place podssh could ever prompt.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PromptSite {
    /// An unknown host key. Remedy: fingerprint + `--accept-new`.
    UnknownHostKey { fingerprint: String },
    /// A changed host key. Refused **always** — never even on a TTY.
    ChangedHostKey { fingerprint: String },
    /// No relay token and none mintable here. Remedy names the knob.
    TokenAbsent,
    /// No relay configured. Remedy names `--relay`; never prompts.
    NoRelay,
    /// A key passphrase. ⛔ **Unowned**: E01 has not named the auth surface,
    /// so the remedy says so instead of inventing a flag.
    Passphrase,
    /// `known_hosts` unreadable. Remedy names the path tried.
    KnownHostsUnreadable { path: String },
    /// A channel join needing `KEY`. Remedy names channel and key.
    ChannelKey { channel: String },
    /// A nick already in use. Remedy names the nick; no re-ask loop.
    NickInUse { nick: String },
    /// `--sendfile` unreadable. Remedy names path and errno text.
    SendfileUnreadable { path: String, errno: String },
}

/// Parse `--timeout DURATION`: `<n>`, `<n>s`, `<n>m`, `<n>h` or `<n>ms`.
///
/// Whole-string, checked, and greater than zero. `30x` is not 30 seconds and
/// `0` is not "no bound" — both are usage errors naming `--timeout`.
pub fn parse_timeout(raw: &str) -> Result<Duration, Refusal> {
    fn refuse(raw: &str, why: &str) -> Refusal {
        Refusal {
            fault: Fault::Usage,
            message: format!(
                "podssh: bad --timeout {raw:?}: {why}.\n\
                 Want a whole duration like 30s, 2m or 1h (a bare 30 means 30s)."
            ),
        }
    }
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
    let value: u64 = digits
        .parse()
        .map_err(|_| refuse(raw, "the number does not fit"))?;
    if value == 0 {
        return Err(refuse(raw, "it must be greater than zero"));
    }
    match unit {
        Unit::Millis => Ok(Duration::from_millis(value)),
        Unit::Secs(mult) => value
            .checked_mul(mult)
            .map(Duration::from_secs)
            .ok_or_else(|| refuse(raw, "the duration overflows")),
    }
}

/// The timeout for this run: required outside `Terminal`, optional inside.
///
/// `Terminal` with none means unbounded (a human can interrupt). Anywhere
/// else with none is [`Fault::Usage`] naming `--timeout`. A provided value is
/// always parsed, even on a terminal — `30x` on a TTY is still a typo.
pub fn require_timeout(
    attachment: Attachment,
    raw: Option<&str>,
) -> Result<Option<Duration>, Refusal> {
    match (attachment, raw) {
        (_, Some(text)) => parse_timeout(text).map(Some),
        (Attachment::Terminal, None) => Ok(None),
        (_, None) => Err(Refusal {
            fault: Fault::Usage,
            message: format!(
                "podssh: --timeout DURATION is required when there is no TTY ({attachment:?}).\n\
                 Without it a script cannot hang for ever — it hangs for ever.\n\
                 Example: podssh chat --send '#chan hi' --timeout 30s"
            ),
        }),
    }
}

/// The single gate: may this prompt be asked?
///
/// `ChangedHostKey` refuses on every attachment — a prompt offers the operator
/// an accident. Every other site refuses outside `Terminal` and allows inside
/// it. There is no other path from "wants a secret" to "asks the user".
pub fn gate_prompt(attachment: Attachment, site: &PromptSite) -> Result<(), Refusal> {
    fn refused(site: &PromptSite, remedy: String) -> Refusal {
        Refusal {
            // ⛔ Provisional: the owning entry names the final value (see the
            // module header). Not `Usage` — the command line was fine.
            fault: Fault::SessionFault,
            message: format!("podssh: refusing to ask ({site:?}).\n{remedy}"),
        }
    }
    match site {
        PromptSite::ChangedHostKey { fingerprint } => Err(refused(
            site,
            format!(
                "The host key changed (now {fingerprint}): remove the old key; \
                 podssh never auto-replaces one, on a TTY or anywhere else (E13)."
            ),
        )),
        _ if !attachment.is_non_interactive() => Ok(()),
        PromptSite::UnknownHostKey { fingerprint } => Err(refused(
            site,
            format!(
                "Unknown host key {fingerprint}: re-run on a terminal or pass \
                 --accept-new (E13)."
            ),
        )),
        PromptSite::TokenAbsent => Err(refused(
            site,
            "No relay token: mint one in memory or set the token knob.".into(),
        )),
        PromptSite::NoRelay => Err(refused(
            site,
            "No relay configured: pass --relay URL. podssh never prompts for one.".into(),
        )),
        PromptSite::Passphrase => Err(refused(
            site,
            "A passphrase is needed and there is no TTY: E01 has not named the \
             auth surface yet, so no flag can carry it (E33 row 5 stays open)."
                .into(),
        )),
        PromptSite::KnownHostsUnreadable { path } => Err(refused(
            site,
            format!("known_hosts unreadable at {path}."),
        )),
        PromptSite::ChannelKey { channel } => Err(refused(
            site,
            format!("Joining {channel} needs its KEY: pass it, podssh never asks."),
        )),
        PromptSite::NickInUse { nick } => Err(refused(
            site,
            format!("Nick {nick} is in use: pick another with --nick."),
        )),
        PromptSite::SendfileUnreadable { path, errno } => Err(refused(
            site,
            format!("--sendfile unreadable: {path}: {errno}."),
        )),
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
