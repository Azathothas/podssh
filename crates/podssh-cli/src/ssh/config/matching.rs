//! `Match` (T-045): the criteria of a `Match` line, evaluated as OpenSSH
//! 10.3p1 evaluates them, measured with its `ssh -G`. The criteria are
//! all needed, each may be negated with `!`, and each but `all`,
//! `canonical` and `final` takes a comma list of patterns, where a pattern
//! with `!` excludes: `host` and `originalhost` with no regard to case, the
//! others with it. `criterion=patterns` reads as `criterion patterns`.
//! `exec` and `localnetwork` are refused by name where they would decide:
//! podssh runs no program for a configuration, and probes no interface.

/// The release whose reading of `ssh_config` podssh follows: what `Match
/// version` matches.
pub const VERSION: &str = "OpenSSH_10.3p1";

const EXEC: &str = "Match exec runs a program at each connection, which podssh does not run; a block that it \
                    decides is refused rather than skipped, as it can change the host";
const LOCALNETWORK: &str = "Match localnetwork reads the addresses of this host's interfaces, which podssh does \
                            not probe; a block that it decides is refused rather than skipped, as it can change \
                            the host";

/// What `Match` reads besides the files: the command line's part, and the
/// local user.
#[derive(Debug, Clone, Default)]
pub struct Given<'a> {
    /// `-o HostName`, which comes before the files' (`Match host`).
    pub host_name: Option<&'a str>,
    /// The user of `-l`, `-o User` or `user@host`, which comes before the
    /// files'.
    pub user: Option<&'a str>,
    /// The local user, from the environment.
    pub local_user: Option<&'a str>,
    /// `-P` or `-o Tag`.
    pub tag: Option<&'a str>,
    /// The command line's command, its words joined with spaces.
    pub command: String,
    /// The session type that the command line sets: `none` (`-N`, `-W`),
    /// `subsystem` (`-s`), or the one of `-o SessionType`.
    pub session: Option<&'a str>,
}

/// What a `Match` line's criteria see where it stands.
pub(super) struct Seen<'a> {
    /// The host after `HostName`: so far in the first pass, and the final
    /// one in the final pass.
    pub host: &'a str,
    /// The host as typed.
    pub original: &'a str,
    /// The user: the command line's, the files' so far, or the local one.
    pub user: Option<&'a str>,
    pub local_user: Option<&'a str>,
    /// The tag, empty with none.
    pub tag: &'a str,
    pub command: &'a str,
    /// `shell`, `exec`, `subsystem` or `none`.
    pub session: &'a str,
    pub final_pass: bool,
}

/// How a `Match` line came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Outcome {
    /// Its block applies.
    pub applies: bool,
    /// It asks for the final pass: a `final` with no `!`, met also where
    /// another criterion fails, as OpenSSH meets it.
    pub wants_final: bool,
}

/// The criteria of a `Match` line, its keyword and comment taken off.
pub(super) fn evaluate(value: &str, seen: &Seen) -> Result<Outcome, String> {
    let mut words = super::super::options::words(value).into_iter().peekable();
    let mut outcome = Outcome { applies: true, wants_final: false };
    let mut criteria = 0;
    // A criterion that podssh does not evaluate, refused if it decides.
    let mut unevaluated: Option<&'static str> = None;
    while let Some(word) = words.next() {
        let (word, inline) = match word.split_once('=') {
            Some((name, patterns)) => (name.to_string(), Some(patterns.to_string())),
            None => (word, None),
        };
        let (negated, name) = match word.strip_prefix('!') {
            Some(name) => (true, name.to_ascii_lowercase()),
            None => (false, word.to_ascii_lowercase()),
        };
        if name == "all" {
            if criteria > 1 || inline.is_some() || words.peek().is_some() {
                return Err("Match all cannot be combined with other criteria".into());
            }
            outcome.applies &= !negated;
            return decided(outcome, unevaluated);
        }
        criteria += 1;
        if name == "canonical" || name == "final" {
            outcome.wants_final |= name == "final" && !negated;
            // podssh canonicalizes no name, so both hold in the final pass
            // alone, as in OpenSSH when it canonicalizes none.
            outcome.applies &= seen.final_pass != negated;
            continue;
        }
        let Some(patterns) = inline.or_else(|| words.next()) else {
            return Err(format!("Match {name} needs patterns"));
        };
        let matched = match name.as_str() {
            "host" => matches(seen.host, &patterns, true),
            "originalhost" => matches(seen.original, &patterns, true),
            "user" => matches(
                seen.user.ok_or("Match user: no user is known; give one with user@host or -l USER")?,
                &patterns,
                false,
            ),
            "localuser" => {
                matches(seen.local_user.ok_or("Match localuser: the local user's name is not known")?, &patterns, false)
            }
            "tagged" => matches(seen.tag, &patterns, false),
            "command" => matches(seen.command, &patterns, false),
            "sessiontype" => matches(seen.session, &patterns, false),
            "version" => matches(VERSION, &patterns, false),
            "exec" => {
                unevaluated.get_or_insert(EXEC);
                continue;
            }
            "localnetwork" => {
                unevaluated.get_or_insert(LOCALNETWORK);
                continue;
            }
            other => return Err(format!("Match {other}: not a criterion of ssh_config")),
        };
        outcome.applies &= matched != negated;
    }
    if criteria == 0 {
        return Err("Match needs a criterion, or all".into());
    }
    decided(outcome, unevaluated)
}

/// The outcome, unless a criterion that podssh does not evaluate decides
/// it: where another one failed, the block is off whatever it would say.
fn decided(outcome: Outcome, unevaluated: Option<&'static str>) -> Result<Outcome, String> {
    match unevaluated {
        Some(why) if outcome.applies => Err(why.into()),
        _ => Ok(outcome),
    }
}

/// OpenSSH's `match_pattern_list`: `text` against a comma list of patterns
/// with `*` and `?`: one that matches, and no `!` one that matches. `fold`
/// compares with no regard to ASCII case, as for a host.
fn matches(text: &str, list: &str, fold: bool) -> bool {
    let text = if fold { text.to_ascii_lowercase() } else { text.to_string() };
    let mut matched = false;
    for pattern in list.split(',') {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        let pattern = if fold { pattern.to_ascii_lowercase() } else { pattern.to_string() };
        if podssh_ssh::known_hosts::wildcard(pattern.as_bytes(), text.as_bytes()) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

#[cfg(test)]
#[path = "matching_tests.rs"]
mod tests;
