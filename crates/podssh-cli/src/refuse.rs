//! Refusals. Every one of them names a real flag, and **none of them prints
//! a usage block**.
//!
//! `docs/cli.md`, "Options of `podssh ssh`", requires an unknown flag to be *"an error that
//! names the nearest real flag"*, and the sibling half-meets that: **READ**,
//! `.tmp/dropssh/src/main.c:276-278` refuses and exits 2, **but the message
//! is only `unknown option %s`, with no nearest match**, and
//! **READ**, `src/main.c:283-287` records the class in its own words — `--json`
//! *"was accepted, set a field, and nothing read it, which is worse than
//! refusing it"*.
//!
//! **The `usage()` dump is the reason refusals live here rather than in the
//! parser.** The sibling prints a full usage block on an unknown option
//! (`src/main.c:277`), and that buries the one line the user needs. A refusal
//! here is three lines: what was given, what it means elsewhere, what to type.

use crate::flags::{FlagKind, FlagRow, VERBS};
use crate::suggest::NoSubcommand;

/// The message for an unknown flag: the flag given, and the nearest known one.
///
/// `nearest_flag` is `clap`'s own suggestion engine (the `suggestions`
/// feature, `strsim`), not the function above — and that asymmetry is
/// deliberate. `clap` searches the flags of the command actually being parsed,
/// so it can name `-p` for a typo of `-P` on `ssh`; a hand-rolled search over a
/// flat list would name a flag belonging to a different verb, which is the
/// `cp`/`ssh` `-P` split made worse.
pub fn unknown_flag(token: &str, suggestion: Option<&str>) -> String {
    // **The last line is the same in both branches, and it was missing from
    // one.** A test caught it: with no suggestion the message ended at
    // *"Run 'podssh --help' for the flags this build accepts."* and never said
    // anything was ignored — which is precisely the reassurance a user who
    // just mistyped `-o StrictHostKeyChecking=no` needs, because the failure
    // they are afraid of is a **silent** drop, and the branch that cannot
    // suggest anything is the branch most likely to be a genuinely unknown flag.
    let last = "Nothing was ignored: an unrecognised -o would drop a security setting.";
    match suggestion {
        Some(s) => format!("podssh: unknown flag '{token}'.\n  Did you mean '{s}'?\n  {last}"),
        None => format!(
            "podssh: unknown flag '{token}'.\n  \
             Run 'podssh --help' for the flags this build accepts.\n  {last}"
        ),
    }
}

/// The message for a flag that parses but is refused, and it **must** name the
/// replacement. A refusal that does not say what to type instead is the
/// sibling's `unknown option %s`. One function, so that each verb, and a
/// refused flag given with no value, refuse in the same words; the third line
/// is the row's own reason.
pub fn refused(verb: &str, given: &str, instead: &str, reason: &str) -> String {
    if instead.is_empty() || instead == "no flag" {
        format!("podssh {verb}: {given} is refused. Leave it out.\n  {reason}.")
    } else {
        format!("podssh {verb}: {given} is refused.\n  Use {instead} instead.\n  {reason}.")
    }
}

/// A word after `podssh --help` or `--version` that it does not take: named,
/// never dropped (GitHub #10).
pub fn extra_word(given: &str, word: &str) -> String {
    let hint = if given == "-V" || given == "--version" {
        "Run 'podssh --version' alone."
    } else {
        "Run 'podssh --help' alone, or 'podssh --help COMMAND' for one command."
    };
    format!("podssh: {given} takes no word '{word}'.\n  {hint}")
}

/// A known flag given with no value. `clap` writes the long spelling also
/// when the short one was typed, so the message names both.
pub fn missing_value(verb: &str, row: &FlagRow) -> String {
    let both = match row.short {
        Some(c) => format!("-{c} (--{})", row.long),
        None => format!("--{}", row.long),
    };
    format!(
        "podssh {verb}: {both} needs a value: {}.\n  Run 'podssh {verb} --help' for each flag and its value.",
        row.arg.unwrap_or("VALUE")
    )
}

/// The message for `-P` on `ssh`, which is **accepted and ignored**, so it
/// has to say why it did nothing.
///
/// The entry's premise said this should be refused, because `ssh -P` was
/// measured to print `option requires an argument -- P`. **That measurement
/// was correct and it was about the wrong thing**: it showed `-P` takes an
/// argument, not that it is absent. MEASURED 2026-10-02, this machine,
/// OpenSSH_10.3p1: `ssh -G -P mytag example.org` prints `tag mytag`, and
/// without `-P` there is no `tag` line. `-P` is a real OpenSSH `ssh` flag
/// whose value is a Tag, and refusing it would refuse a flag a user has
/// memorised.
pub fn accepted_tag_notice(tag: &str) -> String {
    format!(
        "podssh ssh: -P {tag} accepted and ignored.\n  \
         On OpenSSH's ssh, -P is a Tag, not a port; it does not change the connection.\n  \
         For a port use -p. On scp and sftp, -P is the port."
    )
}

/// The message for an unknown verb, and it carries the whole subcommand list
/// when no guess is available — **the list is the answer, not a usage dump**,
/// because it is what the user asked for and it is three lines, not thirty.
pub fn unknown_verb(token: &str, verdict: &NoSubcommand) -> String {
    let mut m = String::new();
    match verdict {
        NoSubcommand::Destination => {
            m.push_str(&format!("podssh: '{token}' looks like a host, not a subcommand.\n"));
            m.push_str(&format!("Try: podssh ssh {token}\n"));
        }
        NoSubcommand::Typo(name) => {
            m.push_str(&format!("podssh: unknown subcommand '{token}'.\n"));
            m.push_str(&format!("Try: podssh {name}\n"));
        }
        NoSubcommand::NoMatch => {
            m.push_str(&format!("podssh: unknown subcommand '{token}'.\n"));
            m.push_str("No close subcommand, so none is guessed.\n");
        }
    }
    m.push_str("Subcommands:\n");
    for v in VERBS {
        m.push_str(&format!("  {:10} {}\n", v.name, v.about));
    }
    m.push_str("Run 'podssh --help' for the same list with flags.");
    m
}

/// The refusal for a subcommand that parses but has no behaviour yet. It must
/// never exit 0 (the caller returns 70), and it says nothing was attempted.
pub fn not_implemented(what: &str) -> String {
    format!("podssh: '{what}' is not implemented yet; nothing was done.")
}

/// The refusal for `podssh man SECTION` when there is no such section. It
/// exits 64 and lists the sections, because the list is what the user can
/// type next; `podssh man` with no section writes the whole manual.
pub fn unknown_man_section(token: &str, sections: &[&str]) -> String {
    let mut m = format!("podssh man: there is no '{token}' section.\n");
    m.push_str("Sections:\n");
    for name in sections {
        m.push_str(&format!("  {name}\n"));
    }
    m.push_str("Run 'podssh man' for the whole manual.");
    m
}

/// The message for `podssh` with no arguments at all. Never an implicit
/// `ssh` — `docs/decisions.md`, "Product" (2026-10-01).
pub fn no_arguments() -> String {
    let mut m = String::from(
        "podssh: no subcommand given.\n\
         podssh never guesses a destination, so it will not connect anywhere.\n\
         Subcommands:\n",
    );
    for v in VERBS {
        m.push_str(&format!("  {:10} {}\n", v.name, v.about));
    }
    m.push_str("Run 'podssh --help' for the same list with flags.");
    m
}

/// **A `clap` error that carries no offending token**: a missing value, or a
/// positional count that does not fit. It names the verb and what was
/// expected, and **never prints a usage block** — the sibling's failure
/// (`src/main.c:277`) is a full usage dump on an unknown option, which buries
/// the one line the user needs.
/// **A `clap` error that carries no offending token**: a missing value, or a
/// positional count that does not fit. It names the verb and what was
/// expected, and **never prints a usage block** — the sibling's failure
/// (`src/main.c:277`) is a full usage dump on an unknown option, which buries
/// the one line the user needs.
///
/// `given` is the offending token, empty when `clap` reported none. It is
/// only ever a token that is **not flag-shaped**: a flag-shaped one is answered
/// by [`unknown_flag`], because being told a flag does not exist when the real
/// problem is a missing positional is a message about the wrong thing.
pub fn bad_invocation(verb: &str, kind: clap::error::ErrorKind, given: &str) -> String {
    let what = match kind {
        clap::error::ErrorKind::InvalidValue => {
            format!("podssh {verb}: that value is not one this flag accepts.")
        }
        clap::error::ErrorKind::InvalidSubcommand => {
            format!("podssh {verb}: that subcommand does not exist.")
        }
        clap::error::ErrorKind::WrongNumberOfValues
        | clap::error::ErrorKind::TooFewValues
        | clap::error::ErrorKind::TooManyValues => {
            format!("podssh {verb}: the right number of arguments was not given.")
        }
        clap::error::ErrorKind::MissingRequiredArgument => {
            format!("podssh {verb}: a required argument was not given.")
        }
        clap::error::ErrorKind::NoEquals => {
            format!("podssh {verb}: that option needs its value as -o Name=Value.")
        }
        clap::error::ErrorKind::UnknownArgument => {
            format!("podssh {verb}: '{given}' is not an argument this verb takes.")
        }
        _ => format!("podssh {verb}: that command line cannot be used."),
    };
    format!(
        "{what}\n  Run 'podssh {verb} --help' for what this verb accepts.\n  \
         Nothing has been ignored and nothing has been attempted."
    )
}

/// Whether a flag kind is one that must refuse rather than parse. One place,
/// so the parser and the table check cannot disagree about which flags refuse.
pub fn refuses(kind: FlagKind) -> bool {
    matches!(kind, FlagKind::Refused | FlagKind::NotInFirstRelease)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suggest::NoSubcommand;

    /// **A refusal is a line, not a usage dump**, and the test for that is a
    /// line-count claim rather than a substring one.
    ///
    /// **A substring test is what this check was written as first, and it is
    /// wrong**: `relay` is in the subcommand list, so a refusal that names the
    /// list would trip a naive `contains("usage")`. The defect being guarded
    /// against is **bulk** the sibling prints ~30 lines of `Usage:` and
    /// `For more information, try '--help'` (`src/main.c:277`), and that is
    /// what buries the one line the user needs.
    ///
    /// So the assertion is: every refusal is a **single short line** plus the
    /// answer. Anything approaching a usage dump fails this.
    #[test]
    fn a_refusal_is_a_line_not_a_usage_dump() {
        for token in ["example.org", "user@example.org", "sttaus", "chatr", "nonsense"] {
            let m = unknown_verb(token, &crate::suggest::diagnose_no_subcommand(token));
            assert!(!m.contains("Usage:"), "{token} printed a usage header: {m}");
            assert!(!m.contains("For more information"), "{token} printed clap's trailer: {m}");
            let lines = m.lines().count();
            assert!(lines <= 18, "{token} produced {lines} lines: {m}");
            assert!(m.contains("Try:") || m.contains("Run 'podssh --help'"), "{token} gave no next step: {m}");
        }
    }

    /// **The other half of the same guard**: the subcommand list is allowed,
    /// and it is what a user who mistyped a verb actually needs.
    #[test]
    fn the_subcommand_list_survives_a_refusal() {
        let m = unknown_verb("example.org", &NoSubcommand::Destination);
        for v in VERBS {
            assert!(m.contains(v.name), "the list omits {}", v.name);
        }
    }

    /// **`podssh` with no arguments says it will not guess a destination**, which
    /// is the sentence that `docs/decisions.md` ("Product", 2026-10-01) turns into behaviour.
    #[test]
    fn no_arguments_says_it_will_not_connect() {
        let m = no_arguments();
        assert!(m.contains("never guesses a destination"), "{m}");
        assert!(!m.contains("Usage:"), "{m}");
        for v in VERBS {
            assert!(m.contains(v.name), "no-arguments omits {}", v.name);
        }
    }

    /// **An unknown flag's message names both ends**: what was given and the
    /// nearest known one. Without a suggestion it still says nothing was
    /// ignored, because a silently-dropped `-o` is the spec's security bug.
    #[test]
    fn an_unknown_flag_names_the_given_and_the_nearest() {
        let with = unknown_flag("-StricthostKeyChekcing", Some("-StrictHostKeyChecking"));
        assert!(with.contains("-StricthostKeyChekcing"), "{with}");
        assert!(with.contains("Did you mean"), "{with}");
        assert!(with.contains("-StrictHostKeyChecking"), "{with}");

        let without = unknown_flag("--qqqqq", None);
        assert!(without.contains("--qqqqq"), "{without}");
        assert!(without.contains("Nothing was ignored"), "{without}");
        // Four lines: the flag, the next step, the reassurance, and nothing else.
        assert!(without.lines().count() <= 4, "{without}");
    }
}
