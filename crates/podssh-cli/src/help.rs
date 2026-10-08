//! `--help`, rendered from [`crate::flags::VERBS`].
//!
//! ⛔ **Renderer one of two, and the tree is shared.** `podssh man` is E32's
//! and walks the same [`crate::flags::VERBS`]; nothing here and nothing there
//! writes a flag down, so `06-cli.md`:154-161's three obligations hold by
//! having one list rather than by being checked afterwards.
//!
//! ⛔ **The width is fixed at 100 columns and is not probed.** `clap`'s
//! `wrap_help` feature is deliberately off in `Cargo.toml`: it pulls
//! `terminal_size`, which is a capability probe, and `RULES.md` forbids
//! depending on a capability that has not been probed. ⛔ A fixed width is
//! also what makes the man/help parity check a string comparison rather than a
//! measurement of somebody's terminal.

use crate::flags::{FlagKind, Verb, VERBS};
use std::fmt::Write as _;

/// The column the flag column ends at, and the width the help wraps to.
const WIDTH: usize = 100;

/// ⛔ **The help column is measured from the rows, not a constant.**
///
/// ⛔ It was a constant of 26 and that produced a real defect: the test below
/// caught `-W, --stdio-forward HOST:PORT` running straight into its help text
/// with no gap — *"HOST:PORTforward stdio to a host:port"* — because that row
/// is 28 characters wide and `format!("{:<26$}")` does not truncate, it only
/// pads. ⛔ **Any row wider than the constant silently loses its separator**,
/// so a fixed width is a layout bug waiting for the longest flag name.
///
/// ⛔ Deriving it means adding a flag with a long name cannot break `--help`,
/// which is the same "one list, two renderers" argument the tree rests on: a
/// constant is a second thing to keep in step with the table.
pub fn flag_column(rows: &[crate::flags::FlagRow]) -> usize {
    // Measured on the text `flag_line` prints, prefix included: measuring
    // `usage_form` left out the `-c,` / three-space prefix, so verbs whose
    // flags have no short form got a column too narrow to separate the two.
    rows.iter()
        .map(|r| flag_left(r).chars().count() + 2)
        .max()
        .unwrap_or(0)
        .min(MAX_FLAG_COLUMN)
}

/// ⛔ The widest the flag column may get before the help wraps under it.
///
/// ⛔ 38, not 34: `--StrictHostKeyChecking yes|no|ask|off` is exactly 37
/// characters, and at a cap of 34 that one row wrapped to its own line while
/// every other row sat in the column — ⛔ an inconsistent help that looks like a
/// mistake in the one flag a security-conscious user is most likely to look up.
/// ⛔ A cap above the widest real row costs nothing and keeps the column even;
/// a cap below it is a trap for whoever adds the next long flag.
const MAX_FLAG_COLUMN: usize = 38;

/// One rendered flag line: `-p, --port PORT  port to connect to`.
///
/// ⛔ **The spelling here is the contract with E32.** `man.rs` extracts flag
/// names out of the man page and the help output and compares the two sets, so
/// what is printed has to be what a user would type and not a decoration. A
/// long-only flag has no short form and says so by omission.
/// The flag half of a help line: `-c, --long ARG`, or `    --long ARG`.
fn flag_left(row: &crate::flags::FlagRow) -> String {
    let mut left = String::new();
    match row.short {
        Some(c) => {
            let _ = write!(left, "-{c},");
        }
        None => left.push_str("   "),
    }
    let _ = write!(left, " --{}", row.long);
    if let Some(a) = row.arg {
        let _ = write!(left, " {a}");
    }
    left
}

pub fn flag_line(row: &crate::flags::FlagRow, column: usize) -> String {
    let left = flag_left(row);
    if left.chars().count() >= column {
        // ⛔ Too wide to sit beside its description: the description goes on
        // the next line rather than being run into.
        format!("{left}\n    {}", help_text(row))
    } else {
        format!("{left:<column$}{}", help_text(row))
    }
}

/// ⛔ **The suffix that says what a flag is *not* doing.** ⛔ A flag that parses
/// and refuses must not read like a flag that works, and a flag that is
/// accepted and ignored must say so in `--help` and not only when used.
///
/// ⛔ **Public because there are two renderers and one sentence.** E32's page
/// prints this text verbatim, ⛔ **and the parity gate asserts the page carries
/// it** — ⛔ a description that stopped being true is not caught by a set
/// comparison, so the two renderings are compared on their words as well as
/// their flags.
pub fn help_text(row: &crate::flags::FlagRow) -> String {
    match row.kind {
        FlagKind::Supported => row.help.to_string(),
        FlagKind::Accepted => format!("{} (accepted and ignored)", row.help),
        FlagKind::Refused => match row.instead {
            Some("no flag") => format!("{} (refused)", row.help),
            instead => format!("{} (refused: use {})", row.help, instead.unwrap_or("a supported flag")),
        },
        FlagKind::NotInFirstRelease => format!("{} (not in this release)", row.help),
    }
}

/// Render the top-level help.
pub fn top_level_help() -> String {
    let mut s = String::new();
    // ⛔ The banner's sentence is [`crate::flags::ABOUT`] and not a copy of it:
    // E32's page writes the same sentence in its `.SH NAME`, and ⛔ a sentence
    // with two copies in two renderers is exactly the drift this crate's tree
    // exists to prevent.
    s.push_str(&format!("podssh - {}\n\n", crate::flags::ABOUT));
    s.push_str("USAGE:\n    podssh <SUBCOMMAND> [OPTIONS]\n\n");
    s.push_str("podssh never guesses a destination. With no subcommand it prints this\n");
    s.push_str("list and exits non-zero; it does not become an implicit ssh.\n\n");
    s.push_str("OPTIONS:\n");
    // ⛔ **The column is derived from the rows, and it has to be.**
    // `format!("{:<12}{}", "  -h, --help", "Print help")` produced
    // `  -h, --helpPrint help` — the left part is **exactly twelve
    // characters**, and `{:<12}` pads without separating, so there was no gap
    // at all. ⛔ This is the same defect E31's `no_flag_runs_into_its_description`
    // records for `flag_line`, one layer up: ⛔ a constant that happens to equal
    // its widest row is a separator that disappears. ⛔ E32's parity gate reads
    // this block, and it read `--helpPrint` as a flag — which is what a user
    // reading it would conclude too.
    let rows: Vec<(String, &str)> = crate::flags::TOP_OPTIONS
        .iter()
        .map(|(short, long, about)| (format!("  {short}, {long}"), *about))
        .collect();
    let column = rows.iter().map(|(l, _)| l.chars().count()).max().unwrap_or(0) + 2;
    for (left, right) in rows {
        s.push_str(&format!("{left:<column$}{right}\n"));
    }
    s.push('\n');
    s.push_str("SUBCOMMANDS:\n");
    let mut w = 0;
    for v in VERBS {
        w = w.max(v.name.len());
    }
    for v in VERBS {
        s.push_str(&format!("    {:w$}  {}{}\n", v.name, v.about, availability_note(v)));
        // ⛔ Aliases are printed beside the verb they resolve to, because a user
        // who types `podssh irc` and gets help for `chat` deserves to know
        // they are the same command.
        if v.aliases.len() > 1 {
            let others: Vec<&str> = v
                .aliases
                .iter()
                .copied()
                .filter(|a| *a != v.name)
                .collect();
            s.push_str(&format!(
                "    {:w$}  aliases: {}\n",
                "",
                others.join(", ")
            ));
        }
    }
    s.push('\n');
    s.push_str("Run 'podssh <SUBCOMMAND> --help' for that subcommand's flags.\n");
    s.push_str("Run 'podssh man' for the whole manual.\n");
    s
}

/// What `--help` and the manual add to a verb that does not work here.
pub fn availability_note(verb: &Verb) -> &'static str {
    match crate::flags::availability(verb) {
        crate::flags::Availability::Works => "",
        crate::flags::Availability::NotYet => " (not implemented yet)",
        crate::flags::Availability::NotInBuild => " (not in this build)",
    }
}

/// Render one verb's help, from the same rows the parser was built from.
pub fn verb_help(verb: &'static Verb) -> String {
    let mut s = String::new();
    s.push_str(&format!("podssh {} - {}\n\n", verb.name, verb.about));
    s.push_str(&format!("USAGE:\n    podssh {} {}\n\n", verb.name, usage_tail(verb)));

    // ⛔ **The `OPTIONS:` header is printed even for a verb with no flags of
    // its own**, because `--help` is one of its options and ⛔ a headerless
    // option line is not a block: E32's parity gate reads the flags inside an
    // `OPTIONS:` block, so a line outside one is a flag the gate cannot see.
    // ⛔ The output for `ssh` and `cp` is unchanged; the flagless verbs gain
    // the two-line block they always should have had.
    s.push_str("OPTIONS:\n");
    if !verb.flags.is_empty() {
        let column = flag_column(verb.flags);
        for row in verb.flags {
            s.push_str(&format!("    {}\n", flag_line(row, column)));
        }
    }
    s.push_str(&format!(
        "{:<12}{}\n",
        "    --help",
        crate::flags::HELP_FLAG.help
    ));
    s.push('\n');

    if verb.name == "ssh" {
        s.push('\n');
        s.push_str("-L, -R and -D are refused by name: podssh never binds a listener.\n");
        s.push_str("  Use -W HOST:PORT, which forwards over an existing connection.\n");
        s.push_str("-P on ssh is OpenSSH's Tag, not a port, and is ignored. On scp and\n");
        s.push_str("  sftp, -P is the port. The meaning is per-verb.\n");
    }
    if verb.name == "cp" || verb.name == "mv" {
        s.push('\n');
        s.push_str("-P here is the port, as on scp and sftp. On ssh it is a Tag.\n");
    }
    s
}

/// ⛔ **The usage tail, and it is public for the same reason [`help_text`] is:**
/// E32's page prints `podssh <verb> <this>`, ⛔ and the parity gate asserts the
/// page carries the string `--help` prints rather than a second copy of it.
pub fn usage_tail(verb: &Verb) -> &'static str {
    match verb.name {
        "ssh" => "[OPTIONS] [--] [user@]host [COMMAND...]",
        "cp" | "mv" => "[OPTIONS] SRC... DST",
        "chat" => "[OPTIONS] [CHANNEL] [MESSAGE]",
        "man" => "[OPTIONS] [SECTION]",
        "relay" => "[OPTIONS] SUBCOMMAND [ARGS...]",
        "node" | "operator" => "NAME",
        "proxy" => "[OPTIONS] [--] HOST PORT",
        _ => "[OPTIONS]",
    }
}

/// The version string. ⛔ Read from the manifest at compile time, so it cannot
/// drift from the crate it ships in.
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// ⛔ **Wrap to [`WIDTH`] without probing the terminal.** ⛔ A word too long for
/// one line is left long rather than broken: a broken flag name is a flag name
/// nobody can type.
pub fn wrap(text: &str) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if line.is_empty() {
            line.push_str(word);
        } else if line.len() + 1 + word.len() <= WIDTH {
            line.push(' ');
            line.push_str(word);
        } else {
            out.push_str(&line);
            out.push('\n');
            line.clear();
            line.push_str(word);
        }
    }
    if !line.is_empty() {
        out.push_str(&line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_top_level_help_lists_every_verb() {
        let h = top_level_help();
        for v in VERBS {
            assert!(h.contains(v.name), "help omits {}", v.name);
        }
    }

    /// ⛔ **The top-level block, and the defect that was in it.** ⛔
    /// `format!("{:<12}{}", "  -h, --help", "Print help")` printed
    /// `  -h, --helpPrint help`: the left part is exactly twelve characters and
    /// `{:<12}` pads without separating. ⛔ The parser E32's gate uses read
    /// `--helpPrint` as a flag name, ⛔ and so would a user. ⛔ This is the same
    /// failure as `no_flag_runs_into_its_description` below, in the block that
    /// test does not cover.
    #[test]
    fn no_top_level_option_runs_into_its_description() {
        let h = top_level_help();
        for (left, right) in
            [("  -h, --help", "Print help; --help COMMAND prints the help of one command"), ("  -V, --version", "Print version")]
        {
            let line = h
                .lines()
                .find(|l| l.starts_with(left))
                .unwrap_or_else(|| panic!("{left:?} is not in the top-level help"));
            let rest = &line[left.len()..];
            assert!(
                rest.starts_with(char::is_whitespace),
                "{left:?} runs straight into {rest:?}"
            );
            assert_eq!(rest.trim(), right, "{line:?}");
        }
    }

    #[test]
    fn help_prints_an_alias_beside_its_verb() {
        let h = top_level_help();
        assert!(h.contains("aliases: irc"), "{h}");
        assert!(h.contains("aliases: scp, sftp"), "{h}");
    }

    #[test]
    fn a_refused_flag_says_so_in_help_not_only_when_used() {
        let ssh = verb_help(VERBS.iter().find(|v| v.name == "ssh").unwrap());
        // ⛔ Asserted on `-L, --forward-local`, not on `-L SPEC`. The first
        // version of this test looked for `-L SPEC` and failed ⛔ **not because
        // the help was wrong but because the assertion named a spelling the
        // help does not use**: `flag_line` prints short, long and metavariable,
        // so the row reads `-L, --forward-local SPEC`. ⛔ A test that fails
        // because it asserted the wrong string teaches the next reader to
        // distrust it.
        assert!(ssh.contains("-L, --forward-local SPEC"), "{ssh}");
        assert!(ssh.contains("refused"), "{ssh}");
        assert!(ssh.contains("-W HOST:PORT"), "{ssh}");
    }

    /// ⛔ **Every flag row is separated from its description.** ⛔ This is the
    /// regression test for the layout defect: `-W, --stdio-forward HOST:PORT`
    /// is 28 characters, the column was a hardcoded 26, and `format!("{:<26$}")`
    /// pads without truncating — so the description ran straight into the
    /// metavariable and read *"HOST:PORTforward stdio to a host:port"*. ⛔ The
    /// column is derived from the rows now, and this asserts the result.
    #[test]
    fn no_flag_runs_into_its_description() {
        for v in VERBS {
            let column = flag_column(v.flags);
            for row in v.flags {
                let line = flag_line(row, column);
                // ⛔ **The defect was the metavariable running into the
                // description with no gap**: `-W, --stdio-forward HOST:PORT`
                // rendered as `...HOST:PORTforward stdio to a host:port`.
                //
                // ⛔ So the claim is about the **full** spelling — short, long
                // and metavariable together — being followed by whitespace or
                // end-of-line. ⛔ `rfind` rather than `find`, because `-N` is a
                // substring of `-N, --no-remote-command`, and the full form is
                // what actually appears in the output.
                let needle = match (row.short, row.arg) {
                    (Some(c), Some(a)) => format!("-{c}, --{} {a}", row.long),
                    (Some(c), None) => format!("-{c}, --{}", row.long),
                    (None, Some(a)) => format!("--{} {a}", row.long),
                    (None, None) => format!("--{}", row.long),
                };
                let idx = line.rfind(&needle).unwrap_or_else(|| {
                    panic!("{}/{}: {needle:?} absent from {line:?}", v.name, row.long)
                });
                let rest = &line[idx + needle.len()..];
                assert!(
                    rest.is_empty() || rest.starts_with(char::is_whitespace),
                    "{}/{}: {:?} runs into {:?}",
                    v.name,
                    row.long,
                    needle,
                    &rest[..rest.len().min(12)]
                );
            }
        }
    }

    #[test]
    fn ssh_help_says_p_is_a_tag_here_and_a_port_on_scp() {
        let ssh = verb_help(VERBS.iter().find(|v| v.name == "ssh").unwrap());
        let cp = verb_help(VERBS.iter().find(|v| v.name == "cp").unwrap());
        assert!(ssh.contains("-P on ssh is OpenSSH's Tag"), "{ssh}");
        assert!(cp.contains("-P here is the port"), "{cp}");
    }

    /// ⛔ **`-P` says it once.** ⛔ The row's own help ended with the same
    /// sentence [`help_text`] appends for [`FlagKind::Accepted`], so `--help`
    /// and the man page both printed *"accepted and ignored (accepted and
    /// ignored)"* — and the parity gate reproduced the duplication in both
    /// renderers, because both walk this function.
    #[test]
    fn an_accepted_flag_says_it_once() {
        let ssh = verb_help(VERBS.iter().find(|v| v.name == "ssh").unwrap());
        let line = ssh
            .lines()
            .find(|l| l.contains("--tag"))
            .expect("-P, --tag is in the ssh help");
        assert_eq!(
            line.matches("accepted and ignored").count(),
            1,
            "the sentence must appear once: {line:?}"
        );
    }
}