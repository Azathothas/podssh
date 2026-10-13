//! `--help`, rendered from [`crate::flags::VERBS`].
//!
//! **Renderer one of two, and the tree is shared.** `podssh man` is the other
//! and walks the same [`crate::flags::VERBS`]; nothing here and nothing there
//! writes a flag down, so the manual's three obligations (`docs/cli.md`, "The manual") hold by
//! having one list rather than by being checked afterwards.
//!
//! **The width is fixed at 100 columns and is not probed.** `clap`'s
//! `wrap_help` feature is deliberately off in `Cargo.toml`: it pulls
//! `terminal_size`, which is a capability probe, and `AGENTS.md` (section 5, rule 1) forbids
//! depending on a capability that has not been probed. A fixed width is
//! also what makes the man/help parity check a string comparison rather than a
//! measurement of somebody's terminal.

use crate::flags::{FlagKind, Verb, VERBS};
use std::fmt::Write as _;

/// The column the flag column ends at, and the width the help wraps to.
const WIDTH: usize = 100;

/// **The help column is measured from the rows, not a constant.**
///
/// It was a constant of 26 and that produced a real defect: the test below
/// caught `-W, --stdio-forward HOST:PORT` running straight into its help text
/// with no gap — *"HOST:PORTforward stdio to a host:port"* — because that row
/// is 28 characters wide and `format!("{:<26$}")` does not truncate, it only
/// pads. **Any row wider than the constant silently loses its separator**,
/// so a fixed width is a layout bug waiting for the longest flag name.
///
/// Deriving it means adding a flag with a long name cannot break `--help`,
/// which is the same "one list, two renderers" argument the tree rests on: a
/// constant is a second thing to keep in step with the table. A verb's block
/// measures its rows and `--help` together (`block_rows`).
pub fn flag_column(rows: &[crate::flags::FlagRow]) -> usize {
    // Measured on the text `flag_line` prints, prefix included: measuring
    // `usage_form` left out the `-c,` / three-space prefix, so verbs whose
    // flags have no short form got a column too narrow to separate the two.
    rows.iter().map(|r| flag_left(r).chars().count() + 2).max().unwrap_or(0).min(MAX_FLAG_COLUMN)
}

/// The widest the flag column may get before the help wraps under it.
///
/// 38, not 34: `--StrictHostKeyChecking yes|no|ask|off` is exactly 37
/// characters, and at a cap of 34 that one row wrapped to its own line while
/// every other row sat in the column — an inconsistent help that looks like a
/// mistake in the one flag a security-conscious user is most likely to look up.
/// A cap above the widest real row costs nothing and keeps the column even;
/// a cap below it is a trap for whoever adds the next long flag.
const MAX_FLAG_COLUMN: usize = 38;

/// One rendered flag line: `-p, --port PORT  port to connect to`.
///
/// **The spelling here is the contract with the manual.** The parity gate extracts flag
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
        // Too wide to sit beside its description: the description goes on
        // the next line rather than being run into.
        format!("{left}\n    {}", help_text(row))
    } else {
        format!("{left:<column$}{}", help_text(row))
    }
}

/// The rows of a verb's `OPTIONS:` block: its own, then `--help`, which each
/// verb takes. One list, so that one column holds them all.
fn block_rows(flags: &[crate::flags::FlagRow]) -> Vec<crate::flags::FlagRow> {
    flags.iter().copied().chain(std::iter::once(crate::flags::HELP_FLAG)).collect()
}

/// The lines of an `OPTIONS:` block, `--help` last.
///
/// **`--help` is a row like the others.** It had a line of its own,
/// `format!("{:<12}{}", "    --help", ...)`: four spaces in, where each other
/// long option starts eight in, and its text in a column of its own, so the
/// block read as two tables, and a reader that parsed it by column could miss
/// `--help`. It stays the last line, with no blank line before it: the parity
/// gate reads a block up to its first blank line.
fn options_lines(flags: &[crate::flags::FlagRow]) -> String {
    let rows = block_rows(flags);
    let column = flag_column(&rows);
    let mut s = String::new();
    for row in &rows {
        s.push_str(&format!("    {}\n", flag_line(row, column)));
    }
    s
}

/// **The suffix that says what a flag is *not* doing.** A flag that parses
/// and refuses must not read like a flag that works, and a flag that is
/// accepted and ignored must say so in `--help` and not only when used.
///
/// **Public because there are two renderers and one sentence.** The manual
/// prints this text verbatim, **and the parity gate asserts the page carries
/// it** — a description that stopped being true is not caught by a set
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
    // The banner's sentence is [`crate::flags::ABOUT`] and not a copy of it:
    // The manual page writes the same sentence in its `.SH NAME`, and a sentence
    // with two copies in two renderers is exactly the drift this crate's tree
    // exists to prevent.
    s.push_str(&format!("podssh - {}\n\n", crate::flags::ABOUT));
    s.push_str("USAGE:\n    podssh <SUBCOMMAND> [OPTIONS]\n\n");
    s.push_str("podssh never guesses a destination. With no subcommand it prints this\n");
    s.push_str("list and exits non-zero; it does not become an implicit ssh.\n\n");
    s.push_str("OPTIONS:\n");
    // **The column is derived from the rows, and it has to be.**
    // `format!("{:<12}{}", "  -h, --help", "Print help")` produced
    // `  -h, --helpPrint help` — the left part is **exactly twelve
    // characters**, and `{:<12}` pads without separating, so there was no gap
    // at all. This is the same defect the test `no_flag_runs_into_its_description`
    // records for `flag_line`, one layer up: a constant that happens to equal
    // its widest row is a separator that disappears. The parity gate reads
    // this block, and it read `--helpPrint` as a flag — which is what a user
    // reading it would conclude too.
    let rows: Vec<(String, &str)> =
        crate::flags::TOP_OPTIONS.iter().map(|(short, long, about)| (format!("  {short}, {long}"), *about)).collect();
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
    // By purpose (T-013): each group's name, then its verbs, with no blank
    // line, so that the block ends where the list ends.
    let grouped = crate::flags::GROUPS.iter().flat_map(|(group, names)| {
        let verbs = names.iter().filter_map(|n| VERBS.iter().find(|v| v.name == *n));
        std::iter::once(Err(*group)).chain(verbs.map(Ok))
    });
    for item in grouped {
        let v = match item {
            Ok(v) => v,
            Err(group) => {
                s.push_str(&format!("  {group}\n"));
                continue;
            }
        };
        s.push_str(&format!("    {:w$}  {}{}\n", v.name, v.about, availability_note(v)));
        // Aliases are printed beside the verb they resolve to, because a user
        // who types `podssh irc` and gets help for `chat` deserves to know
        // they are the same command.
        if v.aliases.len() > 1 {
            let others: Vec<&str> = v.aliases.iter().copied().filter(|a| *a != v.name).collect();
            s.push_str(&format!("    {:w$}  aliases: {}\n", "", others.join(", ")));
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

/// The sentence that `--help` and the manual give a verb that does not work
/// here, in place of its options. One copy, so the two cannot differ.
pub fn availability_sentence(verb: &Verb) -> Option<&'static str> {
    match crate::flags::availability(verb) {
        crate::flags::Availability::Works => None,
        crate::flags::Availability::NotYet => Some("Not implemented yet. The command exits 70 and does nothing."),
        crate::flags::Availability::NotInBuild => Some(
            "Not in this build: this binary was built without the cargo feature ts. The command exits 70 \
             and does nothing.",
        ),
    }
}

/// Render one verb's help, from the same rows the parser was built from.
pub fn verb_help(verb: &'static Verb) -> String {
    let mut s = String::new();
    s.push_str(&format!("podssh {} - {}{}\n\n", verb.name, verb.about, availability_note(verb)));
    s.push_str(&format!("USAGE:\n    podssh {} {}\n\n", verb.name, usage_tail(verb)));
    // A command that does nothing shows no option but --help, as the manual
    // does: its options cannot be used.
    if let Some(sentence) = availability_sentence(verb) {
        s.push_str(&wrap(sentence));
        s.push_str("\n\nOPTIONS:\n");
        s.push_str(&options_lines(&[]));
        return s;
    }

    // **The `OPTIONS:` header is printed even for a verb with no flags of
    // its own**, because `--help` is one of its options and a headerless
    // option line is not a block: the parity gate reads the flags inside an
    // `OPTIONS:` block, so a line outside one is a flag the gate cannot see.
    // The output for `ssh` and `cp` is unchanged; the flagless verbs gain
    // the two-line block they always should have had.
    s.push_str("OPTIONS:\n");
    s.push_str(&options_lines(verb.flags));
    s.push('\n');
    s.push_str(&verb_notes(verb));
    s
}

/// The notes under a verb's options: what its flags cannot say.
pub fn verb_notes(verb: &Verb) -> String {
    let mut s = String::new();
    if verb.name == "ssh" {
        s.push('\n');
        s.push_str("-L and -D listen here, and each connection that they take goes on from\n");
        s.push_str("  the server; -W HOST:PORT carries one connection, with no listener.\n");
        s.push_str("-R [BIND:]PORT:HOST:HOSTPORT: the server listens, and each connection\n");
        s.push_str("  reaches HOST:HOSTPORT from here, through HTTPS_PROXY when it is set.\n");
        s.push_str("-P on ssh is OpenSSH's Tag, which Match tagged reads, not a port. On\n");
        s.push_str("  scp and sftp, -P is the port. The meaning is per-verb.\n");
    }
    if verb.name == "keygen" {
        s.push('\n');
        s.push_str("-V here is the validity of a certificate, with -s; podssh -V prints the version.\n");
        s.push_str("-n, -s, -I, -O and -U mean one thing with -Y and another with -s, as in ssh-keygen.\n");
    }
    if matches!(verb.name, "cp" | "mv" | "scp" | "sftp" | "edit") {
        s.push('\n');
        s.push_str("-P here is the port, as on scp and sftp. On ssh it is a Tag.\n");
    }
    s
}

/// **The usage tail, and it is public for the same reason [`help_text`] is:**
/// The manual page prints `podssh <verb> <this>`, and the parity gate asserts the
/// page carries the string `--help` prints rather than a second copy of it.
pub fn usage_tail(verb: &Verb) -> &'static str {
    match verb.name {
        "ssh" => "[OPTIONS] [--] [user@]host [COMMAND...]",
        "each" => "[OPTIONS] HOSTS [--] COMMAND...",
        "containers" => "[OPTIONS] [user@]host",
        "cp" | "mv" | "scp" => "[OPTIONS] SRC... DST",
        "sftp" => "[OPTIONS] DESTINATION",
        "edit" => "[OPTIONS] [user@]host:PATH",
        "chat" => "[OPTIONS] PEER",
        "man" => "[OPTIONS] [SECTION]",
        "relay" => "[OPTIONS] SUBCOMMAND [NAME | HOST PORT]",
        "node" => "[OPTIONS] NAME TARGET [ROUTE=TARGET]...",
        "operator" => "[OPTIONS] NAME",
        "proxy" => "[OPTIONS] [--] HOST PORT",
        "health" => "[OPTIONS] [user@]host",
        "play" => "[OPTIONS] FILE",
        "config" => "import FORMAT FILE",
        _ => "[OPTIONS]",
    }
}

/// The version string. Read from the manifest at compile time, so it cannot
/// drift from the crate it ships in.
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// **Wrap to [`WIDTH`] without probing the terminal.** A word too long for
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

    /// **The top-level block, and the defect that was in it.**
    /// `format!("{:<12}{}", "  -h, --help", "Print help")` printed
    /// `  -h, --helpPrint help`: the left part is exactly twelve characters and
    /// `{:<12}` pads without separating. The parser the parity gate uses read
    /// `--helpPrint` as a flag name, and so would a user. This is the same
    /// failure as `no_flag_runs_into_its_description` below, in the block that
    /// test does not cover.
    #[test]
    fn no_top_level_option_runs_into_its_description() {
        let h = top_level_help();
        for (left, right) in [
            ("  -h, --help", "Print help; --help COMMAND prints the help of one command"),
            ("  -V, --version", "Print version"),
        ] {
            let line = h
                .lines()
                .find(|l| l.starts_with(left))
                .unwrap_or_else(|| panic!("{left:?} is not in the top-level help"));
            let rest = &line[left.len()..];
            assert!(rest.starts_with(char::is_whitespace), "{left:?} runs straight into {rest:?}");
            assert_eq!(rest.trim(), right, "{line:?}");
        }
    }

    #[test]
    fn help_prints_an_alias_beside_its_verb() {
        let h = top_level_help();
        assert!(h.contains("aliases: irc"), "{h}");
        assert!(h.contains("aliases: ssh-keygen"), "{h}");
    }

    #[test]
    fn a_refused_flag_says_so_in_help_not_only_when_used() {
        let ssh = verb_help(VERBS.iter().find(|v| v.name == "ssh").unwrap());
        // Asserted on `-L, --forward-local`, not on `-L SPEC`. The first
        // version of this test looked for `-L SPEC` and failed **not because
        // the help was wrong but because the assertion named a spelling the
        // help does not use**: `flag_line` prints short, long and metavariable,
        // so the row reads `-L, --forward-local SPEC`. A test that fails
        // because it asserted the wrong string teaches the next reader to
        // distrust it.
        assert!(ssh.contains("-L, --forward-local SPEC"), "{ssh}");
        assert!(ssh.contains("refused"), "{ssh}");
        assert!(ssh.contains("-W HOST:PORT"), "{ssh}");
    }

    /// -R needs no local listener: the server listens (T-035). Its lines say
    /// so, and neither borrow the cause of -L and -D nor offer -W, which
    /// carries the other direction.
    #[test]
    fn the_lines_about_r_say_that_the_server_listens() {
        let ssh = verb_help(VERBS.iter().find(|v| v.name == "ssh").unwrap());
        let lines: Vec<&str> = ssh.lines().filter(|l| l.contains("-R")).collect();
        assert!(lines.len() >= 2, "the row and the note: {lines:#?}");
        assert!(lines.iter().any(|l| l.contains("the server listens")), "{lines:#?}");
        for line in lines {
            for word in ["never", "local listener", "-W", "not implemented"] {
                assert!(!line.contains(word), "{word}: {line}");
            }
        }
    }

    /// **Every flag row is separated from its description.** This is the
    /// regression test for the layout defect: `-W, --stdio-forward HOST:PORT`
    /// is 28 characters, the column was a hardcoded 26, and `format!("{:<26$}")`
    /// pads without truncating — so the description ran straight into the
    /// metavariable and read *"HOST:PORTforward stdio to a host:port"*. The
    /// column is derived from the rows now, and this asserts the result, for
    /// `--help` too, in the column that the block gives it.
    #[test]
    fn no_flag_runs_into_its_description() {
        for v in VERBS {
            let rows = block_rows(v.flags);
            let column = flag_column(&rows);
            for row in &rows {
                let line = flag_line(row, column);
                // **The defect was the metavariable running into the
                // description with no gap**: `-W, --stdio-forward HOST:PORT`
                // rendered as `...HOST:PORTforward stdio to a host:port`.
                //
                // So the claim is about the **full** spelling — short, long
                // and metavariable together — being followed by whitespace or
                // end-of-line. `rfind` rather than `find`, because `-N` is a
                // substring of `-N, --no-remote-command`, and the full form is
                // what actually appears in the output.
                let needle = match (row.short, row.arg) {
                    (Some(c), Some(a)) => format!("-{c}, --{} {a}", row.long),
                    (Some(c), None) => format!("-{c}, --{}", row.long),
                    (None, Some(a)) => format!("--{} {a}", row.long),
                    (None, None) => format!("--{}", row.long),
                };
                let idx = line
                    .rfind(&needle)
                    .unwrap_or_else(|| panic!("{}/{}: {needle:?} absent from {line:?}", v.name, row.long));
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
        // The notes of cp, which its help shows once cp works.
        let cp = verb_notes(VERBS.iter().find(|v| v.name == "cp").unwrap());
        assert!(ssh.contains("-P on ssh is OpenSSH's Tag"), "{ssh}");
        assert!(cp.contains("-P here is the port"), "{cp}");
    }

    /// **An accepted flag says it once.** `-P`'s row ended with the same
    /// sentence [`help_text`] appends for [`FlagKind::Accepted`], so `--help`
    /// and the man page both printed *"accepted and ignored (accepted and
    /// ignored)"* — and the parity gate reproduced the duplication in both
    /// renderers, because both walk this function. `-P` is honoured since
    /// T-045; scp's `-3` is accepted.
    #[test]
    fn an_accepted_flag_says_it_once() {
        let scp = verb_help(VERBS.iter().find(|v| v.name == "scp").unwrap());
        let line = scp.lines().find(|l| l.contains("--through-this-host")).expect("-3 is in the scp help");
        assert_eq!(line.matches("accepted and ignored").count(), 1, "the sentence must appear once: {line:?}");
        let ssh = verb_help(VERBS.iter().find(|v| v.name == "ssh").unwrap());
        let tag = ssh.lines().find(|l| l.contains("--tag")).expect("-P, --tag is in the ssh help");
        assert!(!tag.contains("accepted and ignored"), "{tag:?}");
    }
}
