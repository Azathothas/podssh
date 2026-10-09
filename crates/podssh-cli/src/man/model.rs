//! The manual as data. Each part comes from a table of this binary: the
//! commands and their flags (`flags.rs`), their arguments (`tree.rs`), the
//! `-o` keywords (`ssh/keywords.rs`), and the facts, notes and examples in
//! this directory. Two renderers walk the result (`text.rs` and `roff.rs`),
//! so the text and the man page cannot describe different programs.

use crate::flags::{FlagRow, Verb, VERBS};
use crate::ssh::keywords;

/// Part of a term: what a user types, a value to put in its place, or text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Span {
    Lit(String),
    Var(String),
    Plain(String),
}

/// The plain text of a term, as the text page shows it.
pub fn plain(spans: &[Span]) -> String {
    spans
        .iter()
        .map(|s| match s {
            Span::Lit(t) | Span::Var(t) | Span::Plain(t) => t.as_str(),
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// Prose, filled to the width of the page.
    Para(String),
    /// One line kept as it is, such as a synopsis.
    Line(Vec<Span>),
    /// A heading inside a section ("Options").
    Sub(String),
    /// A term and its description: a flag, an argument, a variable, a file.
    Item { term: Vec<Span>, text: String },
    /// Terms and descriptions in two columns, such as the list of commands.
    Table(Vec<(Vec<Span>, String)>),
    /// What a command line does, then the command line.
    Example { text: String, command: String },
}

pub struct Section {
    /// The name `podssh man NAME` selects it by.
    pub key: &'static str,
    /// Other names that select it, such as a command's aliases.
    pub aliases: Vec<&'static str>,
    pub heading: String,
    /// A command's section; the renderers put these under one heading.
    pub command: bool,
    pub blocks: Vec<Block>,
}

pub struct Manual {
    /// The text before the first section.
    pub intro: Vec<Block>,
    pub sections: Vec<Section>,
}

impl Manual {
    /// The section for `name`: a key or an alias, in any case.
    pub fn find(&self, name: &str) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.key.eq_ignore_ascii_case(name) || s.aliases.iter().any(|a| a.eq_ignore_ascii_case(name)))
    }

    pub fn keys(&self) -> Vec<&'static str> {
        self.sections.iter().map(|s| s.key).collect()
    }
}

/// The whole manual of this binary.
pub fn manual() -> Manual {
    let mut sections: Vec<Section> = VERBS.iter().map(command_section).collect();
    sections.extend(super::facts::sections());
    sections.push(super::examples::section());
    sections.push(see_also());
    Manual { intro: intro(), sections }
}

fn lit(t: impl Into<String>) -> Span {
    Span::Lit(t.into())
}

fn var(t: impl Into<String>) -> Span {
    Span::Var(t.into())
}

fn text(t: impl Into<String>) -> Span {
    Span::Plain(t.into())
}

fn para(t: impl Into<String>) -> Block {
    Block::Para(t.into())
}

/// A flag as a user types it: `-p, --port PORT`.
pub fn flag_term(row: &FlagRow) -> Vec<Span> {
    let mut t = Vec::new();
    if let Some(c) = row.short {
        t.push(lit(format!("-{c}")));
        t.push(text(", "));
    }
    t.push(lit(format!("--{}", row.long)));
    if let Some(a) = row.arg {
        t.push(text(" "));
        t.push(var(a));
    }
    t
}

fn intro() -> Vec<Block> {
    let mut blocks = vec![para(
        "podssh carries SSH, or another TCP stream, through a WebSocket relay on port 443. It is one \
         static binary for hosts whose only way out is HTTPS, often through an HTTP CONNECT proxy. It \
         needs no installed ssh, no root, no pty, no DNS and no user database entry.",
    )];
    blocks.push(Block::Sub("Commands".into()));
    blocks.push(Block::Table(
        VERBS
            .iter()
            .map(|v| (vec![lit(v.name)], format!("{}{}", v.about, crate::help::availability_note(v))))
            .collect(),
    ));
    blocks.push(Block::Sub("Options before a command".into()));
    blocks.push(Block::Table(
        crate::flags::TOP_OPTIONS
            .iter()
            .map(|(short, long, about)| (vec![lit(*short), text(", "), lit(*long)], about.to_string()))
            .collect(),
    ));
    blocks.push(Block::Sub("Start here".into()));
    blocks.extend(super::examples::start_here());
    blocks.push(Block::Sub("Conventions".into()));
    blocks.push(para("Answers go to stdout. Diagnostics go to stderr, so stdout can carry a protocol."));
    blocks.push(para(format!(
        "A question (a host key, a password, a passphrase) goes to the controlling terminal or to \
         SSH_ASKPASS. With neither, podssh refuses at once and names the remedy. When stdin, stdout and \
         stderr are all redirected, a question on the terminal waits {} s at most.",
        podssh_ssh::terminal::UNWATCHED_PROMPT.as_secs()
    )));
    blocks.push(para(
        "With no command, podssh lists the commands on stderr and exits 64. It never takes a word as a \
         host: podssh example.org prints the line to type, podssh ssh example.org.",
    ));
    blocks.push(para(
        "podssh COMMAND --help gives the options of one command. podssh man COMMAND gives one section \
         of this manual. This manual is generated from the tables of this binary, so it describes this \
         binary and no other version.",
    ));
    blocks
}

/// The term of a positional argument: its value name, with `...` when it
/// takes more than one word.
fn argument_term(arg: &clap::Arg) -> Vec<Span> {
    let name = arg
        .get_value_names()
        .and_then(|n| n.first())
        .map(|n| n.to_string())
        .unwrap_or_else(|| arg.get_id().as_str().to_ascii_uppercase());
    let many = arg.get_num_args().is_some_and(|r| r.max_values() > 1);
    vec![var(if many { format!("{name}...") } else { name })]
}

fn command_section(verb: &'static Verb) -> Section {
    let mut blocks = vec![para(verb.about)];
    let others: Vec<&str> = verb.aliases.iter().copied().filter(|a| *a != verb.name).collect();
    if !others.is_empty() {
        let mut line = vec![text("Other names: ")];
        for (i, a) in others.iter().enumerate() {
            if i > 0 {
                line.push(text(", "));
            }
            line.push(lit(format!("podssh {a}")));
        }
        blocks.push(Block::Line(line));
    }
    blocks.push(Block::Line(vec![
        lit(format!("podssh {}", verb.name)),
        text(" "),
        text(crate::help::usage_tail(verb)),
    ]));
    // The command and the topic share a word; point from one to the other.
    if verb.name == "relay" {
        blocks.push(para(
            "The relay that podssh uses (hosts, failover, tokens, limits) is in THE RELAY: podssh man \
             relay-facts.",
        ));
    }
    // The sentence of --help, in place of the options.
    if let Some(sentence) = crate::help::availability_sentence(verb) {
        blocks.push(para(sentence));
        return section_of(verb, blocks);
    }

    let command = crate::tree::verb_command(verb);
    let arguments: Vec<Block> = command
        .get_positionals()
        .map(|a| Block::Item { term: argument_term(a), text: a.get_help().map(|h| h.to_string()).unwrap_or_default() })
        .collect();
    if !arguments.is_empty() {
        blocks.push(Block::Sub("Arguments".into()));
        blocks.extend(arguments);
    }
    blocks.push(Block::Sub("Options".into()));
    for row in verb.flags.iter().chain(std::iter::once(&crate::flags::HELP_FLAG)) {
        blocks.push(Block::Item { term: flag_term(row), text: crate::help::help_text(row) });
    }
    if verb.name == "ssh" {
        blocks.extend(keyword_blocks());
    }
    let notes = super::notes::for_verb(verb.name);
    if !notes.is_empty() {
        blocks.push(Block::Sub("Notes".into()));
        blocks.extend(notes.iter().map(|n| para(*n)));
    }
    section_of(verb, blocks)
}

fn section_of(verb: &'static Verb, blocks: Vec<Block>) -> Section {
    Section {
        key: verb.name,
        aliases: verb.aliases.iter().copied().filter(|a| *a != verb.name).collect(),
        heading: verb.name.to_ascii_uppercase(),
        command: true,
        blocks,
    }
}

/// The `-o` keywords of `podssh ssh`.
fn keyword_blocks() -> Vec<Block> {
    let mut blocks = vec![Block::Sub("Keywords for -o NAME=VALUE".into())];
    blocks.push(para(
        "The name is not case-sensitive. NAME=VALUE, NAME VALUE and NAME = VALUE are the same. For a \
         single value, the first one given wins, as in OpenSSH. An unknown keyword is an error before \
         podssh connects.",
    ));
    for k in keywords::HONOURED {
        blocks.push(Block::Item { term: vec![lit(k.name), text("="), var(k.value)], text: k.help.to_string() });
    }
    for (name, why) in keywords::REFUSED {
        blocks.push(Block::Item { term: vec![lit(*name)], text: format!("refused: {why}") });
    }
    blocks.push(para(format!(
        "Accepted and ignored, because they change nothing that podssh does: {}.",
        keywords::IGNORED.join(", ")
    )));
    blocks
}

fn see_also() -> Section {
    Section {
        key: "see-also",
        aliases: vec![],
        heading: "SEE ALSO".into(),
        command: false,
        blocks: vec![
            Block::Item {
                term: vec![lit("podssh"), text(" "), var("COMMAND"), text(" "), lit("--help")],
                text: "the options of one command".into(),
            },
            Block::Item {
                term: vec![lit("podssh man"), text(" "), var("SECTION")],
                text: "one section of this manual".into(),
            },
            Block::Item { term: vec![lit("podssh man --roff")], text: "this manual as a man(7) page".into() },
            Block::Item {
                term: vec![lit("podssh doctor")],
                text: "what this host allows, and whether the relay works".into(),
            },
            Block::Item {
                term: vec![text(env!("CARGO_PKG_REPOSITORY"))],
                text: "the source, the releases and the issues".into(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::Availability;

    fn all_items(s: &Section) -> Vec<(String, String)> {
        s.blocks
            .iter()
            .filter_map(|b| match b {
                Block::Item { term, text } => Some((plain(term), text.clone())),
                _ => None,
            })
            .collect()
    }

    /// Each flag of each working command is in its section, with its own
    /// spelling, value name and the sentence `--help` prints.
    #[test]
    fn each_flag_of_each_working_command_is_in_its_section() {
        let m = manual();
        for verb in VERBS.iter().filter(|v| crate::flags::availability(v) == Availability::Works) {
            let items = all_items(m.find(verb.name).expect("a section for each verb"));
            for row in verb.flags.iter().chain(std::iter::once(&crate::flags::HELP_FLAG)) {
                let want = (plain(&flag_term(row)), crate::help::help_text(row));
                assert!(items.contains(&want), "{}: {want:?} is missing", verb.name);
            }
        }
    }

    /// The control for the test above: a section that left out a flag fails.
    #[test]
    fn a_section_without_a_flag_is_detected() {
        let m = manual();
        let mut items = all_items(m.find("ssh").unwrap());
        let row = &crate::flags::SSH_FLAGS[0];
        let want = (plain(&flag_term(row)), crate::help::help_text(row));
        items.retain(|i| *i != want);
        assert!(!items.contains(&want));
    }

    #[test]
    fn each_verb_and_alias_finds_its_section() {
        let m = manual();
        for verb in VERBS {
            for name in verb.aliases {
                assert_eq!(m.find(name).map(|s| s.key), Some(verb.name), "{name}");
            }
        }
        assert!(m.find("nonsense").is_none());
    }

    #[test]
    fn a_command_that_does_not_work_says_so_and_shows_no_options() {
        let m = manual();
        for verb in VERBS.iter().filter(|v| crate::flags::availability(v) != Availability::Works) {
            let s = m.find(verb.name).unwrap();
            assert!(all_items(s).is_empty(), "{} shows options", verb.name);
            let says = s.blocks.iter().any(|b| matches!(b, Block::Para(t) if t.contains("exits 70")));
            assert!(says, "{} does not say that it exits 70", verb.name);
        }
    }

    #[test]
    fn each_keyword_is_in_the_ssh_section() {
        let m = manual();
        let s = m.find("ssh").unwrap();
        let items = all_items(s);
        for k in keywords::HONOURED {
            assert!(items.iter().any(|(t, _)| t == &format!("{}={}", k.name, k.value)), "{}", k.name);
        }
        for (name, _) in keywords::REFUSED {
            assert!(items.iter().any(|(t, _)| t == name), "{name}");
        }
        let ignored = s.blocks.iter().any(|b| matches!(b, Block::Para(t) if t.contains("AddKeysToAgent")));
        assert!(ignored, "the ignored keywords are missing");
    }

    #[test]
    fn the_arguments_come_from_the_parser() {
        let m = manual();
        let items = all_items(m.find("proxy").unwrap());
        assert!(items.iter().any(|(t, _)| t == "HOST"), "{items:?}");
        assert!(items.iter().any(|(t, _)| t == "PORT"), "{items:?}");
        let ssh = all_items(m.find("ssh").unwrap());
        assert!(ssh.iter().any(|(t, _)| t == "COMMAND..."), "{ssh:?}");
    }

    /// A name selects one section: no two sections share a key or an alias,
    /// and each topic's key finds that topic.
    #[test]
    fn each_name_selects_one_section() {
        let m = manual();
        let mut seen: Vec<String> = Vec::new();
        for s in &m.sections {
            for name in std::iter::once(s.key).chain(s.aliases.iter().copied()) {
                let name = name.to_ascii_lowercase();
                assert!(!seen.contains(&name), "{name:?} names two sections");
                seen.push(name);
            }
        }
        for s in m.sections.iter().filter(|s| !s.command) {
            assert_eq!(m.find(s.key).map(|f| f.heading.as_str()), Some(s.heading.as_str()), "{}", s.key);
        }
        assert_eq!(m.find("relay-facts").map(|s| s.heading.as_str()), Some("THE RELAY"));
        assert!(m.find("relay").is_some_and(|s| s.command), "relay is the command");
    }

    /// The help of the `man` section argument names each section there is.
    #[test]
    fn the_section_argument_names_each_topic() {
        let m = manual();
        let help = crate::tree::verb_command(crate::flags::verb_for("man").unwrap())
            .get_positionals()
            .find_map(|a| a.get_help().map(|h| h.to_string()))
            .unwrap();
        for s in m.sections.iter().filter(|s| !s.command) {
            assert!(help.contains(s.key), "the help of SECTION does not name {:?}: {help}", s.key);
        }
    }
}
