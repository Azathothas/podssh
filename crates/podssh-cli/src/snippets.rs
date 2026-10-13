//! Snippets (T-187): commands kept in the `[snippets]` table of the
//! settings file (T-048), one `NAME COMMAND` on each line, which
//! `podssh ssh --snippet NAME HOST [WORDS]` and `podssh each --snippet NAME
//! HOSTS [WORDS]` run. A command holds placeholders: `{{host}}`, `{{user}}`
//! and `{{port}}`, the values of the connection, and `{{1}}` to `{{9}}`,
//! the words after the host. Each value goes in quoted for a POSIX shell,
//! one word that runs nothing, and the whole command, its values in, is
//! shown before it runs: asked `Run it? [y/N]` on the terminal or through
//! `SSH_ASKPASS`, or with `--yes` said on stderr and run unasked. With
//! nobody to ask (also under `BatchMode`) and no `--yes`, the run is
//! refused (64) before anything connects.
//!
//! A placeholder that is not one of those, one inside the command's own
//! quotes, where podssh's quotes would not hold, and a quote that does not
//! close are the file's fault (78, with its line), as each bad line of the
//! file is. `{{` that starts no name, as in Go's templates (`{{.Names}}`),
//! is text, and `\{{` is `{{`.

use std::collections::BTreeMap;
use std::io::Write;

use podssh_ssh::prompt::PromptError;
use podssh_ssh::Request;

use crate::relay_settings::Refusal;
use crate::settings::Value;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::Resolved;

/// The snippets of the settings file: each name, and its command as
/// written, with the line `FILE:LINE` that gives it.
pub type Snippets = BTreeMap<String, Value>;

/// The placeholders, as the messages name them.
const PLACEHOLDERS: &str = "{{host}}, {{user}}, {{port}} and {{1}} to {{9}}";

/// A part of a command: text as written, or a placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    Text(String),
    Host,
    User,
    Port,
    /// `{{N}}`: the Nth word after the host, from 1.
    Word(usize),
}

/// Where a character of a command stands: outside quotes, or in single or
/// double quotes, as a POSIX shell reads them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Within {
    Nothing,
    Single,
    Double,
}

/// The pieces of `command`. A placeholder is `{{NAME}}`, with blanks around
/// NAME or none; a NAME that is not a placeholder, a placeholder inside the
/// command's own quotes, and a quote that does not close are refused:
/// podssh quotes each value itself, and a quote of the command around it
/// would open what podssh closed.
pub fn pieces(command: &str) -> Result<Vec<Piece>, String> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut within = Within::Nothing;
    let mut rest = command;
    while let Some(c) = rest.chars().next() {
        // `\{{` is `{{` as text, for a template that needs its braces.
        if let Some(after) = rest.strip_prefix("\\{{") {
            text.push_str("{{");
            rest = after;
            continue;
        }
        let found = if rest.starts_with("{{") { placeholder(rest) } else { None };
        if let Some((name, used)) = found {
            let piece = match name {
                "host" => Piece::Host,
                "user" => Piece::User,
                "port" => Piece::Port,
                n if n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9') => {
                    Piece::Word(usize::from(n.as_bytes()[0] - b'0'))
                }
                other => {
                    return Err(format!(
                        "{{{{{other}}}}} is not a placeholder: the placeholders are {PLACEHOLDERS}, and \\{{{{ \
                         keeps {{{{ as text"
                    ))
                }
            };
            if within != Within::Nothing {
                let written = &rest[..used];
                return Err(format!(
                    "{written} is inside the command's own quotes: podssh quotes each value itself, so take those \
                     quotes away"
                ));
            }
            if !text.is_empty() {
                out.push(Piece::Text(std::mem::take(&mut text)));
            }
            out.push(piece);
            rest = &rest[used..];
            continue;
        }
        text.push(c);
        rest = &rest[c.len_utf8()..];
        match (within, c) {
            // An escaped character opens and closes nothing.
            (Within::Nothing | Within::Double, '\\') => {
                if let Some(next) = rest.chars().next() {
                    text.push(next);
                    rest = &rest[next.len_utf8()..];
                }
            }
            (Within::Nothing, '\'') => within = Within::Single,
            (Within::Nothing, '"') => within = Within::Double,
            (Within::Single, '\'') | (Within::Double, '"') => within = Within::Nothing,
            _ => {}
        }
    }
    // Also what a `#` that the file read as a comment leaves of a command.
    if within != Within::Nothing {
        return Err("a quote does not close: in the settings file a # that starts a word outside double quotes \
                    starts a comment, so put a command that holds one in double quotes"
            .into());
    }
    if !text.is_empty() {
        out.push(Piece::Text(text));
    }
    Ok(out)
}

/// `{{NAME}}` at the start of `text`, blanks around NAME allowed, NAME of
/// letters, digits and `_`: NAME, and the length of the whole. `None` for
/// other text, as `{{.Names}}` of a Go template.
fn placeholder(text: &str) -> Option<(&str, usize)> {
    let inner = &text[2..];
    let end = inner.find("}}")?;
    let name = inner[..end].trim_matches([' ', '\t']);
    let is_name = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    is_name.then_some((name, end + 4))
}

/// The count of words after the host that `pieces` takes: its highest
/// `{{N}}`.
pub fn words_taken(pieces: &[Piece]) -> usize {
    pieces
        .iter()
        .filter_map(|p| match p {
            Piece::Word(n) => Some(*n),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

/// What the placeholders take: the connection's host, user and port, and
/// the words after the host.
pub struct Values<'a> {
    pub host: &'a str,
    pub user: &'a str,
    pub port: u16,
    pub words: &'a [String],
}

/// The command of `pieces` with `values` in, each quoted.
pub fn expand(pieces: &[Piece], values: &Values) -> String {
    let mut out = String::new();
    for piece in pieces {
        match piece {
            Piece::Text(text) => out.push_str(text),
            Piece::Host => out.push_str(&quote(values.host)),
            Piece::User => out.push_str(&quote(values.user)),
            Piece::Port => out.push_str(&values.port.to_string()),
            Piece::Word(n) => out.push_str(&quote(values.words.get(n - 1).map_or("", String::as_str))),
        }
    }
    out
}

/// `value` as one word of a POSIX shell: as it is when each character is
/// one that no shell reads (zsh reads a `=` first, and each shell a `~`),
/// else in single quotes, each `'` as `'\''`. An empty value is `''`.
pub fn quote(value: &str) -> String {
    let plain = !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || "@%+:,./_-".contains(c));
    if plain {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The line `NAME COMMAND` of the `[snippets]` table, read at `at`, into
/// `snippets`. A name is as a group's: letters, digits, `.`, `_` and `-`,
/// not first a `.` or a `-`; a name given twice, or one that is a setting,
/// is refused. A command wholly in double quotes, with none inside, loses
/// them, so that a `#` in it is no comment.
pub fn snippet_line(snippets: &mut Snippets, name: &str, command: &str, at: &str) -> Result<(), String> {
    if !crate::hosts::is_group_name(name) {
        return Err(format!("{at}: {name} is not the name of a snippet: letters, digits, ., _ and -"));
    }
    if crate::settings::KEYWORDS.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)) {
        return Err(format!("{at}: {name} is a setting: put the settings before [snippets]"));
    }
    if let Some(first) = snippets.get(name) {
        let given = &first.at;
        return Err(format!("{at}: the snippet {name} is given at {given} already"));
    }
    let command = match command.strip_prefix('"').and_then(|c| c.strip_suffix('"')) {
        Some(inner) if !inner.contains('"') => inner,
        _ => command,
    };
    if command.trim().is_empty() {
        return Err(format!("{at}: the snippet {name} needs a command"));
    }
    pieces(command).map_err(|why| format!("{at}: the snippet {name}: {why}"))?;
    snippets.insert(name.to_string(), Value { text: command.to_string(), at: at.to_string() });
    Ok(())
}

/// The snippet of a command line: its name, its pieces, and the words after
/// the host that its `{{1}}` to `{{9}}` take.
#[derive(Debug, Clone)]
pub struct Chosen {
    pub name: String,
    pub pieces: Vec<Piece>,
    pub words: Vec<String>,
}

impl Chosen {
    /// The command for the connection of `resolved`, which becomes its
    /// request there. A `SessionType` of ssh_config that asks for no
    /// command is refused (64).
    pub fn apply(&self, resolved: &mut Resolved) -> Result<String, Refusal> {
        if !matches!(resolved.options.request, Request::Exec(_)) {
            return Err(Refusal::usage("SessionType in ssh_config asks for no command here, and --snippet runs one"));
        }
        let options = &resolved.options;
        let values = Values {
            host: &options.destination.host,
            user: &options.user,
            port: options.destination.port,
            words: &self.words,
        };
        let command = expand(&self.pieces, &values);
        resolved.options.request = Request::Exec(command.clone());
        Ok(command)
    }
}

/// The snippet of `args`, or none: the command line with the snippet as
/// written for its command, so that `Match` and the request see one, and
/// the snippet, whose values go in once each connection is resolved
/// ([`settle`]). The words after the host are its words, as many as its
/// placeholders take. Each refusal is 64, before anything connects.
pub fn choose(args: &SshArgs, snippets: &Snippets) -> Result<Option<(SshArgs, Chosen)>, Refusal> {
    let Some(name) = args.snippet.clone() else {
        if args.yes {
            return Err(Refusal::usage("--yes answers the question of --snippet, and no --snippet is given"));
        }
        return Ok(None);
    };
    let other = [
        ("-N", args.no_command),
        ("-s", args.subsystem),
        ("-W", args.stdio_forward.is_some()),
        ("-O", args.control_command.is_some()),
    ];
    if let Some((flag, _)) = other.iter().find(|(_, given)| *given) {
        return Err(Refusal::usage(format!("--snippet runs its command, and {flag} asks for none or another")));
    }
    let Some(value) = snippets.get(&name) else {
        let known: Vec<&str> = snippets.keys().map(String::as_str).collect();
        let have = if known.is_empty() { "none".to_string() } else { known.join(", ") };
        return Err(Refusal::usage(format!(
            "--snippet {name}: no snippet of that name in the settings file, which has {have}"
        )));
    };
    // The file was checked as it was read; a table that was not is still its fault.
    let at = &value.at;
    let pieces = pieces(&value.text).map_err(|why| Refusal::config(format!("{at}: the snippet {name}: {why}")))?;
    let (taken, given) = (words_taken(&pieces), args.command.len());
    if given != taken {
        let takes = match taken {
            0 => "no word".to_string(),
            1 => "one word, {{1}},".to_string(),
            n => format!("{n} words, {{{{1}}}} to {{{{{n}}}}},"),
        };
        let more = if given > taken {
            "; a snippet is the whole command, and a word that no placeholder takes would be a command of its own"
        } else {
            ""
        };
        return Err(Refusal::usage(format!("the snippet {name} takes {takes} after the host, and {given} came{more}")));
    }
    let chosen = Chosen { name, pieces, words: args.command.clone() };
    Ok(Some((SshArgs { command: vec![value.text.clone()], ..args.clone() }, chosen)))
}

/// What a run of the snippet `name` shows: each host, as `runs` names it,
/// and its command, each control character as its escape, so that a value
/// cannot hide a part of the command on a terminal. One command for many
/// hosts is shown once.
pub fn shown(name: &str, runs: &[(String, String)]) -> String {
    let visible = |text: &str| -> String {
        text.chars().map(|c| if c.is_control() { c.escape_default().to_string() } else { c.to_string() }).collect()
    };
    let first = runs.first().map_or("", |(_, command)| command.as_str());
    match runs {
        [(host, command)] => format!("the snippet {name} runs this on {host}:\n  {}\n", visible(command.as_str())),
        _ if runs.iter().all(|(_, command)| command == first) => {
            let hosts: Vec<&str> = runs.iter().map(|(host, _)| host.as_str()).collect();
            let count = runs.len();
            format!("the snippet {name} runs this on {count} hosts, {}:\n  {}\n", hosts.join(", "), visible(first))
        }
        _ => {
            let count = runs.len();
            let mut text = format!("the snippet {name} runs on {count} hosts:\n");
            for (host, command) in runs {
                text.push_str(&format!("  {host}: {}\n", visible(command.as_str())));
            }
            text
        }
    }
}

/// Who answers the question of a snippet: the terminal or `SSH_ASKPASS`
/// ([`Prompt`]), or a test's answers.
pub trait Asker {
    /// Whether anyone could answer, without asking.
    fn can_ask(&self) -> bool;
    fn ask(&mut self, question: &str) -> Result<String, PromptError>;
}

/// The terminal, or the program of `SSH_ASKPASS`, as podssh asks each
/// question.
pub struct Prompt;

impl Asker for Prompt {
    fn can_ask(&self) -> bool {
        podssh_ssh::prompt::can_ask()
    }

    fn ask(&mut self, question: &str) -> Result<String, PromptError> {
        podssh_ssh::prompt::ask(question, true).map(|answer| answer.as_str().to_string())
    }
}

/// How the question of a snippet goes: `--yes`; whether podssh's messages
/// are off (`-q`, or a `LogLevel` below `INFO`); and whether `BatchMode`
/// forbids a question.
#[derive(Debug, Clone, Copy, Default)]
pub struct Asking {
    pub yes: bool,
    pub quiet: bool,
    pub batch: bool,
}

/// Whether the snippet runs, after `shown`. With `--yes`, `shown` is said
/// on `err` (but with `quiet`) and it runs. Else the question, with `shown`
/// in it, goes where the answer comes from, as stderr may go elsewhere, and
/// only y or yes runs it. Each other end is a refusal (64), before anything
/// connects; with nobody to ask, `shown` is said first.
pub fn confirm(
    verb: &str,
    shown: &str,
    asking: Asking,
    asker: &mut dyn Asker,
    err: &mut dyn Write,
) -> Result<(), Refusal> {
    let can_ask = !asking.batch && asker.can_ask();
    if asking.yes || !can_ask {
        if !asking.quiet {
            for line in shown.lines() {
                let _ = writeln!(err, "podssh {verb}: {line}");
            }
        }
        if asking.yes {
            return Ok(());
        }
        let why = if asking.batch {
            "BatchMode forbids a question"
        } else {
            "there is no terminal and no SSH_ASKPASS to ask"
        };
        return Err(Refusal::usage(format!(
            "a snippet is asked before it runs, and {why}: give --yes to run it unasked; nothing has connected"
        )));
    }
    match asker.ask(&format!("podssh: {shown}Run it? [y/N] ")) {
        Ok(answer) if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") => Ok(()),
        Ok(_) => Err(Refusal::usage("not run: the answer was not yes; nothing has connected")),
        Err(why) => Err(Refusal::usage(format!("not run: {why}; nothing has connected"))),
    }
}

/// The snippet filled in for each connection of `runs`, a label as the
/// command line names the host and its resolved command line; then shown,
/// and asked once, before anything connects. `Ok` when it runs.
pub fn settle(
    verb: &str,
    chosen: &Chosen,
    runs: Vec<(String, &mut Resolved)>,
    asking: Asking,
    err: &mut dyn Write,
) -> Result<(), Refusal> {
    let mut commands = Vec::with_capacity(runs.len());
    for (label, resolved) in runs {
        commands.push((label, chosen.apply(resolved)?));
    }
    confirm(verb, &shown(&chosen.name, &commands), asking, &mut Prompt, err)
}
