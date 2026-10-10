//! Encoding: a [`Message`] back to bytes.
//!
//! **Split out of `message.rs`, which went over the 500-line gate with
//! the parser and the encoder together.** Parse and encode are two
//! directions of one grammar and deserve one file each — and a test
//! that says "round trip" reads as one claim rather than two.
//!
//! **What goes on the wire is checked first** ([`Message::to_wire`]). A CR or
//! LF in a parameter ends the line, and the server runs what follows as a
//! command of its own: `PRIVMSG #c :a\r\nQUIT` is two lines to it. A NUL ends
//! the line for a server written in C. In a middle, a space starts the next
//! parameter, a leading `:` starts the trailing, and an empty one moves the
//! next parameter into its place. Each is refused, never removed: removing a
//! character changes the user's text with no word to anyone.

use std::fmt;

use crate::irc::command::parse_command;
use crate::irc::command_view::trailing_of;
use crate::irc::message::{parse_prefix, split_params, Command, Message, ParseError};
use crate::irc::tag::{parse_tags, render_tags};

/// A part of a message that would change the line it is written in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsafe {
    /// What holds it: `the target`, `parameter 2 of JOIN`, `the trailing of
    /// PRIVMSG`.
    pub field: String,
    /// What it holds, escaped so that the refusal itself stays one line: `a
    /// CR (\r) at byte 1`, `a space at byte 2`, `a leading ':'`, `nothing`.
    pub found: String,
}

impl fmt::Display for Unsafe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} holds {}, which would change the IRC line it is written in", self.field, self.found)
    }
}

impl std::error::Error for Unsafe {}

/// A middle: not empty, no leading `:`, and no space, CR, LF or NUL.
pub fn check_middle(field: &str, value: &str) -> Result<(), Unsafe> {
    if value.is_empty() {
        return Err(Unsafe { field: field.to_string(), found: "nothing".into() });
    }
    if value.starts_with(':') {
        return Err(Unsafe { field: field.to_string(), found: "a leading ':'".into() });
    }
    check_chars(field, value, &[' ', '\r', '\n', '\0'])
}

/// A trailing: anything but CR, LF and NUL.
pub fn check_trailing(field: &str, value: &str) -> Result<(), Unsafe> {
    check_chars(field, value, &['\r', '\n', '\0'])
}

/// `value` holds none of `refused`. The transfer's fields refuse `|` too,
/// which separates them.
pub fn check_chars(field: &str, value: &str, refused: &[char]) -> Result<(), Unsafe> {
    match value.char_indices().find(|(_, c)| refused.contains(c)) {
        Some((at, c)) => Err(Unsafe { field: field.to_string(), found: format!("{} at byte {at}", named(c)) }),
        None => Ok(()),
    }
}

/// The place of a middle written with its `:`: the last parameter, when a
/// middle field holds it (`JOIN :#t`, as ngircd writes it).
fn colon_at(command: &Command, params: usize) -> Option<usize> {
    (params > 0 && command.last_colon() && trailing_of(command).is_none()).then(|| params - 1)
}

/// A character as a refusal names it: the escape a reader can type back.
fn named(c: char) -> String {
    match c {
        '\r' => r"a CR (\r)".into(),
        '\n' => r"an LF (\n)".into(),
        '\0' => r"a NUL (\0)".into(),
        ' ' => "a space".into(),
        other => format!("{other:?}"),
    }
}

impl Message {
    /// Parse one line, **without** its `\r\n`. A line that still carries
    /// its terminator parses, because [`crate::irc::framing::Reassembler`] strips it and a caller
    /// that forgot would otherwise fail on a correct message.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut rest = line;
        if let Some(stripped) = rest.strip_suffix("\r\n") {
            rest = stripped;
        } else if let Some(stripped) = rest.strip_suffix('\n') {
            rest = stripped;
        } else if let Some(stripped) = rest.strip_suffix('\r') {
            rest = stripped;
        }

        let mut tags = Vec::new();
        if let Some(after) = rest.strip_prefix('@') {
            let (tag_text, tail) = match after.find(' ') {
                Some(i) => (&after[..i], &after[i + 1..]),
                // A tag with no space after it is a broken line, and the
                // parser must not read the rest of it as a command.
                None => return Err(ParseError::PrefixOnly { line: line.to_string() }),
            };
            tags = parse_tags(tag_text);
            rest = tail;
            if rest.is_empty() {
                return Err(ParseError::PrefixOnly { line: line.to_string() });
            }
        }

        let mut prefix = None;
        if let Some(after) = rest.strip_prefix(':') {
            let (prefix_text, tail) = match after.find(' ') {
                Some(i) => (&after[..i], &after[i + 1..]),
                None => return Err(ParseError::PrefixOnly { line: line.to_string() }),
            };
            prefix = Some(parse_prefix(prefix_text));
            rest = tail;
            if rest.is_empty() {
                return Err(ParseError::PrefixOnly { line: line.to_string() });
            }
        }

        if rest.is_empty() {
            return Err(ParseError::MissingCommand { line: line.to_string() });
        }

        let (params, trailing) = split_params(rest);
        let command = parse_command(params, trailing)?;
        Ok(Message { tags, prefix, command })
    }

    /// **Encode, byte-exactly.** No trailing space is written, and the `:` is
    /// written on the trailing **always** — a trailing without it is not a
    /// trailing, and the shortest legal spelling of a trailing parameter is the
    /// one that says what it is.
    ///
    /// **Not checked**: this is the line for a log, a test or a round trip.
    /// What goes to a server is [`Message::to_wire`], which checks it first.
    pub fn to_line(&self) -> String {
        let mut out = String::new();
        if !self.tags.is_empty() {
            out.push('@');
            out.push_str(&render_tags(&self.tags));
            out.push(' ');
        }
        if let Some(prefix) = &self.prefix {
            out.push(':');
            out.push_str(&prefix.to_string());
            out.push(' ');
        }
        out.push_str(&self.command.name());
        let params = self.command.params();
        let colon = colon_at(&self.command, params.len());
        for (i, param) in params.iter().enumerate() {
            out.push(' ');
            if colon == Some(i) {
                out.push(':');
            }
            out.push_str(&param.0);
        }
        if let Some(trailing) = trailing_of(&self.command) {
            out.push(' ');
            out.push_str(&trailing.to_string());
        }
        out
    }

    /// **Each part, as the server will read it**: what [`Message::to_wire`]
    /// refuses. A trailing that arrived without its `:` is written without
    /// it, so it is read as a middle, and checked as one.
    pub fn check(&self) -> Result<(), Unsafe> {
        for tag in &self.tags {
            if tag.key.is_empty() {
                return Err(Unsafe { field: "a tag's key".into(), found: "nothing".into() });
            }
            // A tag's value is escaped (`crate::irc::tag`); its key is not.
            check_chars("a tag's key", &tag.key, &[' ', ';', '=', '\r', '\n', '\0'])?;
        }
        if let Some(prefix) = &self.prefix {
            check_middle("the prefix", &prefix.to_string())?;
        }
        let name = self.command.name();
        check_middle("the command", &name)?;
        let params = self.command.params();
        let colon = colon_at(&self.command, params.len());
        for (i, param) in params.iter().enumerate() {
            let field = format!("parameter {} of {name}", i + 1);
            if colon == Some(i) {
                check_trailing(&field, &param.0)?;
            } else {
                check_middle(&field, &param.0)?;
            }
        }
        if let Some(trailing) = trailing_of(&self.command) {
            let field = format!("the trailing of {name}");
            if trailing.colon {
                check_trailing(&field, trailing.as_str())?;
            } else {
                check_middle(&field, trailing.as_str())?;
            }
        }
        Ok(())
    }

    /// The line plus its terminator: what goes on the wire, **once each part
    /// is checked**. Each byte that podssh writes to a server passes here, so
    /// no caller's text can end the line early.
    pub fn to_wire(&self) -> Result<String, Unsafe> {
        self.check()?;
        Ok(format!("{}\r\n", self.to_line()))
    }
}
