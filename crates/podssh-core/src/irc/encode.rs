//! Encoding: a [`Message`] back to bytes.
//!
//! **Split out of `message.rs`, which went over the 500-line gate with
//! the parser and the encoder together.** Parse and encode are two
//! directions of one grammar and deserve one file each — and a test
//! that says "round trip" reads as one claim rather than two.

use crate::irc::command::parse_command;
use crate::irc::command_view::trailing_of;
use crate::irc::message::{parse_prefix, split_params, Message, ParseError};
use crate::irc::tag::{parse_tags, render_tags};

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
        for param in self.command.params() {
            out.push(' ');
            out.push_str(&param.0);
        }
        if let Some(trailing) = trailing_of(&self.command) {
            out.push(' ');
            out.push_str(&trailing.to_string());
        }
        out
    }

    /// The line plus its terminator: what goes on the wire.
    pub fn to_wire(&self) -> String {
        format!("{}\r\n", self.to_line())
    }
}
