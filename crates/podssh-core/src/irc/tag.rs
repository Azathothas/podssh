//! IRCv3 message tags: `@key=value;key2 :prefix COMMAND params`.
//!
//! **Tags arrived after RFC 1459 and are optional in both directions.** A
//! peer that sends them to a client that ignores them is common; a client that
//! treats an unknown tag as a parse failure is a client that drops the message
//! *and* the conversation.
//!
//! **The escape set is closed, and it is five characters long.** A tag value
//! is escaped with a backslash for `;`, ` `, `\`, CR and LF. **CR and LF are
//! the two that matter here**: a tag value that could carry a line terminator
//! would let a peer inject a second message into a stream that is otherwise
//! strictly line-oriented, so the escape and the unescape both handle them and
//! neither handles anything else.

use crate::irc::message::Tag;

/// Split `@a=1;b;c=2` into its tags. **A valueless tag is legal and is
/// `None`, not `Some("")`** — `@room` and `@room=` are different, and a parser
/// that maps one to the other changes the tag's meaning when it is echoed back.
pub fn parse_tags(text: &str) -> Vec<Tag> {
    let mut tags = Vec::new();
    for item in text.split(';') {
        if item.is_empty() {
            continue;
        }
        match item.split_once('=') {
            Some((key, value)) => tags.push(Tag { key: key.to_string(), value: Some(unescape(value)) }),
            None => tags.push(Tag { key: item.to_string(), value: None }),
        }
    }
    tags
}

/// Encode tags back to `@a=1;b;c=2`, omitting the `@` and the space.
///
/// **An unknown escape is preserved, backslash included.** Dropping the
/// character after an unrecognised `\` would silently corrupt a value that a
/// peer sent, and a corrupted tag is worse than a slightly ugly one because
/// nothing says it happened.
pub fn render_tags(tags: &[Tag]) -> String {
    let mut out = String::new();
    for (i, tag) in tags.iter().enumerate() {
        if i > 0 {
            out.push(';');
        }
        out.push_str(&tag.key);
        if let Some(value) = &tag.value {
            out.push('=');
            out.push_str(&escape(value));
        }
    }
    out
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(':') => out.push(';'),
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            // A trailing lone backslash is kept. There is no character after
            // it, and discarding it would make the value differ from the wire.
            None => out.push('\\'),
        }
    }
    out
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            // NUL never reaches here: the byte layer strips it. Escaping it
            // would be code that looks like a guarantee and is not one.
            '\0' => {}
            other => out.push(other),
        }
    }
    out
}
