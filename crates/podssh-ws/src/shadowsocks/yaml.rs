//! The part of YAML that an Outline access key uses (T-493): block mappings
//! and sequences by their indentation, plain and quoted scalars, comments,
//! a document's `---`, and anchors with their aliases, as the examples of
//! Outline's configuration share one transport between `tcp` and `udp`
//! (`&shared`, `*shared`). Flow collections (`{...}`, `[...]`), block
//! scalars (`|`, `>`), tags and merge keys are refused by name: no key that
//! Outline documents needs them, and a reader of the whole of YAML is a
//! crate that the build does not hold. Each scalar is a JSON string; the
//! reader of the key reads a number from it where it wants one. A key holds
//! a password: no message here quotes a line, only its number.

use std::collections::HashMap;

use serde_json::{Map, Value};

/// A line of the text, with its indentation and its number.
struct Line {
    indent: usize,
    text: String,
    no: usize,
}

/// The document of `text`, as JSON's values.
pub fn parse(text: &str) -> Result<Value, String> {
    let mut lines = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let lead = &raw[..raw.len() - raw.trim_start().len()];
        if lead.contains('\t') {
            return Err(format!("line {}: a tab in its indentation, which YAML does not take", i + 1));
        }
        let trimmed = raw.trim_end();
        let content = trimmed.trim_start();
        if content.is_empty() || content.starts_with('#') || content == "---" || content == "..." {
            continue;
        }
        lines.push(Line { indent: trimmed.len() - content.len(), text: content.to_string(), no: i + 1 });
    }
    if lines.is_empty() {
        return Err("the YAML is empty".into());
    }
    let mut reader = Reader { lines, at: 0, anchors: HashMap::new() };
    let indent = reader.lines[0].indent;
    let value = reader.block(indent)?;
    if let Some(line) = reader.lines.get(reader.at) {
        return Err(format!("line {}: its indentation does not fit the lines before it", line.no));
    }
    Ok(value)
}

struct Reader {
    lines: Vec<Line>,
    at: usize,
    anchors: HashMap<String, Value>,
}

impl Reader {
    /// A mapping or a sequence whose lines start at `indent`.
    fn block(&mut self, indent: usize) -> Result<Value, String> {
        let first = &self.lines[self.at];
        if first.text == "-" || first.text.starts_with("- ") {
            self.sequence(indent)
        } else {
            self.mapping(indent)
        }
    }

    fn sequence(&mut self, indent: usize) -> Result<Value, String> {
        let mut items = Vec::new();
        while let Some(line) = self.lines.get(self.at) {
            if line.indent != indent || !(line.text == "-" || line.text.starts_with("- ")) {
                break;
            }
            let rest = line.text[1..].trim_start().to_string();
            let (no, inner) = (line.no, indent + line.text.len() - rest.len());
            if rest.is_empty() {
                self.at += 1;
                items.push(self.nested(indent)?);
            } else if key_of(&rest).is_some() {
                // `- key: value` opens a mapping whose keys align with `key`.
                self.lines[self.at] = Line { indent: inner, text: rest, no };
                items.push(self.mapping(inner)?);
            } else {
                self.at += 1;
                items.push(self.scalar(&rest, no)?);
            }
        }
        Ok(Value::Array(items))
    }

    fn mapping(&mut self, indent: usize) -> Result<Value, String> {
        let mut map = Map::new();
        while let Some(line) = self.lines.get(self.at) {
            if line.indent < indent {
                break;
            }
            let no = line.no;
            if line.indent > indent {
                return Err(format!("line {no}: its indentation does not fit the lines before it"));
            }
            let Some((key, rest)) = key_of(&line.text) else {
                return Err(format!("line {no}: neither key: value nor - item"));
            };
            let key = unquote(&key, no)?;
            if key == "<<" {
                return Err(format!("line {no}: a merge key (<<), which podssh's reader of YAML does not take"));
            }
            self.at += 1;
            let (anchor, rest) = anchor_of(&rest);
            // `key: # a comment` has no value on its line either.
            let rest = if rest.starts_with('#') { "" } else { rest };
            let value = if rest.is_empty() { self.nested(indent)? } else { self.scalar(rest, no)? };
            if let Some(name) = anchor {
                self.anchors.insert(name, value.clone());
            }
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }

    /// The value under a key or a `-` that had none on its line: a block
    /// further in, a sequence at the key's own indentation, or nothing.
    fn nested(&mut self, indent: usize) -> Result<Value, String> {
        match self.lines.get(self.at) {
            Some(next) if next.indent > indent => {
                let inner = next.indent;
                self.block(inner)
            }
            Some(next) if next.indent == indent && (next.text == "-" || next.text.starts_with("- ")) => {
                self.sequence(indent)
            }
            _ => Ok(Value::Null),
        }
    }

    /// A scalar, or an alias of an anchor.
    fn scalar(&mut self, text: &str, no: usize) -> Result<Value, String> {
        let (anchor, text) = anchor_of(text);
        let text = strip_comment(text);
        if let Some(name) = text.strip_prefix('*') {
            let value = self.anchors.get(name.trim()).cloned();
            return value.ok_or(format!("line {no}: an alias of an anchor that comes before it nowhere"));
        }
        let refused = match text.chars().next() {
            Some('{' | '[') => Some("a flow collection ({...} or [...])"),
            Some('|' | '>') => Some("a block scalar (| or >)"),
            Some('!') => Some("a tag (!)"),
            _ => None,
        };
        if let Some(what) = refused {
            return Err(format!("line {no}: {what}, which podssh's reader of YAML does not take"));
        }
        let value = match text {
            "~" | "null" | "Null" | "NULL" => Value::Null,
            _ => Value::String(unquote(text, no)?),
        };
        if let Some(name) = anchor {
            self.anchors.insert(name, value.clone());
        }
        Ok(value)
    }
}

/// `key` and the rest of `key: rest`, or of `key:`; a `:` inside quotes, or
/// one not followed by a space (`host:8388`, `wss://`), is no key's end.
fn key_of(text: &str) -> Option<(String, String)> {
    let mut quote = None;
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match (quote, b) {
            (Some(q), _) if b == q => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') if i == 0 => quote = Some(b),
            (None, b':') if bytes.get(i + 1).is_none_or(|n| *n == b' ') => {
                return Some((text[..i].trim().to_string(), text[i + 1..].trim().to_string()));
            }
            (None, b'#') if i > 0 && bytes[i - 1] == b' ' => return None,
            _ => {}
        }
    }
    None
}

/// `&name` before a value, and the value after it.
fn anchor_of(text: &str) -> (Option<String>, &str) {
    match text.strip_prefix('&') {
        Some(rest) => {
            let end = rest.find(' ').unwrap_or(rest.len());
            (Some(rest[..end].to_string()), rest[end..].trim_start())
        }
        None => (None, text),
    }
}

/// A plain scalar with a ` #` comment after it taken off; a quoted one as
/// it is, as its quotes may hold a `#`.
fn strip_comment(text: &str) -> &str {
    if text.starts_with('"') || text.starts_with('\'') {
        return text.trim();
    }
    match text.find(" #") {
        Some(at) => text[..at].trim(),
        None => text.trim(),
    }
}

/// A scalar's text: in double quotes with their escapes, in single quotes
/// with `''` for a quote, or plain.
fn unquote(text: &str, no: usize) -> Result<String, String> {
    let bad = || format!("line {no}: a quoted scalar that does not end where its line does");
    if let Some(inner) = text.strip_prefix('\'') {
        let inner = inner.strip_suffix('\'').ok_or_else(bad)?;
        return Ok(inner.replace("''", "'"));
    }
    let Some(inner) = text.strip_prefix('"') else { return Ok(text.to_string()) };
    let inner = inner.strip_suffix('"').ok_or_else(bad)?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                let c = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32);
                out.push(c.ok_or(format!("line {no}: an escape \\u that is not four hex digits"))?);
            }
            _ => return Err(format!("line {no}: an escape that podssh's reader of YAML does not take")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outline_s_keys_read_with_their_endpoints_anchors_and_comments() {
        let text = "\
# an access key
transport:
  $type: tcpudp
  tcp: &shared
    $type: shadowsocks
    endpoint:
        $type: websocket
        url: wss://ss.example/SECRET_PATH/tcp   # the TLS front
    cipher: chacha20-ietf-poly1305
    secret: \"with # and \\\"quotes\\\"\"
  udp: *shared
";
        let doc = parse(text).unwrap();
        let tcp = &doc["transport"]["tcp"];
        assert_eq!(tcp["$type"], "shadowsocks");
        assert_eq!(tcp["endpoint"]["url"], "wss://ss.example/SECRET_PATH/tcp");
        assert_eq!(tcp["secret"], "with # and \"quotes\"");
        assert_eq!(doc["transport"]["udp"], *tcp, "an alias is its anchor's value");
    }

    #[test]
    fn a_sequence_of_mappings_and_of_scalars_reads_at_either_indentation() {
        let text = "\
endpoint:
  $type: first-supported
  options:
  - $type: websocket
    url: wss://a.example/p
  - 'ss.example:4321'
";
        let doc = parse(text).unwrap();
        let options = doc["endpoint"]["options"].as_array().unwrap();
        assert_eq!(options[0]["url"], "wss://a.example/p");
        assert_eq!(options[1], "ss.example:4321");
        let nested = parse("list:\n    - one\n    - two\n").unwrap();
        assert_eq!(nested["list"], serde_json::json!(["one", "two"]));
    }

    #[test]
    fn what_the_reader_does_not_take_is_refused_by_its_line_never_its_text() {
        let flow = parse("transport: {secret: hunter2}\n").unwrap_err();
        assert!(flow.starts_with("line 1: a flow collection") && !flow.contains("hunter2"), "{flow}");
        assert!(parse("a: |\n  b\n").unwrap_err().contains("block scalar"));
        assert!(parse("a:\n  b: 1\n c: 2\n").unwrap_err().contains("line 3"));
        assert!(parse("a: *nowhere\n").unwrap_err().contains("alias"));
        assert!(parse("# only\n").unwrap_err().contains("empty"));
        assert!(parse("just a line\n").unwrap_err().contains("neither"));
    }
}
