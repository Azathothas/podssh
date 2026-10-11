//! `--record FILE` (T-033): what a session showed, with its timing, as an
//! asciicast v2 file: a line of JSON for the header, then one for each event,
//! which `podssh play` and asciinema play again. Only the output is kept,
//! never the input, and the header holds no command line, which can hold a
//! secret. The JSON is written here by hand: this crate has no JSON
//! dependency.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::terminal::Size;

/// The file of `--record`, which the caller created (mode 0600, never over a
/// file that exists), for the first session that starts.
#[derive(Clone)]
pub struct Target(Arc<Mutex<Option<File>>>);

impl Target {
    pub fn new(file: File) -> Self {
        Target(Arc::new(Mutex::new(Some(file))))
    }

    /// The file, for the session that starts first; `None` after it.
    pub fn take(&self) -> Option<File> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Target(..)")
    }
}

/// The recording of one session.
pub struct Recorder {
    out: BufWriter<File>,
    start: Instant,
    /// The start of a UTF-8 character that the next output completes.
    pending: Vec<u8>,
}

impl Recorder {
    /// Write the header: version 2, the terminal's size, the time of the
    /// start in seconds since 1970, and `TERM`.
    pub fn start(file: File, size: Size, term: &str, timestamp: u64) -> std::io::Result<Recorder> {
        let mut out = BufWriter::new(file);
        writeln!(
            out,
            "{{\"version\": 2, \"width\": {}, \"height\": {}, \"timestamp\": {timestamp}, \"env\": {{\"TERM\": {}}}}}",
            size.cols,
            size.rows,
            json_string(term)
        )?;
        out.flush()?;
        Ok(Recorder { out, start: Instant::now(), pending: Vec::new() })
    }

    /// Output that the session showed: an `o` event of its whole UTF-8
    /// characters.
    pub fn output(&mut self, data: &[u8]) -> std::io::Result<()> {
        let text = decode(&mut self.pending, data);
        if text.is_empty() {
            return Ok(());
        }
        self.event("o", &text)
    }

    /// A new size of the terminal: an `r` event, `COLSxROWS`.
    pub fn resize(&mut self, size: Size) -> std::io::Result<()> {
        self.event("r", &format!("{}x{}", size.cols, size.rows))
    }

    fn event(&mut self, kind: &str, data: &str) -> std::io::Result<()> {
        let at = self.start.elapsed().as_secs_f64();
        writeln!(self.out, "[{at:.6}, {}, {}]", json_string(kind), json_string(data))?;
        self.out.flush()
    }
}

impl Drop for Recorder {
    /// The bytes of a character that never ended, replaced, as the last
    /// event.
    fn drop(&mut self) {
        if !self.pending.is_empty() {
            let text = String::from_utf8_lossy(&std::mem::take(&mut self.pending)).into_owned();
            let _ = self.event("o", &text);
        }
        let _ = self.out.flush();
    }
}

/// `text` as a JSON string, with its quotes: `"` and `\` escaped, and each
/// control character as JSON writes it.
pub fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The whole UTF-8 characters of `pending` and `data`; the start of a
/// character that the next output completes stays in `pending`, and a byte
/// that begins no character is replaced, as `String::from_utf8_lossy` does.
fn decode(pending: &mut Vec<u8>, data: &[u8]) -> String {
    pending.extend_from_slice(data);
    let mut out = String::new();
    let mut rest: &[u8] = pending;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(text);
                rest = &[];
            }
            Err(e) => {
                let (good, after) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(good).unwrap_or_default());
                match e.error_len() {
                    Some(bad) => {
                        out.push('\u{fffd}');
                        rest = &after[bad..];
                    }
                    None => {
                        rest = after;
                        break;
                    }
                }
            }
        }
    }
    let keep = rest.to_vec();
    *pending = keep;
    out
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
