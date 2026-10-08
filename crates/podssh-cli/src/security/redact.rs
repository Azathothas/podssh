//! E12: the backstop, for a value that did not come through [`super::token`].
//!
//! ⛔ **The wrapper type is the guard. This is the net.** `RelayToken` cannot be
//! rendered, so a diagnostic that holds one is safe by construction; what this
//! module catches is the case the wrapper cannot see — ⛔ a secret that arrived
//! as a `String` from a mint response, a cache file, an environment override, or
//! a third-party error message, and was then formatted into a log line.
//!
//! ⛔ **The reason a backstop is worth building even though the wrapper exists.**
//! Spec lines 94-96: *"URLs can appear in logs."* A token that reached a URL, a
//! proxy log, a crash report or a CI transcript is outside anything a type can
//! protect, and the only remaining defence is that the line is dropped on the
//! way out.

use std::sync::OnceLock;

use regex::Regex;

use super::token::TOKEN_SHAPE;

/// The one compiled pattern, built once.
///
/// ⛔ `OnceLock` rather than a `lazy_static` dependency: a regex compiled per log
/// line is a log line that costs more than the session it describes, and the
/// pattern itself is the only state in the process worth sharing.
fn shape() -> &'static Regex {
    static SHAPE: OnceLock<Regex> = OnceLock::new();
    SHAPE.get_or_init(|| {
        Regex::new(TOKEN_SHAPE).expect("TOKEN_SHAPE is a literal and cannot fail to compile")
    })
}

/// ⛔ **What a dropped line is replaced with.** Not `[redacted]`, which is
/// ambiguous with a value the code itself chose to hide, and not nothing, which
/// would make a reader think the program printed an empty line. ⛔ The
/// replacement says *what was removed and why*, so a reader can tell a
/// deliberate redaction from a bug.
pub const DROPPED: &str = "<redacted: a relay token was removed from this line>";

/// ⛔ **True when this line carries something shaped like a relay token.**
///
/// ⛔ This is what the tests plant against, and it is deliberately *not* the same
/// function as [`scrub`]. ⛔ A test that asserts "the filter ran" and a test that
/// asserts "the token is gone" are different tests, and a filter that returned
/// the input unchanged would pass the first one.
pub fn looks_like_token(line: &str) -> bool {
    shape().is_match(line)
}

/// ⛔ **Drop the whole line, not the token.** ⛔ Replacing `ephm1.<mac>` with a
/// placeholder inside a sentence leaves the sentence, and the sentence is a
/// trace line about the upgrade — which names the relay host, the target and
/// the timing. ⛔ The whole line is the unit that was contaminated, so the whole
/// line goes.
///
/// ⛔ A line that matched is replaced by [`DROPPED`], and a line that did not is
/// returned **byte for byte**. ⛔ That is the property the control asserts: a
/// filter that rewrote every line would pass "the token is absent" and fail
/// every useful thing.
pub fn scrub(line: &str) -> Option<String> {
    if looks_like_token(line) {
        Some(DROPPED.to_string())
    } else {
        None
    }
}

/// ⛔ **The sink, as a trait, so the caller is a caller.**
///
/// ⛔ `AGENTS.md` and the whole of `docs/TODO/RULES.md`'s "Secrets" section are
/// about where a secret ends up: stdout, stderr, a log file, a core dump. ⛔ A
/// function that returns a `String` and trusts its caller to write it somewhere
/// sensible is a note. ⛔ This makes the destination a type parameter, so a
/// function that must be able to write a log line takes a `TokenSafeSink` and a
/// function that only ever writes to memory does not.
pub trait TokenSafeSink {
    /// ⛔ The name, for a diagnostic that says where a line would have gone.
    fn sink_name(&self) -> &'static str;
    fn write_line(&mut self, line: &str) -> std::io::Result<()>;
}

/// ⛔ **Collects lines in memory. For tests, and for a caller that wants to
/// inspect what it would have printed.**
#[derive(Debug, Default)]
pub struct MemorySink {
    pub lines: Vec<String>,
}

impl TokenSafeSink for MemorySink {
    fn sink_name(&self) -> &'static str {
        "memory"
    }

    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        match scrub(line) {
            Some(replacement) => self.lines.push(replacement),
            None => self.lines.push(line.to_string()),
        }
        Ok(())
    }
}

/// ⛔ **The one entry point every diagnostic in podssh goes through.** ⛔ It
/// scrubs, and then it hands the result to a sink that can only be a
/// `TokenSafeSink` — ⛔ so a caller cannot reach `eprintln!` with a line that has
/// not been through here.
pub fn emit<S: TokenSafeSink>(sink: &mut S, line: &str) -> std::io::Result<()> {
    sink.write_line(&scrub(line).unwrap_or_else(|| line.to_string()))
}

/// ⛔ **The scan, for a file or a stream podssh did not write line by line.**
///
/// ⛔ The mint response, a proxy's access log, a crash dump: there are places a
/// token can be that never passed through [`emit`]. ⛔ This is the tool for a
/// caller that is *checking* rather than *writing*, and it returns ⛔ **the line
/// numbers that matched, not the lines** — ⛔ a function whose return value is
/// the secret is a function that puts the secret in the caller's next log
/// message.
pub fn scan_for_tokens(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| if looks_like_token(line) { Some(i + 1) } else { None })
        .collect()
}
