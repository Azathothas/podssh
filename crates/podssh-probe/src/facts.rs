//! The relay's structural facts, and the pin against them.
//!
//! **One file, read by `podssh relay spec`, the tests, the record gate and
//! `scripts/check-relay-spec.py`.** A second hand-written copy of these numbers
//! is the exact drift this exists to catch, and a copy in a Python script that
//! the binary cannot see would be worse than none.
//!
//! **The prose is never asserted. The structure is.** A peer rewording a
//! sentence must not turn into a red run; a peer renaming a path, changing a
//! frame cap, or changing the node open timeout must.
//!
//! ## Why this is Rust and not a shell script
//!
//! **MEASURED 2026-10-02, `rust:1-alpine`:** `command -v python` and
//! `command -v python3` both return nothing — *the build image ships no Python
//! at all*, so a fact gate written in Python cannot run in the one image that
//! proves this repository's central constraint. A check that only runs where its
//! interpreter happens to exist is a check nobody runs. `podssh-probe` is the
//! only crate whose job is to probe and report, which makes it the right owner.
//!
//! ## Why the facts file is embedded, not read at runtime
//!
//! `include_str!` bakes it into the binary. A gate that depends on finding a
//! data file at a path relative to the working directory is a gate that fails
//! for a reason that has nothing to do with the relay — and it is exactly that
//! class of failure this repository has shipped. The file is still one file, and
//! `scripts/check-relay-spec.py` still reads it from the tree.

use serde::Deserialize;

/// The facts, at compile time. One file, one copy, no path resolution.
pub const FACTS_TOML: &str = include_str!("../facts/relay-facts.toml");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Facts {
    pub origin: String,
    pub pin: Pin,
    /// Read from `/relays.json` at startup, never compiled in. There is no
    /// `hello` frame on the forward path, so a constant here is a number
    /// nothing could correct. `None` means "not yet measured".
    pub forward_max_frame_bytes: Option<i64>,
    #[serde(default)]
    pub facts: Vec<Fact>,
    #[serde(default)]
    pub relations: Vec<Relation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Pin {
    pub version: String,
    pub spec_sha256: String,
    pub spec_lines: usize,
    pub spec_bytes: usize,
    pub measured_on: String,
    pub measured_how: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Fact {
    pub id: String,
    /// A line of the peer's published document, 1-based.
    pub line: usize,
    #[serde(flatten)]
    pub expect: Expect,
    pub why: String,
}

/// **Untagged, deliberately.** A `Contains` fact needs a needle and a `Number`
/// fact needs a pattern and a value, so a tagged enum would force the facts file
/// to read `expect = { contains = "/v1/node/<name>" }` where a plain string is
/// what a person writes. An untagged enum that matches the wrong variant is
/// refused by serde with a message naming the file, which is the behaviour that
/// matters: a fact whose expectation cannot be read must not assert nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Expect {
    /// The cited line must contain this substring.
    Contains { contains: String },
    /// The cited line must match this pattern and carry this integer.
    Number { pattern: String, value: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Relation {
    pub id: String,
    pub src: Operand,
    pub dst: Operand,
    /// `<a> + <b> == <c>`, with the operands named by `src.names` and
    /// `dst.names`. Evaluating it by name means a capture-group index cannot
    /// silently change what a term means, which is the defect that shipped once
    /// in the Python half of this gate.
    pub expression: String,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Operand {
    pub line: usize,
    pub pattern: String,
    /// The name of capture group 1, then of group 2, and so on. The count
    /// here is what the arithmetic is allowed to refer to.
    pub names: Vec<String>,
}

impl Facts {
    /// The parsed facts. `expect` carries the file name, because a TOML
    /// syntax error reported as "line 3" of an unknown file is not an error
    /// anybody can act on.
    pub fn load() -> Result<Self, String> {
        toml::from_str(FACTS_TOML).map_err(|e| format!("{}: {e}", FACT_SOURCE))
    }
}

pub const FACT_SOURCE: &str = "crates/podssh-probe/facts/relay-facts.toml";
