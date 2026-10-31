//! Assert the relay's structural facts against its published document.
//!
//! **The prose is never asserted. The structure is.** This module reads the
//! peer's live `llms-full.txt` and checks six structural facts and one
//! arithmetic relation. Nothing else about the peer's prose is asserted, so a
//! rewording cannot turn into a red run while a renamed path, a changed frame
//! cap or a changed timeout does.
//!
//! **A fact is read at its line, then in its section.** The facts file names
//! the line of each fact as a hint, and the heading that it stands under: a
//! line that the relay inserts above a fact moves it within its section,
//! which holds, with a note to move the hint; a fact that left its section, or
//! changed, fails (T-338).
//!
//! **Every outcome is three-valued**, and the third value is not optional.
//! `ok` means the facts were checked and they hold. `Failed` means they were
//! checked and they do not. `Unknown` means the document was not read, and it is
//! never collapsed into `ok` — four sibling projects shipped a doctor that
//! reported green over a broken environment, and this repository has shipped a
//! check that reported success when it could not run.

use crate::facts::{Expect, Facts, Operand};

use sha2::{Digest, Sha256};

/// One finding, each naming the line that disagrees and why it matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement {
    pub fact_id: String,
    pub detail: String,
}

impl std::fmt::Display for Disagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.fact_id, self.detail)
    }
}

/// A fact found at another line of its section than the one that the facts
/// file names: the document moved and the fact did not, so it holds, and the
/// hint is old.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub fact_id: String,
    pub section: String,
    pub from: usize,
    pub to: usize,
}

impl std::fmt::Display for Moved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: at line {} of its section {:?}, not at line {}: move the line in the facts file",
            self.fact_id, self.to, self.section, self.from
        )
    }
}

/// **Never an empty vector.** An unreadable relay is not a relay with no
/// disagreements, and the two must not print the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// **`version` is what `/health` served, and `pinned` is what this
    /// repository's facts were pinned against.** They are two different
    /// measurements and both are carried: this check's subject is a version that
    /// moves, and a verdict that reported only the pin would state the version
    /// podssh *expected* as the version it ran against. `version` is `None`
    /// when `/health` was not read, which is not the same as a matching one.
    Ok {
        version: Option<String>,
        pinned: String,
        sha256: String,
        lines: usize,
        /// The facts found away from their line, each within its section.
        moved: Vec<Moved>,
    },
    Failed {
        version: Option<String>,
        disagreements: Vec<Disagreement>,
        moved: Vec<Moved>,
    },
    Unknown {
        why: String,
    },
}

impl Verdict {
    /// `????`, never `ok`. A check that did not run is not a pass.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Verdict::Unknown { .. })
    }

    /// **The relay served a version this repository did not pin.**
    ///
    /// **Reported, never fatal**: the protocol did not necessarily move, and
    /// the structural facts are what decide that. But a client that cannot
    /// tell "the document I checked is the pinned one" from "the relay has
    /// moved since" has not diagnosed anything, which is the whole of this check.
    pub fn version_moved(&self) -> bool {
        matches!(self, Verdict::Ok { version: Some(served), pinned, .. } if served != pinned)
    }
}

/// The document's lines: the empty piece after a last newline is no line,
/// as `wc -l` counts.
fn lines_of(spec: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = spec.split('\n').collect();
    if spec.ends_with('\n') {
        lines.pop();
    }
    lines
}

/// The lines, 1-based and inclusive, of the section whose heading starts with
/// `name`: its heading, and each line before the next heading of its level or
/// above. A line in a fence of code is no heading.
fn section_of(lines: &[&str], name: &str) -> Option<(usize, usize)> {
    let (mut fenced, mut found) = (false, None::<(usize, usize)>);
    for (index, line) in lines.iter().enumerate() {
        let text = line.trim_end();
        if text.starts_with("```") || text.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        let level = text.bytes().take_while(|b| *b == b'#').count();
        if fenced || level == 0 || !text[level..].starts_with(' ') {
            continue;
        }
        match found {
            None if text[level..].trim().starts_with(name) => found = Some((index + 1, level)),
            Some((start, at)) if level <= at => return Some((start, index)),
            _ => {}
        }
    }
    found.map(|(start, _)| (start, lines.len()))
}

/// The line that `holds` a fact, and its number: the hint first, then each
/// line of its section; else why none does, with `what` the fact's text.
fn locate<'a>(
    lines: &[&'a str],
    hint: usize,
    section: &str,
    holds: impl Fn(&str) -> bool,
    what: &str,
) -> Result<(usize, &'a str), String> {
    let at_hint = hint.checked_sub(1).and_then(|index| lines.get(index).copied());
    if let Some(line) = at_hint.filter(|line| holds(line)) {
        return Ok((hint, line));
    }
    let reads = match at_hint {
        Some(line) => format!("spec line {hint} reads: {}", line.trim()),
        None => format!("spec line {hint} does not exist; the document has {} lines", lines.len()),
    };
    let Some((first, last)) = section_of(lines, section) else {
        return Err(format!("{reads}; and the document has no section {section:?}"));
    };
    (first..=last)
        .find(|number| holds(lines[number - 1]))
        .map(|number| (number, lines[number - 1]))
        .ok_or_else(|| format!("no line of its section {section:?} (lines {first}-{last}) carries {what}; {reads}"))
}

/// Read an operand's numbers off one line of the peer's document: the line
/// that the pattern matches, its hint first, then its section.
///
/// **The names bound the groups.** `names = ["cap", "payload"]` binds group 1
/// to `cap` and group 2 to `payload`, and the arithmetic in `evaluate` refers to
/// those names. A relation that names a group index instead would be a check
/// whose meaning can change when a pattern is edited — which is the defect the
/// first version of `scripts/check-relay-spec.py` shipped.
pub fn read_operand(operand: &Operand, spec: &str) -> Result<Vec<(String, i64)>, String> {
    read_operand_in(operand, &lines_of(spec)).map(|(_, values)| values)
}

/// [`read_operand`] on the document's lines, with the number of the line read.
fn read_operand_in(operand: &Operand, lines: &[&str]) -> Result<(usize, Vec<(String, i64)>), String> {
    let pattern =
        regex::Regex::new(&operand.pattern).map_err(|e| format!("fact file has an uncompilable pattern: {e}"))?;
    let (number, line) =
        locate(lines, operand.line, &operand.section, |line| pattern.is_match(line), "a match for the pattern")?;
    let found = pattern.captures(line).ok_or_else(|| format!("spec line {number} carries no match for the pattern"))?;
    let mut values = Vec::with_capacity(operand.names.len());
    for (index, name) in operand.names.iter().enumerate() {
        let group = found.get(index + 1).ok_or_else(|| format!("spec line {number} has no capture group {index}"))?;
        let value: i64 =
            group.as_str().parse().map_err(|_| format!("spec line {number}: group {index} is not an integer"))?;
        values.push((name.clone(), value));
    }
    Ok((number, values))
}

/// The arithmetic, evaluated over named operands.
///
/// **Only the forms this repository actually asserts are accepted**, and
/// anything else is an error naming the expression. An evaluator that silently
/// ignored an expression it did not understand would turn every future relation
/// into a check that passes.
fn evaluate(expression: &str, left: &[(String, i64)], right: &[(String, i64)]) -> Result<i64, String> {
    let operand = |side: &[(String, i64)], name: &str| -> Result<i64, String> {
        side.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
            .ok_or_else(|| format!("expression {expression:?} names `{name}`, which this side does not publish"))
    };
    match expression {
        "id + payload == cap" => {
            // The 32-byte id is named here rather than read off the peer's
            // sentence, because line 147 publishes ONE parenthetical bound and
            // its prose does not match its own parentheses. The id length is
            // therefore an internal constant, and the peer's total cap is
            // compared against `32 + the payload it published`.
            const ID_BYTES: i64 = 32;
            let payload = operand(left, "payload")?;
            let cap = operand(right, "cap")?;
            let sum = ID_BYTES + payload;
            if sum == cap {
                Ok(sum)
            } else {
                Err(format!("{ID_BYTES} + {payload} = {sum}, but the published cap is {cap}"))
            }
        }
        other => Err(format!(
            "no evaluator for {other:?}; a relation this gate does not understand must \
             fail loudly, because silently ignoring it is a check that always passes"
        )),
    }
}

/// **The whole of the assertion.** Pure: it reads a document it was handed
/// and decides. It never fetches. A function that both decides and reaches
/// the network cannot be tested against a planted document without a network.
///
/// **`observed` is the version `/health` served**, so that the verdict can
/// state the version podssh ran against rather than the one it pinned. It may
/// be `None` — a document read without `/health` — and that is reported as
/// "no version observed" rather than as the pin.
pub fn assert_facts(spec: &str, facts: &Facts, observed: Option<&str>) -> Verdict {
    let lines = lines_of(spec);
    let (mut disagreements, mut moved) = (Vec::new(), Vec::new());
    let mut disagree = |fact_id: &str, detail: String| {
        disagreements.push(Disagreement { fact_id: fact_id.to_string(), detail });
    };
    let mut was_moved = |fact_id: &str, section: &str, from: usize, to: usize| {
        let note = Moved { fact_id: fact_id.to_string(), section: section.to_string(), from, to };
        if from != to && !moved.contains(&note) {
            moved.push(note);
        }
    };

    for fact in &facts.facts {
        match &fact.expect {
            Expect::Contains { contains } => {
                let holds = |line: &str| line.contains(contains.as_str());
                match locate(&lines, fact.line, &fact.section, holds, &format!("{contains:?}")) {
                    Ok((number, _)) => was_moved(&fact.id, &fact.section, fact.line, number),
                    Err(why) => disagree(&fact.id, why),
                }
            }
            Expect::Number { pattern, value } => {
                let pattern = match regex::Regex::new(pattern) {
                    Ok(p) => p,
                    Err(e) => {
                        disagree(&fact.id, format!("fact file has an uncompilable pattern: {e}"));
                        continue;
                    }
                };
                let holds = |line: &str| pattern.captures(line).and_then(|c| c.get(1)).is_some();
                let (number, line) = match locate(&lines, fact.line, &fact.section, holds, "a value for this fact") {
                    Ok(found) => found,
                    Err(why) => {
                        disagree(&fact.id, why);
                        continue;
                    }
                };
                let found = pattern.captures(line).and_then(|c| c.get(1)).map(|m| m.as_str().parse::<i64>());
                match found {
                    Some(Ok(got)) if got == *value => was_moved(&fact.id, &fact.section, fact.line, number),
                    Some(Ok(got)) => {
                        disagree(&fact.id, format!("spec line {number} says {got}; this repository says {value}"))
                    }
                    _ => disagree(&fact.id, format!("spec line {number} holds a non-integer value")),
                }
            }
        }
    }

    for relation in &facts.relations {
        let mut read = |operand: &Operand| -> Result<Vec<(String, i64)>, String> {
            let (number, values) = read_operand_in(operand, &lines)?;
            was_moved(&relation.id, &operand.section, operand.line, number);
            Ok(values)
        };
        let both = read(&relation.src).and_then(|left| Ok((left, read(&relation.dst)?)));
        let checked = both.and_then(|(left, right)| evaluate(&relation.expression, &left, &right));
        if let Err(why) = checked {
            disagree(&relation.id, why);
        }
    }

    if disagreements.is_empty() {
        Verdict::Ok {
            version: observed.map(str::to_string),
            pinned: facts.pin.version.to_string(),
            sha256: sha256_hex(spec.as_bytes()),
            lines: line_count(spec),
            moved,
        }
    } else {
        Verdict::Failed { version: None, disagreements, moved }
    }
}

pub fn line_count(spec: &str) -> usize {
    let total = spec.split('\n').count();
    if spec.ends_with('\n') {
        total - 1
    } else {
        total
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// **The half that reads a relay**, which `podssh relay spec` runs: from
/// `/health` and the published document, assert the facts, and state the
/// version the client ran against.
///
/// **A version that is not the pinned one is reported, never fatal.** The
/// protocol did not necessarily move, and the structural facts are what decide
/// that. Refusing to start on a version string alone would make a reworded
/// sentence into an outage.
///
/// **A relay that cannot be read is `Unknown`, not `Ok`.**
pub struct Observed {
    pub version: Option<String>,
    pub document: Option<String>,
}

pub fn verdict_from(observed: &Observed, facts: &Facts) -> Verdict {
    let Some(document) = observed.document.as_deref() else {
        return Verdict::Unknown {
            why: match observed.version.as_deref() {
                Some(v) => format!("read /health (version {v}) but could not read llms-full.txt"),
                None => "read neither /health nor llms-full.txt".to_string(),
            },
        };
    };
    // **The `/health` version travels into the verdict.** See
    // [`Verdict::Ok`]: the pin is what this repository checked against, and the
    // served version is what it ran against. Collapsing them made `--doctor`
    // print the old version after the relay moved.
    assert_facts(document, facts, observed.version.as_deref())
}
