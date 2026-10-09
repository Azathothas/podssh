//! E06 — assert the relay's structural facts against its published document.
//!
//! ⛔ **The prose is never asserted. The structure is.** This module reads the
//! peer's live `llms-full.txt` and checks six structural facts and one
//! arithmetic relation. Nothing else about the peer's prose is asserted, so a
//! rewording cannot turn into a red run while a renamed path, a changed frame
//! cap or a changed timeout does.
//!
//! ⛔ **Every outcome is three-valued**, and the third value is not optional.
//! `ok` means the facts were checked and they hold. `Failed` means they were
//! checked and they do not. `Unknown` means the document was not read, and it is
//! never collapsed into `ok` — four sibling projects shipped a doctor that
//! reported green over a broken environment, and this repository has shipped a
//! check that reported success when it could not run.

use crate::facts::{Expect, Facts, Operand};

use sha2::{Digest, Sha256};

/// ⛔ One finding, each naming the line that disagrees and why it matters.
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

/// ⛔ **Never an empty vector.** An unreadable relay is not a relay with no
/// disagreements, and the two must not print the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// ⛔ **`version` is what `/health` served, and `pinned` is what this
    /// repository's facts were pinned against.** They are two different
    /// measurements and both are carried: E06's subject is a version that
    /// moves, and a verdict that reported only the pin would state the version
    /// podssh *expected* as the version it ran against. ⛔ `version` is `None`
    /// when `/health` was not read, which is not the same as a matching one.
    Ok {
        version: Option<String>,
        pinned: String,
        sha256: String,
        lines: usize,
    },
    Failed {
        version: Option<String>,
        disagreements: Vec<Disagreement>,
    },
    Unknown {
        why: String,
    },
}

impl Verdict {
    /// ⛔ `????`, never `ok`. A check that did not run is not a pass.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Verdict::Unknown { .. })
    }

    /// ⛔ **The relay served a version this repository did not pin.**
    ///
    /// ⛔ **Reported, never fatal**: the protocol did not necessarily move, and
    /// the structural facts are what decide that. ⛔ But a client that cannot
    /// tell "the document I checked is the pinned one" from "the relay has
    /// moved since" has not diagnosed anything, which is the whole of E06.
    pub fn version_moved(&self) -> bool {
        matches!(self, Verdict::Ok { version: Some(served), pinned, .. } if served != pinned)
    }
}

fn line_of(spec: &str, number: usize) -> Result<&str, String> {
    let total = spec.split('\n').count();
    // ⛔ `split('\n')` on a document ending in a newline yields a trailing empty
    // element, so this is one more than a reader's `wc -l`. Subtract it rather
    // than let a citation one line past the end resolve.
    let total = if spec.ends_with('\n') { total - 1 } else { total };
    spec.split('\n')
        .nth(number.checked_sub(1).ok_or("line 0 does not exist")?)
        .ok_or_else(|| format!("spec line {number} does not exist; the document has {total} lines"))
}

/// ⛔ Read an operand's numbers off one line of the peer's document.
///
/// ⛔ **The names bound the groups.** `names = ["cap", "payload"]` binds group 1
/// to `cap` and group 2 to `payload`, and the arithmetic in `evaluate` refers to
/// those names. ⛔ A relation that names a group index instead would be a check
/// whose meaning can change when a pattern is edited — which is the defect the
/// first version of `scripts/check-relay-spec.py` shipped.
pub fn read_operand(operand: &Operand, spec: &str) -> Result<Vec<(String, i64)>, String> {
    let line = line_of(spec, operand.line)?;
    let captures =
        regex::Regex::new(&operand.pattern).map_err(|e| format!("fact file has an uncompilable pattern: {e}"))?;
    let found = captures
        .captures(line)
        .ok_or_else(|| format!("spec line {} carries no match for the pattern", operand.line))?;
    let mut values = Vec::with_capacity(operand.names.len());
    for (index, name) in operand.names.iter().enumerate() {
        let group =
            found.get(index + 1).ok_or_else(|| format!("spec line {} has no capture group {index}", operand.line))?;
        let value: i64 = group
            .as_str()
            .parse()
            .map_err(|_| format!("spec line {}: group {index} is not an integer", operand.line))?;
        values.push((name.clone(), value));
    }
    Ok(values)
}

/// ⛔ The arithmetic, evaluated over named operands.
///
/// ⛔ **Only the forms this repository actually asserts are accepted**, and
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
            // ⛔ The 32-byte id is named here rather than read off the peer's
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
            "no evaluator for {other:?}; ⛔ a relation this gate does not understand must \
             fail loudly, because silently ignoring it is a check that always passes"
        )),
    }
}

/// ⛔ **The whole of E06's assertion.** Pure: it reads a document it was handed
/// and decides. ⛔ It never fetches. A function that both decides and reaches
/// the network cannot be tested against a planted document without a network.
///
/// ⛔ **`observed` is the version `/health` served**, so that the verdict can
/// state the version podssh ran against rather than the one it pinned. It may
/// be `None` — a document read without `/health` — and that is reported as
/// "no version observed" rather than as the pin.
pub fn assert_facts(spec: &str, facts: &Facts, observed: Option<&str>) -> Verdict {
    let mut disagreements = Vec::new();

    for fact in &facts.facts {
        let line = match line_of(spec, fact.line) {
            Ok(line) => line,
            Err(why) => {
                disagreements.push(Disagreement { fact_id: fact.id.clone(), detail: why });
                continue;
            }
        };
        match &fact.expect {
            Expect::Contains { contains } => {
                if !line.contains(contains.as_str()) {
                    disagreements.push(Disagreement {
                        fact_id: fact.id.clone(),
                        detail: format!(
                            "spec line {} does not carry {contains:?}. It reads: {}",
                            fact.line,
                            line.trim()
                        ),
                    });
                }
            }
            Expect::Number { pattern, value } => {
                let pattern = match regex::Regex::new(pattern) {
                    Ok(p) => p,
                    Err(e) => {
                        disagreements.push(Disagreement {
                            fact_id: fact.id.clone(),
                            detail: format!("fact file has an uncompilable pattern: {e}"),
                        });
                        continue;
                    }
                };
                match pattern.captures(line).and_then(|c| c.get(1)) {
                    None => disagreements.push(Disagreement {
                        fact_id: fact.id.clone(),
                        detail: format!("spec line {} carries no value for this fact", fact.line),
                    }),
                    Some(found) => match found.as_str().parse::<i64>() {
                        Err(_) => disagreements.push(Disagreement {
                            fact_id: fact.id.clone(),
                            detail: format!("spec line {} holds a non-integer value", fact.line),
                        }),
                        Ok(got) if got == *value => {}
                        Ok(got) => disagreements.push(Disagreement {
                            fact_id: fact.id.clone(),
                            detail: format!("spec line {} says {got}; this repository says {value}", fact.line),
                        }),
                    },
                }
            }
        }
    }

    for relation in &facts.relations {
        let left = match read_operand(&relation.src, spec) {
            Ok(v) => v,
            Err(why) => {
                disagreements.push(Disagreement { fact_id: relation.id.clone(), detail: why });
                continue;
            }
        };
        let right = match read_operand(&relation.dst, spec) {
            Ok(v) => v,
            Err(why) => {
                disagreements.push(Disagreement { fact_id: relation.id.clone(), detail: why });
                continue;
            }
        };
        if let Err(why) = evaluate(&relation.expression, &left, &right) {
            disagreements.push(Disagreement { fact_id: relation.id.clone(), detail: why });
        }
    }

    if disagreements.is_empty() {
        Verdict::Ok {
            version: observed.map(str::to_string),
            pinned: facts.pin.version.to_string(),
            sha256: sha256_hex(spec.as_bytes()),
            lines: line_count(spec),
        }
    } else {
        Verdict::Failed { version: None, disagreements }
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

/// ⛔ **The startup half.** Read `/health` and the published document, assert
/// the facts, and state the version the client ran against.
///
/// ⛔ **A version that is not the pinned one is reported, never fatal.** The
/// protocol did not necessarily move, and the structural facts are what decide
/// that. Refusing to start on a version string alone would make a reworded
/// sentence into an outage.
///
/// ⛔ **A relay that cannot be read is `Unknown`, not `Ok`.**
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
    // ⛔ **The `/health` version travels into the verdict.** See
    // [`Verdict::Ok`]: the pin is what this repository checked against, and the
    // served version is what it ran against. Collapsing them made `--doctor`
    // print the old version after the relay moved.
    assert_facts(document, facts, observed.version.as_deref())
}
