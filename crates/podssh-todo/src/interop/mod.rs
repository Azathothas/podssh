//! The checks of the interop harnesses against a committed baseline (T-199).
//! Each check of `scripts/interop*` prints a stable id as the first word
//! after its verdict; `scripts/interop-baseline.txt` holds the verdict that
//! each id must give, and a floor of passes for each harness. With no log,
//! the ids that the scripts can print must equal the baseline's, so a check
//! that is deleted, added or renamed is seen by each run of the tests; with
//! the logs of a run, each harness's lines must meet the baseline.

mod score;
mod words;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub use score::{score, Log};

use crate::model::Problem;

/// The baseline, relative to the root.
pub const BASELINE: &str = "scripts/interop-baseline.txt";

/// What an id must give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// `ok`.
    Pass,
    /// `ok`, or `env` when a precondition of the host is missing.
    EnvAllowed,
}

/// A harness: the prefix of its ids, the log of the run that holds its
/// lines, the passes that a run must have at least, and its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Harness {
    pub prefix: String,
    pub run: String,
    pub floor: usize,
    pub file: String,
    pub line: usize,
}

/// The parsed baseline.
#[derive(Debug, Default)]
pub struct Baseline {
    pub harnesses: Vec<Harness>,
    /// Files of the harnesses that print no id of their own (the helpers).
    pub support: Vec<String>,
    /// Each id, with what it must give and the baseline's line.
    pub ids: BTreeMap<String, (Want, usize)>,
}

impl Baseline {
    /// The harness whose prefix starts `id`.
    pub fn harness_of(&self, id: &str) -> Option<&Harness> {
        self.harnesses.iter().find(|h| id.strip_prefix(&h.prefix).is_some_and(|r| r.starts_with('.')))
    }
}

/// Whether `id` has the form of an id: dotted parts of `[a-z0-9_-]`.
pub fn is_id(id: &str) -> bool {
    id.split('.').count() >= 2
        && id.split('.').all(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        })
}

/// Read the baseline; each line that is not one of its four kinds is a
/// problem.
pub fn baseline(text: &str, problems: &mut Vec<Problem>) -> Baseline {
    let mut b = Baseline::default();
    for (i, raw) in text.lines().enumerate() {
        let no = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["support", file] => b.support.push(file.to_string()),
            ["harness", prefix, run, floor, file] => match floor.parse::<usize>() {
                Ok(floor) => b.harnesses.push(Harness {
                    prefix: prefix.to_string(),
                    run: run.to_string(),
                    floor,
                    file: file.to_string(),
                    line: no,
                }),
                Err(_) => problems.push(Problem::new(BASELINE, no, format!("the floor {floor:?} is not a number"))),
            },
            [id, "pass"] | [id, "env-allowed", _, ..] => {
                let want = if words[1] == "pass" { Want::Pass } else { Want::EnvAllowed };
                if !is_id(id) {
                    problems.push(Problem::new(BASELINE, no, format!("{id:?} is not an id")));
                } else if b.ids.insert(id.to_string(), (want, no)).is_some() {
                    problems.push(Problem::new(BASELINE, no, format!("{id} is listed twice")));
                }
            }
            _ => problems.push(Problem::new(
                BASELINE,
                no,
                "not a line of the baseline: support FILE, harness PREFIX RUN FLOOR FILE, ID pass, or \
                 ID env-allowed REASON",
            )),
        }
    }
    for (id, (_, no)) in &b.ids {
        if b.harness_of(id).is_none() {
            problems.push(Problem::new(BASELINE, *no, format!("{id} has the prefix of no harness")));
        }
    }
    b
}

/// What a check of the scripts against the baseline found.
#[derive(Debug, Default)]
pub struct Checked {
    pub baseline: Baseline,
    pub ids: usize,
    pub problems: Vec<Problem>,
}

/// Check the ids of each harness against the baseline, with no log.
pub fn check(root: &Path) -> Checked {
    let mut problems = Vec::new();
    let text = match std::fs::read_to_string(root.join(BASELINE)) {
        Ok(t) => t,
        Err(e) => {
            problems.push(Problem::new(BASELINE, 0, format!("cannot be read: {e}")));
            return Checked { problems, ..Checked::default() };
        }
    };
    let b = baseline(&text, &mut problems);
    let named: BTreeSet<&str> =
        b.harnesses.iter().map(|h| h.file.as_str()).chain(b.support.iter().map(String::as_str)).collect();
    // Each harness file is named: a new one is not left out of the score.
    if let Ok(dir) = std::fs::read_dir(root.join("scripts")) {
        let mut found: Vec<String> = dir
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with("interop") && (n.ends_with(".sh") || n.ends_with(".py")))
            .map(|n| format!("scripts/{n}"))
            .collect();
        found.sort();
        for file in found.iter().filter(|f| !named.contains(f.as_str())) {
            problems.push(Problem::new(file, 0, format!("a harness that {BASELINE} does not name")));
        }
    }
    let mut seen = 0;
    for h in &b.harnesses {
        let text = match std::fs::read_to_string(root.join(&h.file)) {
            Ok(t) => t,
            Err(e) => {
                problems.push(Problem::new(BASELINE, h.line, format!("{} cannot be read: {e}", h.file)));
                continue;
            }
        };
        let ids = if h.file.ends_with(".py") {
            words::python(&h.file, &text, &mut problems)
        } else {
            words::shell(&h.file, &text, &mut problems)
        };
        seen += ids.len();
        for (id, e) in &ids {
            if !is_id(id) {
                problems.push(Problem::new(&h.file, e.line, format!("{id:?} is not an id")));
                continue;
            }
            if b.harness_of(id).map(|o| o.prefix.as_str()) != Some(h.prefix.as_str()) {
                problems.push(Problem::new(&h.file, e.line, format!("{id} does not start with {}.", h.prefix)));
            }
            if !e.pass {
                problems.push(Problem::new(&h.file, e.line, format!("{id} has no line that prints ok")));
            }
            if !e.fail {
                problems.push(Problem::new(&h.file, e.line, format!("{id} has no line that prints FAIL")));
            }
            if !b.ids.contains_key(id) {
                problems.push(Problem::new(&h.file, e.line, format!("{id} is not in {BASELINE}")));
            }
        }
        let mine = b.ids.iter().filter(|(id, _)| b.harness_of(id) == Some(h));
        for (id, (_, no)) in mine.clone().filter(|(id, _)| !ids.contains_key(*id)) {
            problems.push(Problem::new(BASELINE, *no, format!("{id} is printed by no line of {}", h.file)));
        }
        let passes = mine.filter(|(_, (want, _))| *want == Want::Pass).count();
        if passes != h.floor {
            let what = format!("the floor of {} is {}, and {passes} of its ids must pass", h.prefix, h.floor);
            problems.push(Problem::new(BASELINE, h.line, what));
        }
    }
    Checked { baseline: b, ids: seen, problems }
}
