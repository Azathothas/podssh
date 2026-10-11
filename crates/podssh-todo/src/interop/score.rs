//! The result lines of a run's logs against the baseline (T-199). A line is
//! `VERDICT ID TEXT`, the verdict `ok`, `FAIL`, `skip` or `env`; each id of
//! each harness of the run must print exactly one, and the verdict that the
//! baseline wants.

use std::collections::BTreeMap;

use super::{is_id, Baseline, Want, BASELINE};
use crate::model::Problem;

const VERDICTS: &[&str] = &["ok", "FAIL", "skip", "env"];

/// One log of a run: the name shown, the run (the file's stem) and its text.
pub struct Log {
    pub shown: String,
    pub run: String,
    pub text: String,
}

/// Score each log against `b`. Gives a row `score PREFIX PASS FAIL ENV SKIP
/// MISSING FLOOR` for each harness of the runs given, and a problem for each
/// line or id that does not meet the baseline.
pub fn score(b: &Baseline, logs: &[Log]) -> (Vec<String>, Vec<Problem>) {
    let (mut rows, mut problems) = (Vec::new(), Vec::new());
    for log in logs {
        if !b.harnesses.iter().any(|h| h.run == log.run) {
            problems.push(Problem::new(&log.shown, 0, format!("no harness of {BASELINE} runs in {:?}", log.run)));
            continue;
        }
        let mut got: BTreeMap<&str, Vec<(&str, usize)>> = BTreeMap::new();
        for (i, line) in log.text.lines().enumerate() {
            let (verdict, rest) = line.split_once(' ').unwrap_or((line, ""));
            if !VERDICTS.contains(&verdict) {
                continue;
            }
            let id = rest.trim_start().split(' ').next().unwrap_or_default();
            if !is_id(id) {
                problems.push(Problem::new(&log.shown, i + 1, format!("a result line with no id: {verdict} {rest}")));
                continue;
            }
            match b.harness_of(id) {
                Some(h) if h.run == log.run && b.ids.contains_key(id) => {
                    got.entry(id).or_default().push((verdict, i + 1))
                }
                _ => problems.push(Problem::new(&log.shown, i + 1, format!("{id} is no id of the run {}", log.run))),
            }
        }
        for h in b.harnesses.iter().filter(|h| h.run == log.run) {
            let (mut pass, mut fail, mut env, mut skip, mut missing) = (0, 0, 0, 0, 0);
            for (id, (want, _)) in b.ids.iter().filter(|(id, _)| b.harness_of(id) == Some(h)) {
                match got.get(id.as_str()).map(Vec::as_slice) {
                    None | Some([]) => {
                        missing += 1;
                        problems.push(Problem::new(&log.shown, 0, format!("{id} printed no line")));
                    }
                    Some([(verdict, line)]) => {
                        match *verdict {
                            "ok" => pass += 1,
                            "FAIL" => fail += 1,
                            "env" => env += 1,
                            _ => skip += 1,
                        }
                        if *verdict != "ok" && !(*verdict == "env" && *want == Want::EnvAllowed) {
                            let due = if *want == Want::Pass { "ok" } else { "ok or env" };
                            problems.push(Problem::new(
                                &log.shown,
                                *line,
                                format!("{id} gave {verdict}, where {due} is due"),
                            ));
                        }
                    }
                    Some(many) => {
                        let line = many[1].1;
                        problems.push(Problem::new(&log.shown, line, format!("{id} printed {} lines", many.len())));
                    }
                }
            }
            if pass < h.floor {
                let what = format!("{} passed {pass} checks, under its floor of {}", h.prefix, h.floor);
                problems.push(Problem::new(&log.shown, 0, what));
            }
            rows.push(format!("score {} {pass} {fail} {env} {skip} {missing} {}", h.prefix, h.floor));
        }
    }
    (rows, problems)
}
