//! podssh's checker of the work record: `pod-todo` of PodUtils/podcrates
//! with the facts of podssh (`TODO/todo.toml`), and podssh's own command
//! `interop`: the ids of the interop harnesses against
//! `scripts/interop-baseline.txt`, and with logs, each run's results.

pub mod interop;

use std::path::Path;

pub use pod_todo::{check, model, run as run_record};

/// Run the command line: `interop` here, each other command in `pod-todo`.
pub fn run(args: &[String], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let root = || std::env::current_dir().ok().and_then(|d| pod_todo::find_root(&d));
    match words.as_slice() {
        ["interop"] => match root() {
            Some(r) => interop_command(&r, &[], out, err),
            None => pod_todo::run(args, out, err),
        },
        ["interop", "--logs", logs @ ..] if !logs.is_empty() => match root() {
            Some(r) => interop_command(&r, logs, out, err),
            None => pod_todo::run(args, out, err),
        },
        ["interop", ..] => {
            let _ = writeln!(err, "podssh-todo: interop takes only --logs LOG...");
            64
        }
        _ => pod_todo::run(args, out, err),
    }
}

/// Check the interop harnesses against their baseline, and score the logs
/// named, each a run named by its file's stem (T-199).
fn interop_command(root: &Path, logs: &[&str], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let checked = interop::check(root);
    let mut problems = checked.problems;
    if !logs.is_empty() {
        let mut runs = Vec::new();
        for log in logs {
            let path = Path::new(log);
            let run = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_string();
            match std::fs::read_to_string(path) {
                Ok(text) => runs.push(interop::Log { shown: log.to_string(), run, text }),
                Err(e) => problems.push(pod_todo::model::Problem::new(log, 0, format!("cannot be read: {e}"))),
            }
        }
        let (rows, more) = interop::score(&checked.baseline, &runs);
        let _ = writeln!(out, "score harness pass fail env skip missing floor");
        for row in rows {
            let _ = writeln!(out, "{row}");
        }
        problems.extend(more);
    }
    if problems.is_empty() {
        let harnesses = checked.baseline.harnesses.len();
        let _ = writeln!(
            out,
            "podssh-todo: interop: {} ids of {harnesses} harnesses meet {}",
            checked.ids,
            interop::BASELINE
        );
        0
    } else {
        for p in &problems {
            let _ = writeln!(err, "{p}");
        }
        let _ = writeln!(err, "podssh-todo: {} problems in the interop checks", problems.len());
        1
    }
}
