//! The checker of podssh's work record (`TODO/`).
//!
//! The record is the index (`TODO/INDEX.md`), the progress record with the
//! work order (`TODO/PROGRESS.md`) and the entries (`TODO/<area>.md`).
//! Closing one entry moves several numbers in two files, so no number is
//! typed by hand: the writer moves a status and derives the counts, and the
//! reader, which the gate runs, checks that the files agree. When a cited
//! file changes, `remap` moves its citations by a line diff against `HEAD`.

pub mod check;
pub mod diff;
pub mod model;
pub mod parse;
pub mod refs;
pub mod remap;
pub mod write;

use std::path::{Path, PathBuf};

pub const USAGE: &str = "usage: podssh-todo check
       podssh-todo set T-NNN open|partial|blocked|done
       podssh-todo counts
       podssh-todo next
       podssh-todo remap [--dry-run] FILE...   (after an edit of FILE: move its citations by a diff against HEAD)
Options: --root DIR (default: the nearest directory above the current one with TODO/INDEX.md)";

/// The nearest directory at or above `start` that has `TODO/INDEX.md`.
pub fn find_root(start: &Path) -> Option<PathBuf> {
    start.ancestors().find(|d| d.join("TODO").join("INDEX.md").is_file()).map(Path::to_path_buf)
}

/// Run the command line; returns the exit code (0, 1 for a disagreement, 64
/// for a usage error).
pub fn run(args: &[String], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let mut words: Vec<&str> = Vec::new();
    let mut root: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--root" => match it.next() {
                Some(d) => root = Some(PathBuf::from(d)),
                None => return usage(err, "--root needs a directory"),
            },
            "-h" | "--help" => {
                let _ = writeln!(out, "{USAGE}");
                return 0;
            }
            w => words.push(w),
        }
    }
    let root = match root.or_else(|| std::env::current_dir().ok().and_then(|d| find_root(&d))) {
        Some(r) => r,
        None => return usage(err, "no TODO/INDEX.md here or above; give --root"),
    };
    match words.as_slice() {
        ["check"] => report(&root, out, err),
        ["set", id, status] => match write::set_status(&root, id, status) {
            Ok(()) => report(&root, out, err),
            Err(e) => {
                let _ = writeln!(err, "podssh-todo: {e}");
                1
            }
        },
        ["counts"] => match write::counts(&root) {
            Ok(()) => report(&root, out, err),
            Err(e) => {
                let _ = writeln!(err, "podssh-todo: {e}");
                1
            }
        },
        ["next"] => match write::next_id(&root) {
            Ok(id) => {
                let _ = writeln!(out, "{id}");
                0
            }
            Err(e) => {
                let _ = writeln!(err, "podssh-todo: {e}");
                1
            }
        },
        ["remap", rest @ ..] => {
            let dry = rest.iter().any(|w| *w == "--dry-run" || *w == "-n");
            let files: Vec<String> = rest.iter().filter(|w| !w.starts_with('-')).map(|w| w.to_string()).collect();
            if files.is_empty() || rest.iter().any(|w| w.starts_with('-') && *w != "--dry-run" && *w != "-n") {
                return usage(err, "remap needs one FILE or more, and takes only --dry-run");
            }
            remap_command(&root, &files, dry, out, err)
        }
        _ => usage(err, "unknown command"),
    }
}

/// Move the citations of `files`, print what moved and what a person must
/// read, then check the record (unless nothing was written).
fn remap_command(
    root: &Path,
    files: &[String],
    dry: bool,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> i32 {
    let head = |rel: &str| remap::git_head(root, rel);
    let r = match remap::remap(root, files, &head, !dry) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err, "podssh-todo: remap: {e}");
            return 1;
        }
    };
    for line in &r.notes {
        let _ = writeln!(out, "note: {line}");
    }
    for line in &r.moved {
        let _ = writeln!(out, "moved: {line}");
    }
    for line in &r.kept {
        let _ = writeln!(out, "kept (new in this change): {line}");
    }
    for line in &r.review {
        let _ = writeln!(out, "REVIEW: {line}");
    }
    let verb = if dry { "would move" } else { "moved" };
    let _ = writeln!(
        out,
        "podssh-todo: remap: {verb} {} citations; {} to review; {} on new lines kept",
        r.moved.len(),
        r.review.len(),
        r.kept.len()
    );
    if dry {
        0
    } else {
        report(root, out, err)
    }
}

fn usage(err: &mut dyn std::io::Write, why: &str) -> i32 {
    let _ = writeln!(err, "podssh-todo: {why}\n{USAGE}");
    64
}

/// Run the reader and print what it found.
fn report(root: &Path, out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let r = check::check(root);
    if r.problems.is_empty() {
        let _ = writeln!(out, "podssh-todo: the record agrees: {}", r.counts.phrase());
        0
    } else {
        for p in &r.problems {
            let _ = writeln!(err, "{p}");
        }
        let _ = writeln!(err, "podssh-todo: {} problems in the record", r.problems.len());
        1
    }
}
