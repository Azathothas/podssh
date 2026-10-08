//! The remap writer against edits of a cited file. HEAD is a closure over
//! the texts before the edit, so no test needs git.

mod common;

use std::collections::HashMap;

use common::{Tree, SOURCE};
use podssh_todo::check::check_with;
use podssh_todo::remap::{remap, Report};

const LIB: &str = "crates/x/src/lib.rs";
const TWO: &str = "crates/x/src/two.rs";

/// Each file of the tree, as HEAD has it.
fn snapshot(t: &Tree) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for rel in ["TODO/INDEX.md", "TODO/PROGRESS.md", "TODO/area.md", "docs/ROADMAP.md", "README.md", LIB] {
        out.insert(rel.to_string(), t.read(rel));
    }
    for rel in ["docs/notes.md", TWO] {
        if t.path().join(rel).is_file() {
            out.insert(rel.to_string(), t.read(rel));
        }
    }
    out
}

fn run(t: &Tree, head: &HashMap<String, String>, write: bool) -> Report {
    run_on(t, head, LIB, write)
}

fn run_on(t: &Tree, head: &HashMap<String, String>, file: &str, write: bool) -> Report {
    let get = |rel: &str| Ok::<_, String>(head.get(rel).cloned());
    remap(t.path(), &[file.to_string()], &get, write).unwrap()
}

#[test]
fn a_line_added_above_a_cited_line_moves_the_citation() {
    let t = Tree::new("remap-above");
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0\n{SOURCE}"));
    let r = run(&t, &head, true);
    let area = t.read("TODO/area.md");
    assert!(area.contains("`crates/x/src/lib.rs:4`."), "{area}");
    assert!(area.contains("`crates/x/src/lib.rs:3-5`"), "{area}");
    assert!(area.contains("`crates/x/src/lib.rs:5` says \"line 4\""), "{area}");
    assert_eq!(r.moved.len(), 3, "{r:#?}");
    assert!(r.review.is_empty() && r.kept.is_empty(), "{r:#?}");
    // The record agrees, the quote included: line 5 says "line 4" now.
    assert_eq!(t.problems(), Vec::<String>::new());
}

#[test]
fn a_change_inside_a_cited_range_is_listed_and_not_moved() {
    let t = Tree::new("remap-inside");
    let head = snapshot(&t);
    t.write(LIB, &SOURCE.replace("line 3", "line three"));
    let r = run(&t, &head, true);
    let area = t.read("TODO/area.md");
    assert!(area.contains("`crates/x/src/lib.rs:3`."), "{area}");
    assert!(area.contains("`crates/x/src/lib.rs:2-4`"), "{area}");
    assert_eq!(r.review.len(), 2, "{r:#?}");
    assert!(r.review.iter().any(|l| l.contains("lib.rs 3:") && l.contains("move the citation by hand")), "{r:#?}");
    assert!(r.review.iter().any(|l| l.contains("lib.rs 2-4:") && l.contains("a line inside it changed")), "{r:#?}");
    assert!(r.moved.is_empty(), "{r:#?}");
}

/// A range names a part of a file; it moves by its ends when a line inside
/// it changed, so it keeps naming that part, and it is listed for review.
#[test]
fn a_range_moves_by_its_ends_when_a_line_inside_changed() {
    let t = Tree::new("remap-range-ends");
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0
{}", SOURCE.replace("line 3", "line three")));
    let r = run(&t, &head, true);
    let area = t.read("TODO/area.md");
    assert!(area.contains("`crates/x/src/lib.rs:3-5`"), "{area}");
    assert!(area.contains("`crates/x/src/lib.rs:3`."), "a changed single line stays: {area}");
    assert!(r.review.iter().any(|l| l.contains("lib.rs 3-5: moved by its ends")), "{r:#?}");
    // An end that changed keeps the range where it was.
    let t = Tree::new("remap-range-end-changed");
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0
{}", SOURCE.replace("line 4", "line four")));
    let r = run(&t, &head, true);
    assert!(t.read("TODO/area.md").contains("`crates/x/src/lib.rs:2-4`"));
    assert!(r.review.iter().any(|l| l.contains("lib.rs 2-4:") && l.contains("by hand")), "{r:#?}");
}

#[test]
fn a_second_run_after_a_second_edit_moves_from_head_not_twice() {
    let t = Tree::new("remap-twice");
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0\n{SOURCE}"));
    run(&t, &head, true);
    t.write(LIB, &format!("line -1\nline 0\n{SOURCE}"));
    run(&t, &head, true);
    let area = t.read("TODO/area.md");
    assert!(area.contains("`crates/x/src/lib.rs:5`."), "{area}");
    assert!(area.contains("`crates/x/src/lib.rs:4-6`"), "{area}");
    // A third run with no edit moves nothing.
    let r = run(&t, &head, true);
    assert!(r.moved.is_empty(), "{r:#?}");
    assert_eq!(t.read("TODO/area.md"), area);
}

#[test]
fn a_citation_moved_by_hand_is_kept_on_the_next_run() {
    let t = Tree::new("remap-by-hand");
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0\n{}", SOURCE.replace("line 3", "line three")));
    let first = run(&t, &head, true);
    assert!(first.review.iter().any(|l| l.contains("lib.rs 3:")), "{first:#?}");
    // The person reads the changed line and moves the citation to it.
    t.plant("TODO/area.md", "`crates/x/src/lib.rs:3`.", "`crates/x/src/lib.rs:4`.");
    let second = run(&t, &head, true);
    assert!(t.read("TODO/area.md").contains("`crates/x/src/lib.rs:4`."));
    assert!(!second.review.iter().any(|l| l.contains("lib.rs 4:")), "{second:#?}");
}

#[test]
fn a_bare_line_after_a_citation_moves_and_a_fence_does_not() {
    let t = Tree::new("remap-bare");
    t.write(
        "docs/notes.md",
        "# Notes\n\nSee `crates/x/src/lib.rs:2` and\n`:4-5`.\n\n```sh\nsed -n 3p `crates/x/src/lib.rs:3`\n```\n\nAlone: `:3`.\n",
    );
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0\n{SOURCE}"));
    run(&t, &head, true);
    let notes = t.read("docs/notes.md");
    assert!(notes.contains("See `crates/x/src/lib.rs:3` and\n`:5-6`."), "{notes}");
    assert!(notes.contains("sed -n 3p `crates/x/src/lib.rs:3`"), "a fenced line moved: {notes}");
    assert!(notes.contains("Alone: `:3`."), "a bare span with no citation before it moved: {notes}");
}

#[test]
fn a_line_new_in_this_change_is_kept() {
    let t = Tree::new("remap-new-line");
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0\n{SOURCE}"));
    // Written after the edit, with the new numbers.
    t.plant("TODO/area.md", "Bound the wait.", "Bound the wait at `crates/x/src/lib.rs:6`.");
    let r = run(&t, &head, true);
    assert!(t.read("TODO/area.md").contains("Bound the wait at `crates/x/src/lib.rs:6`."));
    assert_eq!(r.kept.len(), 1, "{r:#?}");
}

#[test]
fn line_endings_are_kept_and_a_dry_run_writes_nothing() {
    let t = Tree::new("remap-crlf");
    t.write("docs/notes.md", "# Notes\r\n\r\nSee `crates/x/src/lib.rs:2`.\r\n");
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0\n{SOURCE}"));
    let dry = run(&t, &head, false);
    assert_eq!(dry.moved.len(), 4, "{dry:#?}");
    assert_eq!(t.read("docs/notes.md"), "# Notes\r\n\r\nSee `crates/x/src/lib.rs:2`.\r\n");
    run(&t, &head, true);
    assert_eq!(t.read("docs/notes.md"), "# Notes\r\n\r\nSee `crates/x/src/lib.rs:3`.\r\n");
}

#[test]
fn a_file_that_is_not_in_head_moves_nothing() {
    let t = Tree::new("remap-new-file");
    let mut head = snapshot(&t);
    head.remove(LIB);
    t.write(LIB, &format!("line 0\n{SOURCE}"));
    let r = run(&t, &head, true);
    assert!(r.moved.is_empty(), "{r:#?}");
    assert!(r.notes.iter().any(|n| n.contains("not in HEAD")), "{r:#?}");
}

#[test]
fn a_line_that_cites_two_files_moves_in_a_run_for_each() {
    let t = Tree::new("remap-two-files");
    t.write(TWO, SOURCE);
    t.write("docs/notes.md", "# Notes

See `crates/x/src/lib.rs:2` and `crates/x/src/two.rs:3`.
");
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0
{SOURCE}"));
    run_on(&t, &head, LIB, true);
    assert!(t.read("docs/notes.md").contains("`crates/x/src/lib.rs:3` and `crates/x/src/two.rs:3`"));
    // The line differs from HEAD now; the run for the second file still
    // finds it, and keeps what the first run did.
    t.write(TWO, &format!("line -1
line 0
{SOURCE}"));
    let r = run_on(&t, &head, TWO, true);
    let notes = t.read("docs/notes.md");
    assert!(notes.contains("`crates/x/src/lib.rs:3` and `crates/x/src/two.rs:5`"), "{notes}");
    assert!(r.kept.is_empty(), "{r:#?}");
}

/// A cited file edited with no remap: the check names each citation that
/// would move, with the command. After the remap it agrees, and with no git
/// (`None`) it says nothing of the kind.
#[test]
fn an_edit_with_no_remap_is_found_by_the_check() {
    let t = Tree::new("remap-forgotten");
    let head = snapshot(&t);
    t.write(LIB, &format!("line 0\n{SOURCE}"));
    let get = |rel: &str| Ok::<_, String>(head.get(rel).cloned());
    let forgotten = |changed: Option<Vec<String>>| -> Vec<String> {
        check_with(t.path(), changed, &get)
            .problems
            .iter()
            .map(|p| p.to_string())
            .filter(|p| p.contains("cargo todo remap"))
            .collect()
    };
    let found = forgotten(Some(vec![LIB.to_string()]));
    assert_eq!(found.len(), 3, "{found:#?}");
    assert!(found[0].starts_with("TODO/area.md:"), "{found:#?}");
    assert!(found.iter().all(|p| p.contains("run `cargo todo remap crates/x/src/lib.rs`")), "{found:#?}");
    assert!(forgotten(None).is_empty(), "no git: nothing to say");

    remap(t.path(), &[LIB.to_string()], &get, true).unwrap();
    assert!(forgotten(Some(vec![LIB.to_string(), "TODO/area.md".to_string()])).is_empty());
}
