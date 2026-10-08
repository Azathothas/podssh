//! ⭐ **E32's acceptance: the page and `--help` must agree on every flag.**
//!
//! ⛔ `docs/spec/06-cli.md`:163-165: *"Extract every flag name from `--help`
//! output and every `.It`/`.Fl` from the man page; ⛔ **the sets must be
//! equal.** ⛔ A missing or extra flag fails the build."* ⛔ And
//! `docs/TODO/cli/man.md`:210-217 adds the half that is easy to skip:
//! *"assert `help_set == man_set` in **both** directions with the missing and
//! extra sets printed. ⛔ A gate that only asserts 'every help flag appears in
//! the page' is half the gate."*
//!
//! ⛔ **What this file reads is the rendered text, not the table.** Both sides
//! are parsed out of what a user would see — [`help::verb_help`]'s `OPTIONS:`
//! block and [`man::page`]'s `.Fl` lines — ⛔ because a gate that compared
//! `VERBS` to itself would pass while either renderer dropped a row. ⛔ The
//! table is then used as the *third* reading, so a flag that both renderers
//! agree on but the table does not have is still a failure.
//!
//! ⛔ **It reads no file.** `man.md`:165-173 chooses runtime generation over a
//! committed `.1` page, and plant 3 is that decision read the other way round:
//! a hand-written page reintroduced beside this one changes nothing here,
//! because nothing here reads it. ⛔ That makes plant 3 a *review* failure
//! rather than an exit code — the entry says so — and ⛔ the review note is
//! `grep -rn 'podssh.1'` returning any file under `docs/`.

use podssh_cli::flags::VERBS;
use podssh_cli::{help, man};

/// ⛔ The readers live in `tests/man_extract/mod.rs`, ⛔ and they are separate
/// because the rule and the parser outgrew one file: `RULES.md`:80-91 asks for
/// a split *"into modules with names that say what they hold"*.
mod man_extract;
use man_extract::*;

/// ⛔ The one option every verb accepts. It is not a row in any verb's table —
/// the parser declares it — ⛔ so it is named here once, and the check that it
/// is rendered is the *section* checks below rather than a table read.
const UNIVERSAL: &str = "--help";

// -------------------------------------------------------------------- checks

/// ⛔ **A gate that extracted nothing would pass on nothing.** ⛔ This is the
/// guard E31's flag-table check learned the hard way (*"a line range that
/// drifts to nothing makes every other assertion in this file pass
/// vacuously"*), and ⛔ the floors are floors: a flag added later must not
/// require this test to be edited.
#[test]
fn the_extractors_are_not_vacuous() {
    let page = man::page();
    let regions = man_regions(&page);
    assert!(
        regions.contains_key(""),
        "the page has no top-level OPTIONS region, so the top-level check would compare nothing"
    );
    for (name, verb) in sections() {
        let expected = tree_map(verb);
        let h = help_map(&options_block(&help_text(verb)), verb);
        let m = man_map(regions.get(&name).unwrap_or_else(|| panic!("no region {name:?}")), verb);
        assert!(
            h.len() >= expected.len(),
            "section {name:?}: the help extractor found {} flags and the table has {}",
            h.len(),
            expected.len()
        );
        assert!(
            m.len() >= expected.len(),
            "section {name:?}: the page extractor found {} flags and the table has {}",
            m.len(),
            expected.len()
        );
    }

    // ⛔ And the spot checks, by name, on the flags a first-token-only parser
    // loses: `-4`/`-6` are alphanumeric, `--StrictHostKeyChecking` is long-only,
    // and `-P` is a row whose meaning is per-verb.
    let ssh = VERBS.iter().find(|v| v.name == "ssh").unwrap();
    let ssh_page = man_map(regions.get("ssh").unwrap(), Some(ssh));
    let ssh_help = help_map(&options_block(&help::verb_help(ssh)), Some(ssh));
    for want in ["--port", "--tag", "--forward-local", "--StrictHostKeyChecking", "--ipv4-only"] {
        assert!(ssh_page.contains_key(want), "the page extractor missed {want}");
        assert!(ssh_help.contains_key(want), "the help extractor missed {want}");
    }
    // ⛔ And both spellings, because a page that printed only `-p` would still
    // reach the same canonical name and slip through the set comparison.
    let items = man_items(regions.get("ssh").unwrap());
    let port = items
        .iter()
        .find(|i| i.flags.iter().any(|f| f == "-p"))
        .unwrap_or_else(|| panic!("no .Fl item names -p"));
    assert!(port.flags.iter().any(|f| f == "--port"), "one spelling only: {port:?}");
    assert!(
        options_block(&help::verb_help(ssh)).contains("-p, --port PORT"),
        "the help block lost a spelling"
    );
}

/// ⭐ **The gate.** ⛔ `06-cli.md`:163-165, both directions, naming the flag.
#[test]
fn every_sections_flag_set_is_equal_in_both_renderings() {
    let page = man::page();
    let regions = man_regions(&page);
    for (name, verb) in sections() {
        let h = help_map(&options_block(&help_text(verb)), verb);
        let m = man_map(regions.get(&name).unwrap_or_else(|| panic!("no region {name:?}")), verb);

        // ⛔ The two directions, printed separately and by name: ⛔ a gate that
        // fails without saying which flag has taught this project to be ignored
        // (`man.md`:215-217).
        let missing: Vec<&String> = h.keys().filter(|k| !m.contains_key(*k)).collect();
        let extra: Vec<&String> = m.keys().filter(|k| !h.contains_key(*k)).collect();
        assert!(
            missing.is_empty(),
            "section {name:?}: in --help and NOT in the page (drift-free): {missing:?}"
        );
        assert!(
            extra.is_empty(),
            "section {name:?}: in the page and NOT in --help (current): {extra:?}"
        );
        // ⛔ The metavariable too — `man.md`:213's "argument shapes". A page
        // that showed `PORT` where the help shows `HOST:PORT` describes a
        // command line that does not exist.
        assert_eq!(h, m, "section {name:?}: the two renderings disagree");
    }
}

/// ⛔ **The third reading: the table.** ⛔ A flag both renderers agree on and
/// the tree does not have is a page documenting a flag the binary refuses;
/// ⛔ a flag the table has and a renderer dropped is the same defect one layer
/// down.
#[test]
fn every_sections_flag_set_is_the_tables() {
    let page = man::page();
    let regions = man_regions(&page);
    for (name, verb) in sections() {
        let expected = tree_map(verb);
        let h = help_map(&options_block(&help_text(verb)), verb);
        let m = man_map(regions.get(&name).unwrap_or_else(|| panic!("no region {name:?}")), verb);
        for (label, got) in [("--help", &h), ("the page", &m)] {
            let missing: Vec<&String> =
                expected.keys().filter(|k| !got.contains_key(*k)).collect();
            let extra: Vec<&String> = got.keys().filter(|k| !expected.contains_key(*k)).collect();
            assert!(
                missing.is_empty(),
                "section {name:?}: {label} omits {missing:?}, which the tree has"
            );
            assert!(
                extra.is_empty(),
                "section {name:?}: {label} has {extra:?}, which the tree does not"
            );
        }
    }
}

/// ⛔ **The argument shapes, against the rows.** ⛔ `-W HOST:PORT` and `-W PORT`
/// are different command lines, and a set comparison cannot tell them apart.
#[test]
fn every_flags_argument_shape_is_the_rows() {
    let page = man::page();
    let regions = man_regions(&page);
    for (name, verb) in sections() {
        let m = man_map(regions.get(&name).unwrap_or_else(|| panic!("no region {name:?}")), verb);
        let h = help_map(&options_block(&help_text(verb)), verb);
        for (flag, metavar) in &m {
            let Some(row) = row_for(verb, flag) else { continue };
            assert_eq!(
                metavar.as_deref(),
                row.arg,
                "section {name:?}: the page shows {flag} as {metavar:?} and the table says {:?}",
                row.arg
            );
            let expected = row.arg.map(str::to_string);
            assert_eq!(
                h.get(flag),
                Some(&expected),
                "section {name:?}: --help shows {flag} with a different argument"
            );
        }
    }
}

/// ⛔ **The sentence, not the set.** ⛔ `man.md`:165-173 rejects a checked-in
/// template because *"a set cannot tell a stale sentence from a fresh one"* —
/// ⛔ the answer is that there is one sentence, in the table, and this asserts
/// both renderings carry it. ⛔ A description that stopped being true is caught
/// here even though the flag set is unchanged.
#[test]
fn every_description_in_the_page_is_the_one_help_prints() {
    let page = man::page();
    let regions = man_regions(&page);
    for (name, verb) in sections() {
        let (Some(v), Some(region)) = (verb, regions.get(&name)) else { continue };
        for row in v.flags {
            let sentence = man::text(&help::help_text(row));
            assert!(
                region.contains(&sentence),
                "section {name:?}: the page does not carry {sentence:?}"
            );
            assert!(
                help_text(Some(v)).contains(&help::help_text(row)),
                "section {name:?}: --help does not carry the row's own sentence"
            );
        }
        // ⛔ The universal option and the synopsis are shared facts too.
        assert!(region.contains(&man::text(podssh_cli::flags::HELP_FLAG.help)), "section {name:?}: no --help text");
        assert!(
            region.contains(&man::text(&man::usage_line(v))),
            "section {name:?}: the page does not carry `{}`",
            man::usage_line(v)
        );
    }
    // ⛔ The top-level rows, which are literals in both renderers.
    for sentence in ["Print help", "Print version"] {
        assert!(page.contains(sentence), "the page lost {sentence:?}");
        assert!(help::top_level_help().contains(sentence), "--help lost {sentence:?}");
    }
}
