//! **The acceptance of the relay's facts check, and its plants in one place.**
//!
//! Every test here runs against a **local copy of the relay's published
//! document**, committed under `tests/`, so the gate is provable on a host with
//! no egress. That copy is a *recorded measurement*, not a fixture someone
//! invented: its SHA-256 is the one in `relay-facts.toml`, and
//! `spec_copy_matches_the_pin` fails if it is edited without re-pinning.
//!
//! **The plants are tests, not comments.** The check must be seen to fail, so the
//! failures of the gate are asserted here rather than
//! described. A gate that has never failed is indistinguishable from one that
//! always passes.

use std::path::Path;

use podssh_probe::relay_facts::{
    assert_facts, line_count, read_operand, sha256_hex, verdict_from, Moved, Observed, Verdict,
};
use podssh_probe::Facts;

const SPEC_COPY: &str = include_str!("spec/relay-spec-2026-10-03-r2.txt");

fn facts() -> Facts {
    Facts::load().expect("the facts file is embedded and must parse")
}

/// Replace the first line carrying `needle` with a mutated one.
fn mutate(spec: &str, needle: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(spec.len());
    let mut done = false;
    for line in spec.split_inclusive('\n') {
        if !done && line.contains(needle) {
            out.push_str(&line.replace(needle, replacement));
            done = true;
        } else {
            out.push_str(line);
        }
    }
    assert!(done, "the plant must change something, or it proves nothing");
    out
}

// ── the control: correct input ──────────────────────────────────────────────

#[test]
fn spec_copy_matches_the_pin() {
    let facts = facts();
    assert_eq!(
        sha256_hex(SPEC_COPY.as_bytes()),
        facts.pin.spec_sha256,
        "the committed copy of the relay's document must be the one the pin names"
    );
    assert_eq!(line_count(SPEC_COPY), facts.pin.spec_lines);
    assert_eq!(SPEC_COPY.len(), facts.pin.spec_bytes);
}

#[test]
fn every_structural_fact_holds_on_the_pinned_document() {
    let facts = facts();
    assert!(!facts.facts.is_empty(), "a gate with no facts asserts nothing");
    match assert_facts(SPEC_COPY, &facts, Some("2026-10-03-r2")) {
        Verdict::Ok { version, pinned, lines, .. } => {
            assert_eq!(version.as_deref(), Some("2026-10-03-r2"));
            assert_eq!(pinned, facts.pin.version);
            assert_eq!(lines, facts.pin.spec_lines);
        }
        Verdict::Failed { disagreements, .. } => {
            panic!("the pinned document must satisfy every fact: {disagreements:?}")
        }
        Verdict::Unknown { .. } => panic!("a local document is never Unknown"),
    }
}

#[test]
fn the_node_frame_cap_arithmetic_is_the_one_the_relay_publishes() {
    let facts = facts();
    let relation = &facts.relations[0];
    let left = read_operand(&relation.src, SPEC_COPY).expect("spec line 182 publishes two numbers");
    let right = read_operand(&relation.dst, SPEC_COPY).expect("spec line 182 publishes one");
    // Group 1 of line 182 is the TOTAL cap, not the id length. Its prose is
    // "over 65568 (32-byte id plus 65536 payload)": the 65568 is before the '('.
    assert_eq!(left, vec![("cap".to_string(), 65568), ("payload".to_string(), 65536)]);
    assert_eq!(right, vec![("cap".to_string(), 65568)]);

    // And the number an earlier version wrongly compared against: line 184 is
    // the OPERATOR frame's payload cap, a different limit, and 32 + 65536 is
    // not it. Asserted here so the two can never be confused again.
    assert_eq!(
        read_operand(
            &podssh_probe::facts::Operand {
                line: 184,
                section: "Reverse close codes".to_string(),
                pattern: "exceeded (\\d+) payload bytes".to_string(),
                names: vec!["cap".to_string()],
            },
            SPEC_COPY,
        )
        .expect("spec line 184 publishes one"),
        vec![("cap".to_string(), 65536)],
        "65536 on line 184 is the OPERATOR payload cap, not the node frame cap"
    );
}

// ── the plants: each fact, corrupted, must redden ──────────────────────────

/// **One test per plant, and each asserts the specific fact that fired.**
/// A plant that made the gate red for some other reason would pass here, so the
/// fact id is checked by name.
#[test]
fn plant_renamed_node_path_fails() {
    let planted = mutate(SPEC_COPY, "/v1/node/<name>", "/v1/drop/<name>");
    assert_fact_fired(&planted, "reverse-node-path");
}

#[test]
fn plant_renamed_operator_path_fails() {
    let planted = mutate(SPEC_COPY, "/v1/connect/<name>", "/v1/join/<name>");
    assert_fact_fired(&planted, "reverse-operator-path");
}

#[test]
fn plant_changed_node_open_timeout_fails() {
    let planted = mutate(SPEC_COPY, "within 15 s of `open`", "within 45 s of `open`");
    assert_fact_fired(&planted, "node-open-timeout");
}

#[test]
fn plant_changed_node_frame_cap_fails() {
    let planted =
        mutate(SPEC_COPY, "over 65568 (32-byte id plus 65536 payload)", "over 32768 (32-byte id plus 65536 payload)");
    assert_fact_fired(&planted, "reverse-node-frame-cap");
}

#[test]
fn plant_text_frames_instead_of_binary_fails() {
    let planted = mutate(
        SPEC_COPY,
        "**binary** frames carry raw TCP bytes verbatim",
        "**text** frames carry raw TCP bytes verbatim",
    );
    assert_fact_fired(&planted, "binary-frames-required");
}

#[test]
fn plant_subprotocol_offer_fails() {
    let planted = mutate(SPEC_COPY, "no subprotocol", "subprotocol `podssh.v1`");
    assert_fact_fired(&planted, "no-subprotocol");
}

#[test]
fn plant_reworded_prose_does_not_fail() {
    // **The other direction, and the one a fact gate is easy to get wrong.**
    // Reflowing a sentence, changing the surrounding table's wording, or
    // reordering prose must leave the gate green. A gate that asserts prose is
    // a conformance suite that has to be re-maintained every time the peer
    // rewords a sentence, which this check's rule forbids: the prose is never asserted.
    let reworded = SPEC_COPY.replace('\n', " \n").replace("  \n", "\n");
    match assert_facts(&reworded, &facts(), None) {
        Verdict::Ok { .. } => {}
        Verdict::Failed { disagreements, .. } => {
            panic!("reflowing prose must not redden the gate: {disagreements:?}")
        }
        Verdict::Unknown { .. } => panic!("a local document is never Unknown"),
    }
}

#[test]
fn a_truncated_document_is_failed_not_unknown() {
    // Lines past the end must be reported as disagreements, not silently
    // skipped: a shorter document is a relay that changed shape.
    let truncated = SPEC_COPY.split('\n').take(100).collect::<Vec<_>>().join("\n");
    match assert_facts(&truncated, &facts(), None) {
        Verdict::Failed { disagreements, .. } => {
            assert!(
                disagreements.iter().any(|d| d.detail.contains("does not exist")),
                "a truncated document must say a line went missing: {disagreements:?}"
            );
        }
        other => panic!("a truncated document must fail, got {other:?}"),
    }
}

#[test]
fn an_unreadable_relay_is_unknown_and_never_ok() {
    // **The defect this repository has shipped three times.** A relay that
    // could not be read must not produce `ok`, and must not produce `Failed`
    // either — those are different facts with different remedies.
    for observed in
        [Observed { version: None, document: None }, Observed { version: Some("2026-10-03-r2".into()), document: None }]
    {
        match verdict_from(&observed, &facts()) {
            Verdict::Unknown { why } => assert!(!why.is_empty(), "???? must say why"),
            other => panic!("an unreadable relay must be Unknown, got {other:?}"),
        }
    }
}

#[test]
fn a_readable_document_is_checked_whatever_health_said_and_the_move_is_visible() {
    // **The version the relay served is reported, and the pin is not
    // substituted for it.** This check's subject is a version that moves: a verdict
    // that echoed the pin back would tell an operator, after the relay
    // upgraded, that they had run against the version they pinned — which is
    // the one answer that is certainly wrong.
    let observed = Observed { version: Some("2026-10-01-r9".into()), document: Some(SPEC_COPY.to_string()) };
    match verdict_from(&observed, &facts()) {
        Verdict::Ok { version, pinned, .. } => {
            assert_eq!(version.as_deref(), Some("2026-10-01-r9"), "the served version");
            assert_eq!(pinned, facts().pin.version, "and the pin, separately");
        }
        other => panic!("a readable document is checked, whatever /health said: {other:?}"),
    }
    assert!(verdict_from(&observed, &facts()).version_moved(), "the move is visible");
    let same = Observed { version: Some(facts().pin.version.clone()), document: Some(SPEC_COPY.to_string()) };
    assert!(!verdict_from(&same, &facts()).version_moved());
    // A document read with no `/health` reports NO served version rather
    // than the pin: "not read" and "matches" must not print the same way.
    let document_only = Observed { version: None, document: Some(SPEC_COPY.to_string()) };
    match verdict_from(&document_only, &facts()) {
        Verdict::Ok { version, .. } => assert_eq!(version, None),
        other => panic!("a readable document is checked: {other:?}"),
    }
    assert!(!verdict_from(&document_only, &facts()).version_moved());
}

#[test]
fn the_facts_file_is_one_file_and_there_is_only_one() {
    // A second copy of these numbers is the drift this exists to catch.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(Path::parent).expect("a workspace root");
    // The copies that existed once; a copy found later joins the list.
    const COPIES: &[&str] = &["docs/spec/relay-structural-facts.json"];
    let found: Vec<String> = COPIES.iter().filter(|c| root.join(c).is_file()).map(|c| c.to_string()).collect();
    assert_eq!(
        found,
        Vec::<String>::new(),
        "crates/podssh-probe/facts/relay-facts.toml is the only facts file; \
         these are copies that can drift from it: {found:?}"
    );
}

// ── a fact moved within its section, or out of it (T-338) ───────────────────

/// The pinned document with `text` inserted before its line `at` (1-based).
fn insert_before(spec: &str, at: usize, text: &str) -> String {
    let mut out = String::with_capacity(spec.len() + text.len());
    for (index, line) in spec.split_inclusive('\n').enumerate() {
        if index + 1 == at {
            out.push_str(text);
        }
        out.push_str(line);
    }
    out
}

/// The notes of an `Ok` verdict, or a panic that names what came instead.
fn moved_of(spec: &str) -> Vec<Moved> {
    match assert_facts(spec, &facts(), None) {
        Verdict::Ok { moved, .. } => moved,
        other => panic!("each fact moved within its section, so each holds: {other:?}"),
    }
}

#[test]
fn a_line_inserted_at_the_top_moves_each_fact_and_each_holds_with_a_note() {
    let facts = facts();
    assert!(moved_of(SPEC_COPY).is_empty(), "the pinned copy: each fact at its line");
    let moved = moved_of(&insert_before(SPEC_COPY, 1, "A line that the relay inserted.\n"));
    let ids: Vec<&str> =
        facts.facts.iter().map(|f| f.id.as_str()).chain(facts.relations.iter().map(|r| r.id.as_str())).collect();
    for id in &ids {
        assert!(moved.iter().any(|m| m.fact_id == *id && m.to == m.from + 1), "{id} moved by one line: {moved:?}");
    }
    assert_eq!(moved.len(), ids.len(), "one note for each fact, the relation's two operands in one: {moved:?}");
    let node = moved.iter().find(|m| m.fact_id == "reverse-node-path").expect("the node path's note");
    assert_eq!((node.from, node.to, node.section.as_str()), (23, 24, "Exact addresses"));
}

#[test]
fn a_fact_that_left_its_section_fails_though_the_document_holds_its_text() {
    // The node path stands on line 23, under "Exact addresses"; the same text
    // stands under "Reverse transport (outbound-only nodes)" too, so the
    // search must stop at the section's end.
    let node_line = SPEC_COPY.split_inclusive('\n').nth(22).expect("line 23").to_string();
    assert!(node_line.contains("/v1/node/<name>"));
    let without: String =
        SPEC_COPY.split_inclusive('\n').enumerate().filter(|(i, _)| *i != 22).map(|(_, l)| l).collect();
    let moved_out = format!("{without}{node_line}");
    assert!(moved_out.contains("/v1/node/<name>"), "the text is still in the document");
    assert_fact_fired(&moved_out, "reverse-node-path");
}

#[test]
fn a_hash_line_in_a_fence_of_code_ends_no_section() {
    // Three lines before the node path, in its section: a fence whose middle
    // line starts with `#`, as a shell comment does. Read as a heading, it
    // would end "Exact addresses" before the fact.
    let fenced = insert_before(SPEC_COPY, 23, "```sh\n# a shell comment\n```\n");
    let moved = moved_of(&fenced);
    let node = moved.iter().find(|m| m.fact_id == "reverse-node-path").expect("the node path moved");
    assert_eq!((node.from, node.to), (23, 26));
}

#[test]
fn a_heading_whose_version_changed_still_names_its_section() {
    // The close codes' heading carries the document's version; a section is
    // named by the heading's first words, so a new version keeps it.
    let renamed = SPEC_COPY
        .replace("## Reverse close codes (version 2026-10-03-r2)", "## Reverse close codes (version 2027-01-01-r1)");
    assert_ne!(renamed, SPEC_COPY, "the plant must change the heading");
    let moved = moved_of(&insert_before(&renamed, 161, "A line that the relay inserted.\n"));
    assert!(moved.iter().any(|m| m.fact_id == "bad-multiplex-frame-is-1009" && m.to == 183), "{moved:?}");
    assert!(moved.iter().any(|m| m.fact_id == "node-open-timeout" && m.to == 191), "{moved:?}");
}

fn assert_fact_fired(planted: &str, fact_id: &str) {
    match assert_facts(planted, &facts(), None) {
        Verdict::Failed { disagreements, .. } => {
            assert!(
                disagreements.iter().any(|d| d.fact_id == fact_id),
                "the plant must fail on {fact_id} specifically: {disagreements:?}"
            );
        }
        Verdict::Ok { .. } => panic!("the plant was accepted: the gate is vacuous"),
        Verdict::Unknown { why } => panic!("a local document is never Unknown: {why}"),
    }
}
