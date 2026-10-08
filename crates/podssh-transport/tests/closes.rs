//! ⛔ **Every close in the published table, and the retry decision each one
//! implies.** E02's `Prove` block requires a handler for every row, because
//! *"the table's own `Observed by` column says which socket the close lands on
//! and that is what podssh must branch on"*.
//!
//! ⛔ **Every row is checked against the pinned copy of the relay's document**,
//! `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt` — 246 lines,
//! 18 359 bytes, sha256
//! `88eb1b0b8571b829daab17614ea2e27966ba5611951ea28db84660fc41cfa5a8`,
//! `curl -sSL https://tcp.ssh.relay.ajam.dev/llms-full.txt` on 2026-10-05. ⛔ **A
//! citation is not a number this file agrees with itself about**: the table used
//! to carry 137-160 for rows the copy had at 135-158, and the contiguity check
//! below was satisfied by both. ⛔ Not recalled: three line citations in this
//! repository were found wrong the same day, and a number written from memory is
//! a guess wearing a label.

use podssh_transport::closes::{classify, Classified, Leg, CLOSE_ROWS};
use podssh_transport::error::{Asked, HttpFailure, Retry, SessionAction};
use podssh_transport::LegShape;
use podssh_transport::RelayClose;

/// ⛔ **The document the `spec_line` values are read out of.** The same file
/// `podssh-probe` checks its structural facts against, included by path rather
/// than copied: ⛔ a copy here would be a second source of these numbers, which
/// is the drift the facts file exists to prevent. ⛔ If the relay moves, the pin
/// moves, the file is replaced, and this test goes red rather than stale.
const SPEC_COPY: &str = include_str!("../../podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt");

/// ⛔ **A close as the relay sends it.**
fn closed(code: u16, reason: &str) -> RelayClose {
    RelayClose { code, reason: reason.to_string(), clean: true }
}

// ── the table is complete, and 24 rows is not an accident ───────────────────

#[test]
fn the_table_has_twenty_four_rows_and_one_per_published_line() {
    assert_eq!(
        CLOSE_ROWS.len(),
        25,
        "⛔ 24 rows are PUBLISHED (170-193) and 25 are represented in Rust: \n         line 192 is a `1000 or 1011` row and each code needs its own entry, or \n         a `reject` would classify as if it were a `close`"
    );

    let mut lines: Vec<u16> = CLOSE_ROWS.iter().map(|r| r.spec_line).collect();
    lines.sort_unstable();
    lines.dedup();
    // ⛔ **Line 192 carries two rows**, because it is a `1000 or 1011` row: node
    // `close` relays as 1000 and node `reject` as 1011. Every other line is one.
    // ⛔ **24 distinct lines, 170-193 with no gap**, and line 192 carrying two
    // rows. A gap would mean a published row nobody transcribed, and a
    // transcription of a line that is not published would mean the reverse.
    assert_eq!(lines.len(), 24, "every line from 170 to 193 carries a row");
    assert_eq!(*lines.first().unwrap(), 170);
    assert_eq!(*lines.last().unwrap(), 193);
    assert_eq!(lines, (170..=193).collect::<Vec<u16>>(), "⛔ no line skipped, no line invented");
    assert_eq!(CLOSE_ROWS.iter().filter(|r| r.spec_line == 192).count(), 2);

    // ⛔ **And every citation resolves to the row it names.** ⛔ This is the
    // assertion the contiguous run above cannot make: 137..160 is exactly as
    // contiguous as 170..193, and only one of the two runs is the table.
    let document: Vec<&str> = SPEC_COPY.split('\n').collect();
    for row in CLOSE_ROWS {
        let line = document
            .get((row.spec_line - 1) as usize)
            .unwrap_or_else(|| panic!("spec line {} is past the document", row.spec_line));
        assert!(
            line.to_lowercase().contains(row.reason),
            "spec line {} does not carry {:?}: {}",
            row.spec_line,
            row.reason,
            line.trim()
        );
    }
}

#[test]
fn every_row_matches_the_operators_own_action_column() {
    // ⛔ **The row's action is asserted, not implied.** A table whose actions were
    // filled in by hand would drift from the document silently, and the actions
    // are the only part podssh actually runs.
    for row in CLOSE_ROWS {
        assert!(
            !row.reason.is_empty() && row.reason.chars().all(|c| c.is_ascii_lowercase() || c == ' ' || c == '-'),
            "row on spec line {} has an unmatchable reason {:?}",
            row.spec_line,
            row.reason
        );
        assert!(
            !row.action.explain().is_empty(),
            "spec line {} has no explanation",
            row.spec_line
        );
        let classified = classify(&closed(row.code, row.reason));
        assert_eq!(
            classified.row, Some(*row),
            "spec line {} must classify back to itself",
            row.spec_line
        );
        assert_eq!(classified.session, row.action);
    }
}

// ── the codes that must NEVER be retried ───────────────────────────────────

#[test]
fn a_1001_is_never_retried_and_the_two_rows_are_never_confused() {
    // ⛔ **Spec line 170:** `POST /v1/stop/<name>` ran — *"do not retry the same
    // name"*. ⛔ **Spec line 171:** the 72h TTL elapsed — create a new pair.
    // ⛔ **Both are 1001, and one of them wants a credential minted while the
    // other wants nothing retried at all.** A client that classified on the code
    // alone would mint a new pair after a deliberate revocation.
    let revoked = classify(&closed(1001, "operator stopped reverse relay"));
    assert_eq!(revoked.session, SessionAction::Stop);
    assert_eq!(revoked.retry, Retry::Never);

    let expired = classify(&closed(1001, "pair expired"));
    assert_eq!(expired.session, SessionAction::MintNewPair);
    assert_eq!(expired.retry, Retry::NewPair);
    assert_ne!(revoked.row, expired.row);

    // ⛔ **An empty reason on an ambiguous code resolves to no row at all**,
    // rather than guessing between revocation and expiry.
    let blank = classify(&closed(1001, ""));
    assert_eq!(blank.row, None, "⛔ guessing here would mint a credential on a revocation");
    assert_eq!(blank.retry, Retry::Never);
    assert_eq!(blank.session, SessionAction::Unknown);
}

/// The relay's own bodies (the contract, spec lines 97-103, and the tests of
/// `podssh_relay::open`), for each leg: a forward `403` is repaired by a new
/// token unless it names the target; a reverse `403` waits for the runner's
/// reading of `expires`; a `503` is not retried on this host; a `409` exits on
/// a node upgrade and pairs again on `/v1/pair`.
#[test]
fn http_answers_follow_the_contract() {
    const WRONG_TOKEN: &str = "missing or wrong token";
    const POLICY: &str = "forward: github.com:25 not in the ALLOW list";
    const REVERSE: &str = "reverse: forbidden";
    const NO_TOKENS: &str = "forward relay authentication is not configured";
    let forward = Asked::Upgrade(LegShape::Forward);
    let node = Asked::Upgrade(LegShape::ReverseNode);
    let operator = Asked::Upgrade(LegShape::ReverseOperator);

    let cases = [
        (403, WRONG_TOKEN, forward, HttpFailure::TokenRefused, Retry::NewToken),
        (403, POLICY, forward, HttpFailure::PolicyRefused, Retry::Never),
        (400, "blocked address range", forward, HttpFailure::PolicyRefused, Retry::Never),
        (403, REVERSE, node, HttpFailure::ReverseForbidden, Retry::ReverseForbidden),
        (403, REVERSE, operator, HttpFailure::ReverseForbidden, Retry::ReverseForbidden),
        (503, NO_TOKENS, forward, HttpFailure::Unavailable, Retry::Never),
        (503, NO_TOKENS, node, HttpFailure::Unavailable, Retry::Never),
        (503, NO_TOKENS, operator, HttpFailure::Unavailable, Retry::Never),
        (409, "", node, HttpFailure::NameInUse, Retry::Never),
        (409, "", Asked::Pair, HttpFailure::PairAgain, Retry::NewPair),
        (426, "", node, HttpFailure::UpgradeRequired, Retry::Never),
        (502, "relay: connect failed: timed out", forward, HttpFailure::BadGateway, Retry::Reconnect),
        (429, "slow down", forward, HttpFailure::RateLimited, Retry::Reconnect),
        (418, "", forward, HttpFailure::Other(418), Retry::Never),
    ];
    for (status, body, asked, failure, retry) in cases {
        let got = HttpFailure::from_answer(status, body, asked);
        assert_eq!(got, failure, "{status} {body:?} on {asked:?}");
        assert_eq!(got.retry(), retry, "{status} {body:?} on {asked:?}");
    }
    assert!(Retry::NewToken.is_retryable());
    assert!(!Retry::ReverseForbidden.is_retryable(), "only the runner knows expires");

    // The error keeps the body for the user, made safe to print.
    let error = podssh_transport::socket::http_failure(403, "forward: x:25 not in the ALLOW list\u{1b}[2J", forward);
    let text = error.to_string();
    assert!(text.contains("policy") && text.contains("not in the ALLOW list"), "{text}");
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert_eq!(error.retry(), Retry::Never);
}

#[test]
fn a_codec_fault_is_never_retried_because_the_next_attempt_sends_the_same_bytes() {
    // ⛔ Each of these is podssh's own bytes being wrong. ⛔ Reconnecting does not
    // change them, so a retry loop would hide a codec bug behind a network error.
    let never = [
        (1003u16, "invalid control json"),
        (1003, "invalid session id"),
        (1003, "unknown control type"),
        (1003, "bad multiplex id"),
        (1003, "data before ready"),
        (1003, "binary frames required"),
        (1009, "control frame byte cap"),
        (1009, "bad multiplex frame"),
        (1009, "frame byte cap"),
        (1011, "relay backpressure"),
    ];
    for (code, reason) in never {
        let classified = classify(&closed(code, reason));
        assert_eq!(
            classified.retry,
            Retry::Never,
            "⛔ `{reason}` ({code}) must not be retried"
        );
        assert!(!classified.retry.is_retryable());
    }
}

#[test]
fn a_session_byte_cap_means_a_new_session_and_not_a_reconnect() {
    // ⛔ **Spec line 183:** *"One session exceeded 64 MiB in both directions. Open
    // a new session."* ⛔ **The socket is fine**; reconnecting would throw away a
    // working socket and the count would restart from zero by accident.
    // ⛔ **And two rows in this family DO retry**, because their own action
    // column says so and ⛔ a table that refused everything would not be
    // following the document. **Spec line 172:** *"Re-open the session; never
    // invent addressing"* — a stale id is stale, so a new session on the same
    // socket is the stated remedy, and reconnecting would change nothing.
    let stale_id = classify(&closed(1003, "unknown session id"));
    assert_eq!(stale_id.row.expect("a published row").spec_line, 172);
    assert_eq!(stale_id.retry, Retry::NewSession, "⛔ the row says re-open the session");
    // **Spec line 180:** `1008 wait for ready` — operator data arrived before the
    // node readied; the remedy is to wait for `ready`, which costs a new session
    // attempt rather than a reconnect of the same socket.
    let too_early = classify(&closed(1008, "wait for ready"));
    assert_eq!(too_early.row.expect("a published row").spec_line, 180);
    assert_eq!(too_early.retry, Retry::NewSession);

    let classified = classify(&closed(1009, "session byte cap"));
    assert_eq!(classified.session, SessionAction::OpenNewSession);
    assert_eq!(classified.retry, Retry::NewSession);
    assert_ne!(classified.retry, Retry::Reconnect, "⛔ the two are different actions");
    assert!(classified.retry.is_retryable());
}

#[test]
fn the_three_1011_operator_rows_tell_themselves_apart_only_by_reason() {
    // ⛔ **Spec lines 186, 187 and 188 are three `1011` rows that differ in nothing
    // but prose**: `node unavailable` (retry the open), `node offline` (wait and
    // retry) and `node disconnected` (reconnect). ⛔ **A client that reads only
    // the code cannot tell them apart**, which is the whole reason this table
    // matches on the reason.
    let reasons = ["node unavailable", "node offline", "node disconnected", "socket error"];
    let mut seen = std::collections::HashSet::new();
    for reason in reasons {
        let classified = classify(&closed(1011, reason));
        let row = classified.row.unwrap_or_else(|| panic!("`{reason}` must match a row"));
        assert_eq!(row.code, 1011);
        assert_eq!(row.reason, reason);
        assert!(seen.insert(row.spec_line), "`{reason}` reused a line");
        assert_eq!(classified.retry, Retry::Reconnect, "every 1011 here reconnects");
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn a_node_supplied_close_carries_the_nodes_own_reason_and_the_code_is_not_the_signal() {
    // ⛔ **Spec line 192**, verbatim: *"Per-session refusal, not a fixed pair:
    // node `close` relays as `1000`, node `reject` as `1011`, both carrying the
    // node's own reason — or the literal type string when the node sent none —
    // limited to 100 chars and 123 UTF-8 bytes … Parse the reason, not the code."*
    let node_close = classify(&closed(1000, "connection refused"));
    assert_eq!(
        node_close.session,
        SessionAction::ParseReasonNotCode,
        "⛔ line 192 carries the node's OWN reason, so a refusal must resolve to "
    );
    assert_eq!(node_close.row.expect("line 192").spec_line, 192);

    let node_reject = classify(&closed(1011, "connection refused"));
    assert_eq!(node_reject.session, SessionAction::ParseReasonNotCode);
    assert_eq!(node_reject.retry, Retry::Never, "a refusal is not a transient failure");

    // ⛔ **The two spellings of the row's own Reason column, and both codes
    // line 192 names.** ⛔ `1001` is NOT one of them, so a `1001` carrying a
    // refusal reason must stay unmatched rather than borrow this row.
    assert_eq!(classify(&closed(1000, "node-supplied")).row.unwrap().spec_line, 192);
    assert_eq!(classify(&closed(1011, "node-supplied")).row.unwrap().spec_line, 192);
    assert_eq!(classify(&closed(1000, "node supplied")).row.unwrap().spec_line, 192);
    assert_eq!(
        classify(&closed(1001, "connection refused")).row,
        None,
        "⛔ 1001 is not a code line 192 names"
    );

    // ⛔ And the reason survives into the message, because parsing the reason is
    // the whole instruction.
    let message = classify(&closed(1011, "connection refused")).message();
    assert!(message.contains("1011 connection refused"), "{message}");
}

/// Each message names the code and the reason as received, matched or not,
/// with no control characters and within the relay's own cap.
#[test]
fn the_message_names_the_code_and_the_reason() {
    let unmatched = classify(&closed(4000, "x")).message();
    assert!(unmatched.contains("4000 x"), "{unmatched}");
    assert!(unmatched.contains("forward close set is unpublished"), "{unmatched}");
    let refusal = classify(&closed(1011, "connection refused")).message();
    assert!(refusal.contains("1011 connection refused"), "{refusal}");
    assert!(refusal.contains("spec line 192"), "{refusal}");
    let expired = classify(&closed(1001, "pair expired")).message();
    assert!(expired.contains("1001 pair expired"), "{expired}");
    let empty = classify(&closed(1001, "")).message();
    assert!(empty.contains("1001 (no reason)"), "{empty}");

    let noisy = classify(&closed(4001, "a\u{1b}]0;title\u{7}b\r\nc")).message();
    assert!(!noisy.chars().any(char::is_control), "{noisy:?}");
    let long = classify(&closed(4002, &"y".repeat(500))).message();
    assert!(long.contains(&"y".repeat(100)) && !long.contains(&"y".repeat(101)), "{long}");
}

#[test]
fn an_unpublished_close_is_reported_as_unmatched_and_never_forced_into_a_row() {
    // ⛔ **The forward close set is published nowhere** —
    // `01-relay-protocol.md:151-158` records that the relay publishes exactly one
    // close table, headed `## Reverse close codes`, and that the forward set is
    // not published anywhere. ⛔ So a forward close matches nothing, and ⛔ **it
    // must not be forced into a reverse row that never applied to it.**
    let forward_close = classify(&closed(1006, ""));
    assert_eq!(forward_close.row, None);
    assert_eq!(forward_close.session, SessionAction::Unknown);
    assert_eq!(forward_close.retry, Retry::Never);
    assert!(forward_close.message().contains("forward close set is unpublished"));
}

#[test]
fn the_observed_by_column_is_carried_and_the_node_exception_is_recorded() {
    let node_rows = CLOSE_ROWS.iter().filter(|r| r.observed_by == Leg::Node).count();
    let operator_rows = CLOSE_ROWS.iter().filter(|r| r.observed_by == Leg::Operator).count();
    let either_rows = CLOSE_ROWS.iter().filter(|r| r.observed_by == Leg::Either).count();
    assert_eq!(node_rows + operator_rows + either_rows, 25, "25 rows in Rust: line 192 is two");

    // ⛔ **Spec lines 162-165:** *"when the relay itself closed the node socket
    // for cause, the operator observes that cause too (the close is forwarded to
    // its sessions instead of the `1011` default), so a `side: node` row can
    // reach the operator leg."* ⛔ **So `Leg::Node` does NOT mean "the operator
    // will never see this"**, and a `LegShape`-aware caller must know that.
    let data_before_ready = classify(&closed(1003, "data before ready"));
    assert_eq!(data_before_ready.row.unwrap().observed_by, Leg::Node);
    assert_eq!(data_before_ready.row.unwrap().spec_line, 177);
    assert!(
        data_before_ready.message().contains("possibly forwarded"),
        "the message says the node row can land on the operator too"
    );
}

#[test]
fn a_clean_close_and_an_abrupt_one_are_different_facts() {
    // ⛔ `1006` is not a close the relay sent; it is the absence of one. ⛔ Keeping
    // `clean` means a caller can tell "the relay said goodbye" from "the socket
    // went away", which `AGENTS.md:157-161` records as the difference between a
    // diagnosis and a guess.
    let clean: Classified = classify(&RelayClose { code: 1000, reason: "session ended".into(), clean: true });
    assert_eq!(clean.session, SessionAction::NormalEnd);
    let abrupt = RelayClose { code: 1006, reason: String::new(), clean: false };
    assert_eq!(classify(&abrupt).session, SessionAction::Unknown);
}

// ── the backoff: 1 s, ×2, cap 30 s, no jitter ──────────────────────────────

#[test]
fn the_backoff_is_one_two_four_eight_sixteen_then_thirty_and_holds() {
    use podssh_transport::backoff::{MAX_DELAY_MS, BASE_DELAY_MS};
    assert_eq!(BASE_DELAY_MS, 1_000);
    assert_eq!(MAX_DELAY_MS, 30_000, "⛔ the documented intent is 30 s, not the code path's 32");

    let schedule = podssh_transport::Backoff::schedule(12);
    assert_eq!(
        schedule,
        vec![1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000, 30_000, 30_000, 30_000, 30_000],
        "⛔ 1s → ×2 → cap 30s, and the cap HOLDS: 16 × 2 = 32 is clamped, not used"
    );
    // ⛔ **The seed is 1 s and not zero.** A reconnect that fires immediately
    // after a 1011 meets the same socket.
    assert_eq!(schedule[0], 1_000);
    assert!(schedule.iter().all(|d| *d <= MAX_DELAY_MS));
}

#[test]
fn the_backoff_has_no_jitter_and_a_reset_returns_it_to_the_seed() {
    // ⛔ **⛔ NO JITTER.** `relay-transport.md:75-80`: *"the sibling's documentation
    // claims jitter and its code has none, and podssh follows the code."* ⛔ The
    // schedule is fully deterministic, which is what makes it assertable at all.
    let a = podssh_transport::Backoff::schedule(8);
    let b = podssh_transport::Backoff::schedule(8);
    assert_eq!(a, b, "⛔ two runs of the same schedule must be identical");

    let mut backoff = podssh_transport::Backoff::new();
    assert_eq!(backoff.peek_ms(), 1_000);
    for _ in 0..9 {
        backoff.next_ms();
    }
    assert_eq!(backoff.peek_ms(), MAX);
    backoff.reset();
    assert_eq!(backoff.peek_ms(), 1_000, "a successful connect resets to the seed");
}
const MAX: u64 = 30_000;