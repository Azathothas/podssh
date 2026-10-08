//! E15 — ⛔ **the plants `dns.md`'s `## Prove` block names**, each with the
//! control that proves it is not a guard that refuses everything.
//!
//! | plant | what it plants | control in the same test |
//! | --- | --- | --- |
//! | `literal_short_circuit` | the literal goes to a resolver | a name ⛔ **does** reach it, and is `System` — **that pair is `dns_props.rs`'s** |
//! | `hanging_system` | `FAIL` for a `getaddrinfo` that never returned | a lookup that returns immediately is `ok` |
//! | `nothing_resolves` | the chain guessing an address | ⛔ the message names every stage |
//! | `unparseable_doh` | an empty `Vec` returned as a resolution | the message names the endpoint |
//! | `truncated_doh` | a `TC` answer accepted | ⛔ `TC` is not an answer |
//! | `control_system_answers` | a chain that skips `System` and still answers | ⛔ `System: ok` |
//!
//! ⛔ **Every arm lives with its own control, and the two arms are selected by
//! `PODSSH_PLANT`**, ⛔ following `tests/plants.rs`:
//!
//! ```sh
//! PODSSH_PLANT=hanging_system cargo test -p podssh-transport --test dns_plants plant
//! cargo test -p podssh-transport --test dns_plants plant    # the control
//! ```
//!
//! ⛔ **`control_system_answers` is the one the entry says is ⛔ *"the one
//! ⛔ most likely to be quietly missing"*** ⛔ — ⛔ **a resolver that only ever
//! works by falling through has tested nothing about the common case.** ⛔ Its
//! defect arm is ⛔ **a chain that answers without `System` having answered**,
//! ⛔ **which passes every other assertion in this file.**
//!
//! ⛔ **The `Literal` short-circuit's two arms are `dns_props.rs`'s**, ⛔ and
//! ⛔ **that split is deliberate**: ⛔ the *defect* needs the plants ⛔ — ⛔ **and
//! ⛔ the control that a name DOES reach a resolver is what proves the counter
//! ⛔ in `Chain::asked` is not stuck at zero** ⛔ — ⛔ **a chain that never
//! ⛔ asked anybody would pass that test untouched.**
//!
//! ⛔ **The watchdog plant is `dns_watchdog.rs`.** ⛔ **It was
//! ⛔ here and pushed this file to 525 lines.** ⛔ **Its
//! ⛔ own plant and ⛔ both arms of that one test moved
//! ⛔ together**, ⛔ so ⛔ **the split never
//! ⛔ **separates a plant from its
//! ⛔ control** ⛔ — ⛔ **and that is the only thing the
//! ⛔ split was allowed to not do.**
//!
//! ⛔ **Every plant asserts something its control could not have asserted**, ⛔
//! ⛔ **because a control that shares its assertions proves nothing.**

use std::sync::Arc;
use std::time::Instant;

use podssh_transport::dns::{self, Chain, How, ResolveError, Sources, Stage, StageReport};

mod common;
use common::block_on;
use common::dns::{absent_hosts, budgets, endpoint, planted, Counting, Unreachable, BUDGET, RELAY};

// ── plant B — the chain guessing, and the message naming every stage ───────

#[test]
fn plant_nothing_resolving_fails_loudly_and_names_every_stage() {
    let chain = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("plants"),
        doh: Some(endpoint()),
        doh_transport: Some(Arc::new(Unreachable)),
        budgets: budgets(),
        ..Sources::default()
    });

    if planted("nothing_resolves") {
        // ⛔ **THE DEFECT: the chain guesses.** ⛔ A silent fallback to a hardcoded
        // address is indistinguishable from a working connection until the day it
        // is not ⛔ and E06's entry exists about exactly that ⛔
        // (`DROPSSH_DEFAULT_FORWARD "/connect/railway"`, gone).
        let answer = block_on(chain.resolve(RELAY, 443));
        assert!(
            answer.is_ok(),
            "⛔ the chain resolved {RELAY} with no resolver, no hosts entry and an unreachable              DoH endpoint. podssh ships no default relay path and must fail loudly instead"
        );
        panic!("the chain returned {answer:?} for a name nothing could resolve");
    }

    let started = Instant::now();
    let error = block_on(chain.resolve(RELAY, 443)).expect_err("nothing can resolve this name");
    let elapsed = started.elapsed();

    assert!(
        elapsed < BUDGET * 6,
        "the chain took {elapsed:?}; dns.md's plant requires it to fail in bounded time"
    );
    let message = error.to_string();
    assert!(message.contains(RELAY), "⛔ the message must name the host: {message}");
    for stage in ["System", "Hosts", "Doh"] {
        assert!(
            message.contains(stage),
            "⛔ the message must name the {stage} stage: {message}"
        );
    }
    assert!(
        message.contains("relay") && message.contains("address"),
        "⛔ and it must name the remedy that is always available: {message}"
    );
    assert!(
        !message.contains("104.21.39.2"),
        "⛔ a failure message must not carry a hardcoded relay address: {message}"
    );
}

/// ⛔ **A stage that did not run is not reported as `ok`,** ⛔ and ⛔
/// ⛔ **a stage that DID run and fail is not reported as `????` either.**
#[test]
fn a_stage_that_never_ran_is_not_reported_as_ok() {
    let chain = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("plants"),
        budgets: budgets(),
        ..Sources::default()
    });
    let reports = block_on(chain.doctor(RELAY, 443));

    // ⛔ **Every stage in `Stage::ALL` appears, every time.** ⛔ A doctor that
    // prints three lines on a host with six stages ⛔ **is a doctor that cannot be
    // read against a host with three.**
    assert_eq!(reports.len(), Stage::ALL.len());

    let by_stage = |s: Stage| -> StageReport {
        reports.iter().find(|r| r.stage == s).expect("every stage").clone()
    };
    let doh = by_stage(Stage::Doh);
    assert_eq!(doh.outcome.label(), "????", "⛔ no DoH endpoint is configured here");
    assert!(!doh.consulted);
    assert!(
        doh.line().starts_with("Doh: ???? not consulted"),
        "⛔ and the line says so: {}",
        doh.line()
    );

    // ⛔ **AND THE OTHER HALF, which is the half that cost a bug** ⛔ — ⛔
    // ⛔ **`System` ran and failed, ⛔ and it says `FAIL` with the
    // ⛔ errno, not `????`.** ⛔ **MEASURED 2026-10-02: the first
    // ⛔ `doctor` reported `System: ????` on a host whose `getaddrinfo`
    // ⛔ returned `EAI_NONAME`,** ⛔ and the test caught it. ⛔
    // ⛔ A `resolv.conf` that exists and a resolver that answers are
    // ⛔ different facts, ⛔ and ⛔ `System` ⛔ is the one that will be
    // ⛔ wrong first on a cage.
    let system = by_stage(Stage::System);
    assert_eq!(system.outcome.label(), "FAIL", "⛔ it RAN: {}", system.line());
    assert!(system.consulted);
    assert!(system.line().contains("errno="), "⛔ and it names the errno: {}", system.line());

    // ⛔ **`Literal` on a name is `????` and never `ok`.**
    assert_eq!(by_stage(Stage::Literal).outcome.label(), "????");

    // ⛔ **No line anywhere claims `ok` for a stage that did not answer.**
    for report in &reports {
        if report.outcome.label() == "ok" {
            assert!(report.consulted, "⛔ {} reported ok without being consulted", report.stage);
        }
    }
}

// ── plant C — DoH bodies that are not answers ──────────────────────────────

#[test]
fn plant_an_unparseable_doh_body_is_a_named_error_not_an_empty_answer() {
    let transport = dns::ScriptedTransport::new()
        .reply(RELAY, 200, "<html>this is a captive portal</html>")
        .reply("empty.example", 200, r#"{"Status":0}"#);
    let asked = Arc::new(transport);
    let chain = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("plants"),
        doh: Some(endpoint()),
        doh_transport: Some(asked.clone()),
        budgets: budgets(),
        ..Sources::default()
    });

    if planted("unparseable_doh") {
        // ⛔ **THE DEFECT: an empty `Vec<SocketAddr>` treated as a resolution.**
        // ⛔ `dns.md` names it: ⛔ *"not an empty `Vec<SocketAddr>` some caller
        // treats as success"*. ⛔ The caller would dial nothing and report success.
        let answer = block_on(chain.resolve(RELAY, 443));
        assert!(
            matches!(&answer, Ok(a) if a.addrs.is_empty()),
            "⛔ the chain returned an empty address list as a resolution: {answer:?}. An empty \
             answer is not a resolution, and `Answer::first` exists to refuse it"
        );
        // ⛔ And if it does refuse it, the error still has to name the endpoint.
        let refused = answer.err().expect("empty").to_string();
        assert!(!refused.contains("1.1.1.1"), "⛔ the error must name the endpoint: {refused}");
    }

    // ⛔ **THE CORRECT PATH — an unparseable body.**
    let error = block_on(chain.resolve(RELAY, 443)).expect_err("that body is not a DNS answer");
    assert!(
        matches!(error, ResolveError::Exhausted { .. }),
        "an exhausted chain, not a panic and not an empty answer: {error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("1.1.1.1"), "⛔ the error names the endpoint: {message}");
    assert!(
        message.contains("DNS"),
        "⛔ and it says what was expected: {message}"
    );

    // ⛔ **AN EMPTY ANSWER FOR A REAL NAME**, separately ⛔ — ⛔ **and a distinct
    // ⛔ error, because a real name with no records is a different fact from a
    // ⛔ broken endpoint.**
    let error = block_on(chain.resolve("empty.example", 443)).expect_err("no records at all");
    let message = error.to_string();
    assert!(message.contains("empty.example"), "⛔ it names the name: {message}");
    assert!(
        message.contains("empty answer is not a resolution"),
        "⛔ and it says an empty answer is not a resolution: {message}"
    );
    assert!(
        message.contains("1.1.1.1"),
        "⛔ and it names the endpoint: {message}"
    );

    // ⛔ **AND THE STAGE SENT A REAL QUESTION.** ⛔ **This is the arm that
    // ⛔ catches a base64url encoder that is subtly wrong**: ⛔ a wrong encoding
    // ⛔ produces a question nobody answers, ⛔ and the "empty answer"
    // ⛔ assertion above would then pass for the wrong reason.
    let asked = asked.asked();

    assert_eq!(
        asked.len(), 3,
        "⛔ two A queries (one per name) and ONE AAAA, because the unparseable body for          {RELAY} ends the lookup before its AAAA — an endpoint that is not a DNS endpoint          does not get asked twice: {asked:?}"
    );
    for line in &asked {
        assert!(line.starts_with("GET /dns-query?dns="), "⛔ the request line: {line}");
        let (name, kind) = dns::decode_question(line).expect("⛔ podssh must read its own question back");
        assert!(kind == "A" || kind == "AAAA");
        assert!(name == RELAY || name == "empty.example", "⛔ decoded {name:?} out of {line}");
    }
}

#[test]
fn plant_a_truncated_doh_answer_is_not_a_resolution() {
    let transport = dns::ScriptedTransport::new().reply(
        RELAY,
        200,
        r#"{"TC":true,"Status":0,"Answer":[{"name":"tcp-1.ssh.relay.ajam.dev","type":1,"data":"104.21.39.2"}]}"#,
    );
    let chain = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("plants"),
        doh: Some(endpoint()),
        doh_transport: Some(Arc::new(transport)),
        budgets: budgets(),
        ..Sources::default()
    });
    if planted("truncated_doh") {
        let answer = block_on(chain.resolve(RELAY, 443));
        assert!(answer.is_ok(), "⛔ a truncated answer is not a resolution: {answer:?}");
    }
    let error = block_on(chain.resolve(RELAY, 443)).expect_err("TC is not an answer");
    assert!(error.to_string().contains("truncated"), "{}", error);
}

// ── plant D — THE CONTROL: `ok` naming `System` ────────────────────────────

#[test]
fn plant_the_control_a_working_system_resolver_reports_ok_naming_system() {
    let system = Counting::answering();
    let chain = Chain::new(Sources {
        system: system.clone(),
        hosts: absent_hosts("plants"),
        budgets: budgets(),
        ..Sources::default()
    });

    // ⛔ A SECOND, UNUSED chain, and the reason it exists here rather than being
    // ⛔ the one below: ⛔ the first resolve through `chain` fills its cache, and
    // ⛔ a second resolve through the SAME chain is answered by `Cache`, which
    // ⛔ made the `System` row read `????`. ⛔ This one is never resolved through
    // ⛔ outside this arm, so its `System` row can be read with an empty cache.
    let defect_chain = Chain::new(Sources {
        system: system.clone(),
        hosts: absent_hosts("plants"),
        budgets: budgets(),
        ..Sources::default()
    });

    if planted("control_system_answers") {
        // ⛔ THE DEFECT: a chain that answers without `System` having answered.
        // ⛔ The hosts file cannot answer here ⛔ — it does not exist ⛔ — so the
        // ⛔ only way this arm can pass is if the chain stops at `Literal` or
        // ⛔ `Cache`, which is the shape of a resolver that skips the system
        // ⛔ stage. ⛔ This is the plant the entry says is ⛔ *"the one most
        // ⛔ likely to be quietly missing."*
        let answers = block_on(defect_chain.record(RELAY, 443)).expect("still resolves");
        let system = answers.iter().find(|r| r.stage == Stage::System).unwrap();
        assert_ne!(
            system.outcome.label(),
            "ok",
            "⛔ a resolver that answers `ok` for a name the system resolver could \
             resolve, without naming System, has tested nothing about the common case"
        );
    }

    let answer = block_on(chain.resolve(RELAY, 443)).expect("the system resolver answers");
    assert_eq!(answer.how, How::System, "the route that answered is reported");
    assert_eq!(answer.how.as_str(), "System", "and the word the doctor prints is `System`");
    assert_eq!(answer.how.stage(), Stage::System);
    assert_eq!(answer.addrs.len(), 1, "and a real address, not an empty Vec");
    assert_eq!(system.calls(), 1, "one system call, and no resolver was consulted twice");

    // ⛔ **THE CONTROL, ⛔ and it is the `Answer`:** ⛔ a correct resolver on a
    // ⛔ host with a working system resolver reports `ok` NAMING `System`. ⛔ One
    // ⛔ that only ever works by falling through to DoH has tested nothing about
    // ⛔ the common case.

    // ⛔ A FRESH chain, and the reason is written down because it cost an hour:
    // ⛔ the previous line resolved through the SAME chain, ⛔ which cached the
    // ⛔ answer, ⛔ so the doctor's own resolve was answered by the `Cache` stage
    // ⛔ and the `System` row read `???? not consulted`. ⛔ A green assertion
    // ⛔ about "System: ok" that depends on the cache being empty is a green
    // ⛔ assertion that stops testing the thing it names.
    let doctor_chain = Chain::new(Sources {
        system: Counting::answering(),
        hosts: absent_hosts("plants"),
        budgets: budgets(),
        ..Sources::default()
    });
    let records = block_on(doctor_chain.record(RELAY, 443)).expect("the doctor resolves for itself");
    let report = records.iter().find(|r| r.stage == Stage::System).expect("every stage");
    assert_eq!(report.outcome.label(), "ok", "⛔ System: ok");
    assert!(report.consulted);
    assert!(report.line().starts_with("System: ok"), "⛔ `{}`", report.line());

    // ⛔ And the stages after it did not run, so they are `????` and not `ok`:
    // ⛔ a chain that reported `Doh: ok` here without a single HTTP request would
    // ⛔ be reporting a stage it never exercised.
    for stage in [Stage::Hosts, Stage::Doh, Stage::Configured] {
        let report = records.iter().find(|r| r.stage == stage).unwrap();
        assert_eq!(
            report.outcome.label(),
            "????",
            "⛔ {stage} was never consulted and must not report ok: {}",
            report.line()
        );
    }
}
// ── the doctor's trace against an outcome that would misreport it ───────────

/// ⛔ **A stage that RAN and FAILED is named as `FAIL`, even when a later stage
/// answers.**
///
/// ⛔ This is the successful-resolve half of the same misreport the failure
/// path was fixed for: the report used to be reconstructed from the outcome
/// alone, so a resolve that succeeded attributed the answer to one stage and
/// said `???? not consulted` about every other — ⛔ **including `System`, which
/// had run and returned `EAI_NONAME`.** ⛔ `dns.md` forbids exactly that: a
/// stage the client DID exercise must not print `????`.
#[test]
fn a_stage_that_ran_and_failed_is_named_even_when_a_later_stage_answers() {
    let chain = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("plants"),
        configured: vec![
            (RELAY.to_string(), "203.0.113.7:443".parse().expect("a literal address")),
        ],
        budgets: budgets(),
        ..Sources::default()
    });

    let records = block_on(chain.record(RELAY, 443)).expect("the configured pair answers");
    let system = records.iter().find(|r| r.stage == Stage::System).expect("every stage");
    assert_eq!(system.outcome.label(), "FAIL", "⛔ `{}`", system.line());
    assert!(system.consulted, "⛔ a stage that ran is consulted: `{}`", system.line());

    let answered = records.iter().find(|r| r.stage == Stage::Configured).expect("every stage");
    assert_eq!(answered.outcome.label(), "ok", "⛔ `{}`", answered.line());

    // ⛔ And the doctor's own resolve must say the same, because it is a second
    // run and not a replay of this one.
    let reports = block_on(chain.doctor(RELAY, 443));
    assert_eq!(reports.len(), Stage::ALL.len(), "⛔ every stage appears");
    let system = reports.iter().find(|r| r.stage == Stage::System).expect("every stage");
    assert_eq!(system.outcome.label(), "FAIL", "⛔ `{}`", system.line());
    let answered = reports.iter().find(|r| r.stage == Stage::Configured).expect("every stage");
    assert_eq!(answered.outcome.label(), "ok", "⛔ `{}`", answered.line());
}
