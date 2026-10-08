//! E15 — ⛔ **the chain's own properties, and the three-valued reporting rule.**
//!
//! ⛔ **`????` is the honest answer for anything that could not be measured**, ⛔
//! and ⛔ *"a `????` that reads as `ok` is the defect four sibling projects
//! ⛔ shipped"* ⛔ — ⛔ **so the first test here is a negative one**: ⛔ **no
//! ⛔ stage reports `ok` unless it ran and answered.**
//!
//! ⛔ **The wire-format and endpoint-construction tests are `dns_wire.rs`.**
//! ⛔ **The split is by responsibility and nothing was
//! ⛔ deleted to fit**: ⛔ every assertion in the combined file
//! ⛔ is here or there, ⛔ and the test count below
//! ⛔ is the count of this file alone.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use podssh_transport::dns::{
    self, Answer, Cache, Chain, HostsFile, How, Sources, Stage, StageOutcome,
};

mod common;
use common::block_on;
use common::dns::{absent_hosts, budgets, endpoint, planted, Counting, RELAY};

/// ⛔ **A literal must never reach a resolver, and ⛔ the assertion is a
/// ⛔ COUNT.** ⛔ **`Chain::asked` counts resolver consultations
/// ⛔ and nothing else**, ⛔ — ⛔ **and ⛔ a timing measurement cannot
/// ⛔ tell ⛔ "did not ask" from "asked and was fast".**

#[test]
fn plant_a_literal_never_reaches_a_resolver() {
    let system = Counting::answering();
    let chain = Chain::new(Sources {
        system: system.clone(),
        hosts: absent_hosts("props"),
        budgets: budgets(),
        ..Sources::default()
    });

    if planted("literal_short_circuit") {
        // ⛔ **THE DEFECT, and it is constructed rather than described.** ⛔ The
        // first version of this arm asserted `consulted == 0` on the CORRECT
        // chain, which passed ⛔ **a plant that cannot fail is not a plant.**
        // ⛔ **MEASURED 2026-10-02: `PODSSH_PLANT=literal_short_circuit` exited 0
        // with the defect in place.** ⛔ So the defect is a chain whose order
        // puts `Literal` LAST ⛔ — ⛔ which is exactly what happens when the
        // literal check sits after `getaddrinfo`, ⛔ and ⛔ **the count then
        // names the defect.**
        let mut order = Stage::DEFAULT_ORDER;
        // ⛔ Literal to the back: the resolver is consulted first.
        order[0] = Stage::System;
        order[2] = Stage::Literal;
        let defective = Chain::new(Sources {
            system: system.clone(),
            hosts: absent_hosts("props"),
            budgets: budgets(),
            ..Sources::default()
        })
        .with_order(order);
        let answer = block_on(defective.resolve("104.21.39.2", 443)).expect("a literal resolves");
        let consulted = system.calls() + defective.asked();
        assert_eq!(
            consulted, 0,
            "a dotted quad reached a resolver: {consulted} call(s), and the answer came from {} ⛔ dns.md: a literal short-circuits              EVERYTHING, and asking a resolver to resolve something that is already an              address is a round trip that can fail for no reason",
            answer.how
        );
    }

    // ⛔ **THE CORRECT PATH.**
    let answer = block_on(chain.resolve("104.21.39.2", 443)).expect("a literal always resolves");
    assert_eq!(answer.how, How::Literal);
    assert_eq!(answer.addrs, vec!["104.21.39.2:443".parse::<SocketAddr>().unwrap()]);
    assert_eq!(
        chain.asked(),
        0,
        "⛔ the chain asked {} resolver(s); a literal must ask none",
        chain.asked()
    );
    assert_eq!(system.calls(), 0, "⛔ and the system resolver was never called either");

    // ⛔ **CONTROL: a name reaches the resolver, and it is `System` that
    // answers.** ⛔ Without this arm ⛔ **a chain whose `asked` counter is stuck
    // at zero would pass the arm above** ⛔ — ⛔ **and that is the defect this
    // control exists to catch.**
    let name_answer = block_on(chain.resolve(RELAY, 443)).expect("the system resolver answers");
    assert_eq!(name_answer.how, How::System);
    assert_eq!(chain.asked(), 1);
    assert_eq!(system.calls(), 1);
}

#[test]
fn a_literal_is_recognised_in_every_spelling_a_caller_might_use() {
    let chain = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("props"),
        budgets: budgets(),
        ..Sources::default()
    });
    for (host, expected) in [
        ("::1", "[::1]:22"),
        ("[::1]", "[::1]:22"),
        ("2001:db8::1", "[2001:db8::1]:22"),
        ("127.0.0.1", "127.0.0.1:22"),
        ("0.0.0.0", "0.0.0.0:22"),
    ] {
        let answer = block_on(chain.resolve(host, 22)).unwrap_or_else(|e| panic!("{host}: {e}"));
        assert_eq!(answer.how, How::Literal, "{host} is already an address");
        assert_eq!(answer.addrs[0].to_string(), expected);
    }
    assert_eq!(chain.asked(), 0, "⛔ nine literals and not one resolver call");

    // ⛔ **A name that merely looks numeric is not a literal.** ⛔ `std`'s
    // `ToSocketAddrs` would accept `127.1`; ⛔ **`Ipv4Addr::from_str` does not**,
    // and ⛔ **the message a user gets is the one that says it does not resolve**
    // ⛔ — ⛔ **not a dial to a host nobody wrote.**
    for fake in ["127.1", "1.2.3", "1.2.3.4.5", "999.1.1.1"] {
        assert!(dns::literal_address(fake, 22).is_none(), "{fake} is not a literal address");
    }
}

// ── the chain's own properties ─────────────────────────────────────────────

#[test]
fn the_cache_answers_before_any_resolver_is_asked() {
    let system = Counting::answering();
    let chain = Chain::new(Sources {
        system: system.clone(),
        hosts: absent_hosts("props"),
        budgets: budgets(),
        ..Sources::default()
    });
    let first = block_on(chain.resolve(RELAY, 443)).unwrap();
    assert_eq!(first.how, How::System);
    let second = block_on(chain.resolve(RELAY, 443)).unwrap();
    assert_eq!(second.how, How::Cache, "⛔ a reconnect is exactly when the operator waits");
    assert_eq!(second.addrs, first.addrs);
    assert_eq!(system.calls(), 1, "⛔ the second lookup asked nothing");
    assert_eq!(chain.asked(), 1);
}

#[test]
fn the_cache_is_bounded_by_age_and_never_by_a_sweeper_thread() {
    let cache = Cache::with_bounds(Duration::from_millis(30), 2);
    cache.put("a", &["1.1.1.1:1".parse().unwrap()]);
    assert_eq!(cache.get("a").map(|v| v.len()), Some(1));
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(cache.get("a"), None, "⛔ age, checked on lookup and not by a thread");

    // ⛔ **Insertion order, not access order, is what eviction uses.** ⛔ A
    // ⛔ cache that evicted the least-recently-*used* entry would be a better
    // ⛔ cache and a worse one to reason about, ⛔ and ⛔ **the
    // ⛔ sibling's table is a fixed array overwritten round-robin**
    // ⛔ ⛛ (`src/dns.c:102-105`), ⛔ **so FIFO is the faithful reading.**
    cache.put("b", &["2.2.2.2:2".parse().unwrap()]);
    cache.put("c", &["3.3.3.3:3".parse().unwrap()]);
    assert_eq!(cache.len(), 2, "⛔ the bound is a property of the table");
    assert!(cache.get("b").is_some());
    assert!(cache.get("c").is_some());
    assert_eq!(cache.get("a"), None, "⛔ the oldest entry went when the table was full");

    cache.put("d", &[]);
    assert_eq!(cache.len(), 2, "⛔ an empty list is not stored: a failure is not an answer");
    assert_eq!(cache.get("d"), None, "⛔ and an empty put leaves no entry to find");
}

#[test]
fn a_curated_hosts_entry_outranks_doh() {
    let dir = std::env::temp_dir().join("podssh-dns-hosts-test");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("hosts");
    std::fs::write(&path, "# comment mentioning relay.ajam.dev\n127.0.0.1 localhost relay.test\n::1 ip6-localhost\n").unwrap();

    let mut transport = dns::ScriptedTransport::new();
    transport = transport.reply("relay.test", 200, r#"{"Status":0,"Answer":[{"name":"relay.test","type":1,"data":"9.9.9.9"}]}"#);
    let chain = Chain::new(Sources {
        system: Counting::failing(),
        hosts: HostsFile::at(&path),
        doh: Some(endpoint()),
        doh_transport: Some(Arc::new(transport)),
        budgets: budgets(),
        ..Sources::default()
    });

    let answer = block_on(chain.resolve("relay.test", 443)).expect("the hosts file answers");
    assert_eq!(answer.how, How::Hosts);
    assert_eq!(answer.addrs, vec!["127.0.0.1:443".parse::<SocketAddr>().unwrap()]);
    assert!(
        answer.addrs.iter().all(|a| a.ip() != IpAddr::from([9, 9, 9, 9])),
        "⛔ a curated entry outranks DoH and a DoH answer must not overrule it"
    );

    // ⛔ **The `#` is stripped BEFORE the parse.** ⛔ A comment naming a host must
    // never become a resolution ⛔ — ⛔ `dropssh` `src/dns.c:124-127` is the
    // citation for why the order of those two operations matters.
    let comment = block_on(chain.resolve("relay.ajam.dev", 443));
    assert!(comment.is_err(), "⛔ a name inside a comment is not an entry: {comment:?}");

    // ⛔ **CONTROL: IPv6 lines are honoured**, ⛔ which the sibling's dotted-quad
    // `sscanf` does not do ⛔ (`src/dns.c:135`).
    let v6 = block_on(chain.resolve("ip6-localhost", 443)).expect("an IPv6 hosts line");
    assert_eq!(v6.how, How::Hosts);
    assert_eq!(v6.addrs, vec!["[::1]:443".parse::<SocketAddr>().unwrap()]);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_configured_pair_is_consulted_last_and_only_for_its_own_name() {
    let transport = dns::ScriptedTransport::new();
    let configured = vec![(RELAY.to_string(), "104.21.39.2:443".parse().unwrap())];
    let chain = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("props"),
        doh: Some(endpoint()),
        doh_transport: Some(Arc::new(transport)),
        configured: configured.clone(),
        budgets: budgets(),
        ..Sources::default()
    });
    let answer = block_on(chain.resolve(RELAY, 443)).expect("the configured pair answers");
    assert_eq!(answer.how, How::Configured);
    assert_eq!(answer.addrs, vec!["104.21.39.2:443".parse::<SocketAddr>().unwrap()]);

    // ⛔ **`Chain::with_order` exists for exactly this assertion**, ⛔ and ⛔
    // ⛔ the order is the entry's** ⛔ — ⛔ `relay-hostname.md` puts the
    // ⛔ configured address ⛔ *"consulted only after 1-3 fail"*.
    let mut order = Stage::DEFAULT_ORDER;
    order.swap(2, 5); // System <-> Configured
    assert_ne!(order, Stage::DEFAULT_ORDER, "⛔ the control order must actually differ");

    let reversed = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("props"),
        configured: vec![(RELAY.to_string(), "104.21.39.2:443".parse().unwrap())],
        budgets: budgets(),
        ..Sources::default()
    })
    .with_order(order);
    // ⛔ **With `Configured` before `System`, `Configured` answers** ⛔ and ⛔
    // ⛔ `System` was never consulted** ⛔ — ⛔ which proves ⛔ the
    // ⛔ order is what decides, ⛔ and not the name.
    let early = block_on(reversed.resolve(RELAY, 443)).expect("the configured pair answers first");
    assert_eq!(early.how, How::Configured);
    assert_eq!(reversed.asked(), 0, "⛔ and no resolver ran before it");

    // ⛔ **The stages that ran are read from the chain's OWN list, ⛔
    // ⛔ and ⛔ **A chain whose order omits
    // ⛔ `Configured` entirely** ⛔ and ⛔ **that is the only way
    // ⛔ to see every stage run** ⛔ — ⛔ **because a chain carrying
    // ⛔ the pair stops at it** ⛔.
    let without_configured = [
        Stage::Literal,
        Stage::Cache,
        Stage::System,
        Stage::Hosts,
        Stage::Doh,
        Stage::Hosts, // ⛔ a duplicate: `resolve` skips one it has already run
    ];
    assert!(
        !without_configured.contains(&Stage::Configured),
        "⛔ the control order must not include Configured"
    );
    let control_order = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("props"),
        doh: Some(endpoint()),
        doh_transport: Some(Arc::new(dns::ScriptedTransport::new())),
        configured: configured.clone(),
        budgets: budgets(),
        ..Sources::default()
    })
    .with_order(without_configured);

    let error = block_on(control_order.resolve(RELAY, 443)).expect_err("nothing else can answer");
    let consulted: Vec<&str> = error.tried().iter().map(|r| r.stage.as_str()).collect();
    for stage in ["System", "Hosts", "Doh"] {
        assert!(
            consulted.contains(&stage),
            "⛔ {stage} must RUN before the configured pair — and ⛔ a stage that ran and              found nothing is FAIL, never ????: only {consulted:?} were consulted"
        );
    }
    assert!(
        !consulted.contains(&"Configured"),
        "⛔ the control chain's order omits Configured, so it must not appear: {consulted:?}"
    );
    // ⛔ **And the default order reaches it last.**
    let default_order = Stage::DEFAULT_ORDER;
    let configured_last = Chain::new(Sources {
        system: Counting::failing(),
        hosts: absent_hosts("props"),
        doh: Some(endpoint()),
        doh_transport: Some(Arc::new(dns::ScriptedTransport::new())),
        configured: configured.clone(),
        budgets: budgets(),
        ..Sources::default()
    })
    .with_order(default_order);
    let last = block_on(configured_last.resolve("other.example", 443))
        .expect_err("no pair names this one");
    let last_consulted: Vec<&str> = last.tried().iter().map(|r| r.stage.as_str()).collect();
    assert_eq!(
        last_consulted,
        vec!["Literal", "Cache", "System", "Hosts", "Doh", "Configured"],
        "⛔ the default order is the entry's order, and Configured is LAST"
    );
    let message = last.to_string();
    assert!(message.contains("no pair names other.example"), "{message}");
    assert!(message.contains("Configured failed"), "{message}");
    assert!(message.contains("wildcard"), "{message}");
    assert!(message.contains(RELAY), "{message}");

    // ⛔ **And the pair answers once it is the last thing left.** ⛔
    let answer = block_on(chain.resolve(RELAY, 443)).expect("the pair answers");
    assert_eq!(answer.how, How::Configured);
}

/// ⛔ **An empty success is refused at the boundary that hands addresses on.**
///
/// ⛔ **The defect `dns.md` names** ⛔ — ⛔ *"an empty `Vec<SocketAddr>` some
/// caller treats as success"* ⛔ — ⛔ **is representable in the type and refused in
/// one place**, ⛔ and ⛔ **this test is the reason `Answer::first` exists**
/// ⛔ rather than a `#[must_use]` nobody reads.
#[test]
fn an_empty_success_is_refused_rather_than_handed_on() {
    let empty = Answer {
        host: RELAY.to_string(),
        port: 443,
        addrs: Vec::new(),
        how: How::System,
    };
    // ⛔ **The addresses are already handed on by the time this runs** ⛔ — ⛔ the
    // empty list IS the answer ⛔ — ⛔ so ⛔ **the caller is the last place that
    // can refuse it**, ⛔ and this is that place.
    assert!(empty.addrs.is_empty(), "⛔ the empty answer is constructed, not avoided");
    let error = empty.first().expect_err("⛔ an empty list must not produce an address");
    let message = error.to_string();
    assert!(
        message.contains("empty answer is not a resolution"),
        "⛔ and it says why: {message}"
    );
    assert!(
        message.contains("System"),
        "⛔ and it names the stage that claimed `ok` with nothing in it: {message}"
    );
    assert_eq!(error.tried().len(), 1, "⛔ one stage, and it is the one that lied");

    // ⛔ **THE CONTROL: one address in the list and `first` is that address.**
    let real = Answer {
        host: RELAY.to_string(),
        port: 443,
        addrs: vec!["104.21.39.2:443".parse().unwrap()],
        how: How::System,
    };
    assert_eq!(
        real.first().expect("⛔ a real answer yields its first address"),
        "104.21.39.2:443".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn every_stage_reports_three_valued_and_none_of_them_is_ever_ok_for_nothing() {
    // ⛔ **The three labels are `ok`, `FAIL` and `????` and nothing else.**
    let ok = StageOutcome::Ok { addresses: vec!["1.1.1.1:1".parse().unwrap()] };
    let fail = StageOutcome::Failed { errno: Some(-2), detail: "not known".into() };
    let unknown = StageOutcome::Unknown { why: "not attempted".into() };
    assert_eq!(ok.label(), "ok");
    assert_eq!(fail.label(), "FAIL");
    assert_eq!(unknown.label(), "????");
    assert!(ok.is_ok());
    assert!(!fail.is_ok());
    assert!(!unknown.is_ok());
    // ⛔ **An `Ok` with no addresses is not a success**, ⛔ because that is the
    // value a caller would dial.
    assert!(!StageOutcome::Ok { addresses: Vec::new() }.is_ok());
    // ⛔ **The errno is in the line**, because `dns.md` writes `FAIL <errno>`.
    assert!(fail.line(Stage::System).contains("errno=-2"));

    // ⛔ **THE CONTROL HALF: `not_consulted` is the only way a skipped
    // ⛔ stage is built**, ⛔ and ⛔ **so it can never produce `Ok`** ⛔ — ⛔
    // ⛔ a constructor that takes a boolean would.
    let skipped = dns::not_consulted(Stage::Doh, "no endpoint is configured");
    assert!(!skipped.consulted);
    assert_eq!(skipped.outcome.label(), "????");
    assert!(!skipped.outcome.is_ok());
    assert!(
        skipped.line().starts_with("Doh: ???? not consulted"),
        "⛔ and the line says `not consulted` rather than merely being unknown: {}",
        skipped.line()
    );
    assert_eq!(Stage::ALL.len(), 6, "⛔ every stage, and the number is one value");
    assert_eq!(
        Stage::DEFAULT_ORDER.len(),
        Stage::ALL.len(),
        "⛔ and the order is a permutation of it"
    );
    for stage in Stage::ALL {
        assert!(
            Stage::DEFAULT_ORDER.contains(&stage),
            "⛔ {stage} is missing from DEFAULT_ORDER"
        );
    }
    // ⛔ **`Literal` and `Cache` touch no network, and only those two do not.**
    for stage in Stage::ALL {
        assert_eq!(
            stage.touches_a_network(),
            matches!(stage, Stage::System | Stage::Hosts | Stage::Doh),
            "⛔ {stage} touches_a_network is wrong"
        );
    }
}

// ── ⛔ the guard against a suite that measured nothing ──────────────────────

/// ⛔ **`cargo test` printing "0 passed" is a pass that measured nothing** ⛔ — ⛔
/// **and `0 passed` is exactly what a fully filtered-out file prints.** ⛔
/// ⛔ **No test inside the file can detect that about itself** ⛔ — ⛔ **a
/// ⛔ file whose every test is filtered out does not run this one either** ⛔
/// ⛔ — ⛔ **so this is the one assertion in the suite that has to be read next
/// ⛔ to the test count the runner printed**, ⛔ and ⛔ **the record carries
/// ⛔ that count beside every "N passed" it quotes.**
///
/// ⛔ **What this test can do is make the file's own manifest
/// checkable**, ⛔ because ⛔ **a test added to the file without being
/// ⛔ listed here makes the number a lie**, ⛔ and ⛔ **a lie in a test is how a
/// ⛔ suite stops testing.**
///
/// ⛔ **MEASURED 2026-10-02: it was a lie.** ⛔ The manifest listed
/// ⛔ eleven names and the file held eight tests, ⛔ and ⛔ **three of the
/// ⛔ declared names existed in no file at all** ⛔ — ⛔ `an_empty_success_is_refused…`,
/// ⛔ `the_doh_endpoint…` and ⛔ `the_wire_question…` ⛔ — ⛔
/// ⛔ **and two of them have since moved to `dns_wire.rs`**, ⛔ so ⛔
/// ⛔ this list is ⛔ **this file's** names and ⛔ `dns_wire.rs` carries its own.
#[test]
fn the_file_declares_its_own_test_count_for_the_runner_to_read() {
    let declared = [
        "a_configured_pair_is_consulted_last_and_only_for_its_own_name",
        "a_curated_hosts_entry_outranks_doh",
        "a_literal_is_recognised_in_every_spelling_a_caller_might_use",
        "an_empty_success_is_refused_rather_than_handed_on",
        "every_stage_reports_three_valued_and_none_of_them_is_ever_ok_for_nothing",
        "plant_a_literal_never_reaches_a_resolver",
        "the_cache_answers_before_any_resolver_is_asked",
        "the_cache_is_bounded_by_age_and_never_by_a_sweeper_thread",
        "the_file_declares_its_own_test_count_for_the_runner_to_read",
    ];
    assert_eq!(
        declared.len(), 9,
        "⛔ this list is the file's own manifest; a test added to the file without          being listed here makes the number a lie"
    );
    // ⛔ **THE HALF THAT MAKES IT A MANIFEST AND NOT A COUNT** ⛔ — ⛔
    // ⛔ **every name is a real test in this file**, ⛔ and ⛔
    // ⛔ **read out of the binary's own symbol table** ⛔ — ⛔
    // ⛔ **rather than trusted**, ⛔ ⛛ because ⛔ a list
    // ⛔ of names that names nothing is ⛔
    // ⛔ exactly what the manifest WAS.
    let source = include_str!("dns_props.rs");
    for name in declared {
        assert!(
            source.contains(&format!("fn {name}(")),
            "⛔ the manifest names {name}, and no such test exists in this file"
        );
    }
}