//! E15 — ⛔ **the watchdog plant, and its two arms together.**
//!
//! ⛔ **This file was `dns_plants.rs`, and it was the 500-line limit that
//! ⛔ moved it here.** ⛔ **The move was by responsibility and not by
//! ⛔ deleting anything**, ⛔ and ⛔ **the plant and its control
//! ⛔ are still in one test function** ⛔ — ⛔ **which is the one thing
//! ⛔ the split was not allowed to do**: ⛔ a plant whose control
//! ⛔ lives in another file is a plant with no control. ⛔
//!
//! ⛔ **The defect this plant plants:** a `System` stage that reports `FAIL`
//! for a `getaddrinfo` that never returned.
//!
//! ⛔ **It is the exact mistake `dns.md`'s `## Premise` warns about, and
//! ⛔ the correction is recorded in `dns.md` itself:** ⛔ *"a `getaddrinfo`
//! ⛔ that has not returned is `????`, because the call is still inside
//! ⛔ libc"* ⛔ — ⛔ **and `????` exists because it
//! ⛔ does.** ⛔ A stage that claims to know
//! ⛔ what libc is doing ⛔ is ⛔ claiming ⛔
//! ⛔ a fact it cannot have.
//!
//! ⛔ **A hanging `getaddrinfo` cannot be produced on demand on a machine whose
//! ⛔ resolver works**, ⛔ **so `HangForever` is the honest double**: ⛔ a
//! ⛔ loop that never returns, ⛔ **which is the shape
//! ⛔ of a host whose `resolv.conf` names a nameserver the egress
//! ⛔ refuses** ⛔
//! ⛔ and ⛔ **it is the only way to test the
//! ⛔ watchdog on every run instead of only on a host that happens to hang.**

use std::sync::Arc;
use std::time::Instant;

use podssh_transport::dns::{Chain, ResolveError, Sources, SystemResult};

mod common;
use common::block_on;
use common::dns::{absent_hosts, budgets, planted, system_stage, Counting, HangForever, BUDGET};

#[test]
fn plant_the_watchdog_bounds_a_getaddrinfo_that_never_returns() {
    let started = Instant::now();
    let result = system_stage(Arc::new(HangForever), "internal-name.invalid", 22);
    let elapsed = started.elapsed();

    if planted("hanging_system") {
        // ⛔ **THE DEFECT: a stage that reports `FAIL` for a call that
        // ⛔ never returned**, ⛔ **which is claiming to know what libc
        // ⛔ is doing** ⛔
        let outcome = result.outcome();
        assert!(
            matches!(outcome, podssh_transport::dns::StageOutcome::Failed { .. }),
            "the system stage reported {outcome:?} for a getaddrinfo that never returned.              ⛔ dns.md's plant: the stage must report a bound verdict after its watchdog fires              ⛔ — ⛔ and the three-valued rule says a call that did not answer is `????`,              because a thread already inside libc cannot be cancelled."
        );
    }

    // ⛔ THE CORRECT PATH: `????`, inside a budget far below any real
    // ⛔ `getaddrinfo` ⛔ so the bound is measured on every run and not only on a
    // ⛔ host that happens to hang.
    assert_eq!(
        result.outcome().label(),
        "????",
        "⛔ a call that did not answer is `????` and never `FAIL`"
    );
    assert!(
        elapsed >= BUDGET,
        "⛔ and it returned in {elapsed:?}, under a {BUDGET:?} budget: the bound was not          exercised, so this test measured nothing"
    );
    assert!(
        elapsed < BUDGET * 3,
        "⛔ but the stage took {elapsed:?}, past three budgets of {BUDGET:?} — ⛔ the          watchdog is not cutting the call off"
    );

    // ⛔ AND THE CHAIN CONTINUES PAST IT, because ⛔ `dns.md`'s plant requires
    // ⛔ it: ⛔ *"the chain must continue to /etc/hosts and then
    // ⛔ DoH"* ⛔
    let chain = Chain::new(Sources {
        system: Arc::new(HangForever),
        hosts: absent_hosts("watchdog"),
        budgets: budgets(),
        ..Sources::default()
    });
    let error = block_on(chain.resolve("internal-name.invalid", 22)).expect_err("nothing resolves");
    assert_eq!(error.tried().len(), 6, "⛔ every stage is accounted for");
    assert!(
        matches!(error, ResolveError::Watchdog { .. }),
        "⛔ and the error is the WATCHDOG variant, not a plain exhaustion: {error:?}"
    );
    assert!(
        error.to_string().contains("getaddrinfo"),
        "⛔ and it names libc: {error}"
    );

    // ⛔ THE CONTROL: a lookup that returns immediately is `ok`, and is not
    // ⛔ measured against the budget at all.
    let quick = system_stage(Counting::answering(), "tcp-1.ssh.relay.ajam.dev", 443);
    assert!(matches!(quick, SystemResult::Answered(ref a) if !a.is_empty()));
    assert_eq!(quick.outcome().label(), "ok");
}