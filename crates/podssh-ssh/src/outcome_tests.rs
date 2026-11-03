//! The tests of the records of a session (T-484): two sessions at once keep
//! their own facts, bytes, phase and server's words, and a task of a session
//! that runs apart writes the session's record through the one it took.

use super::*;
use crate::retry::{self, Phase};

/// Two sessions polled at once in one task, as the hosts of `podssh each`
/// are, each writing between the other's writes.
#[tokio::test]
async fn two_sessions_at_once_keep_their_own_records() {
    let a = scoped(async {
        retry::begin();
        status(3);
        failed("auth");
        tokio::task::yield_now().await;
        output(4, false);
        retry::reached(Phase::Requested);
        tokio::task::yield_now().await;
        (retry::phase(), take_broke())
    });
    let b = scoped(async {
        retry::begin();
        tokio::task::yield_now().await;
        status(0);
        failed("connect");
        here().broke("reset".into());
        output(5, true);
        tokio::task::yield_now().await;
        (retry::phase(), take_broke())
    });
    let (((a_phase, a_broke), a), ((b_phase, b_broke), b)) = tokio::join!(a, b);
    assert_eq!((a.facts.status, a.facts.failure, a.stdout, a.stderr), (Some(3), Some("auth"), 4, 0));
    assert_eq!((b.facts.status, b.facts.failure, b.stdout, b.stderr), (Some(0), Some("connect"), 0, 5));
    assert_eq!((a_phase, b_phase), (Phase::Requested, Phase::Handshake), "each its own phase");
    assert_eq!((a_broke, b_broke.as_deref()), (None, Some("reset")), "each its own words");
}

/// The SSH client's task runs apart, with no scope: the record that it
/// took where it was made is the session's.
#[tokio::test]
async fn a_task_apart_writes_the_record_that_it_took() {
    let (said, record) = scoped(async {
        let carried = here();
        tokio::spawn(async move { carried.said("bye (ByApplication)".into()) }).await.unwrap();
        relay_host("relay.example.org");
        take_said()
    })
    .await;
    assert_eq!(said.as_deref(), Some("bye (ByApplication)"));
    assert_eq!(record.facts.relay_host.as_deref(), Some("relay.example.org"));
}

/// A scope whose work was dropped, as at a deadline, still gives what the
/// work did.
#[tokio::test]
async fn a_scope_keeps_what_dropped_work_did() {
    let scope = Scope::new();
    let work = scope.run(async {
        status(7);
        std::future::pending::<()>().await;
    });
    let ended = tokio::time::timeout(std::time::Duration::from_millis(10), work).await;
    assert!(ended.is_err(), "the work never ends");
    assert_eq!(scope.record().facts.status, Some(7));
}
