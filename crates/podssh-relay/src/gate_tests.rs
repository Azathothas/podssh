//! The tests of the gates (T-637), on tokio's paused clock, with attempts
//! that count their dials: a wave that fails, a wait outside the deadline,
//! the epochs, the verdict of each error, the ladder, a lease dropped with
//! no verdict, and the line of a run whose every host is held.

use std::sync::atomic::{AtomicUsize, Ordering};

use podssh_ws::dial::DialError;

use super::*;
use crate::token::Origin;

/// The deadline of the attempts here, as an attempt's.
const DEADLINE: Duration = crate::open::HOST_DEADLINE;

fn relay(host: &str) -> Relay {
    Relay { host: host.into(), port: 443 }
}

/// A dial that the host refuses.
fn refused_dial() -> OpenError {
    let error = DialError::Connect { target: "a.example:443".into(), detail: "refused".into(), cut: None, kind: None };
    OpenError::Connect { error: ConnectError::Dial(error), origin: Origin::Minted }
}

fn refused(status: u16, body: &str) -> OpenError {
    OpenError::Connect { error: ConnectError::Refused { status, body: body.into() }, origin: Origin::Minted }
}

/// An attempt that counts its dial and fails after 100 ms.
async fn failing(dials: Arc<AtomicUsize>) -> Result<(), OpenError> {
    dials.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    Err(refused_dial())
}

/// A wave of 64 at once at a host that gave no verdict: at most eight dial,
/// the first failure closes the gate and the others of the wave move its
/// ladder no further; the rest, each with a next host, go on to it.
#[tokio::test(start_paused = true)]
async fn a_cold_wave_dials_at_most_eight_and_its_failures_move_the_ladder_once() {
    let (gates, a) = (Gates::default(), relay("a.example"));
    let dials = Arc::new(AtomicUsize::new(0));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let (gates, a, dials) = (gates.clone(), a.clone(), dials.clone());
        set.spawn(async move { guarded(&gates, &a, true, DEADLINE, failing(dials)).await });
    }
    let mut held = 0;
    while let Some(ended) = set.join_next().await {
        held += usize::from(matches!(ended.unwrap(), Err(OpenError::Held { left: Some(_) })));
    }
    assert_eq!(dials.load(Ordering::SeqCst), MOST_AT_ONCE);
    assert_eq!(held, 64 - MOST_AT_ONCE);
    let (wait, left, probing, epoch) = gates.held(&a).expect("closed");
    assert_eq!((wait, left, probing, epoch), (FIRST_WAIT, FIRST_WAIT, false, 1), "one wave moves the ladder once");
}

/// After a failure of one session, 64 at once dial the host once: those
/// with a next host are held at once with the wait left, and those with
/// none wait, one of them the probe, the others until their caller's own
/// limit; none reads the wait as a host that timed out.
#[tokio::test(start_paused = true)]
async fn sixty_four_attempts_at_a_failing_origin_dial_it_once_and_the_rest_go_on_or_wait() {
    let (gates, a) = (Gates::default(), relay("a.example"));
    let dials = Arc::new(AtomicUsize::new(0));
    let first = guarded(&gates, &a, false, DEADLINE, failing(dials.clone())).await;
    assert!(matches!(first, Err(OpenError::Connect { .. })), "{first:?}");
    let limit = Duration::from_millis(1500);
    let mut set = tokio::task::JoinSet::new();
    for i in 0..64 {
        let (gates, a, dials, successor) = (gates.clone(), a.clone(), dials.clone(), i % 2 == 0);
        set.spawn(async move {
            let t = Instant::now();
            let ended = tokio::time::timeout(limit, guarded(&gates, &a, successor, DEADLINE, failing(dials))).await;
            (successor, ended, t.elapsed())
        });
    }
    let (mut on, mut probed, mut waited) = (0, 0, 0);
    while let Some(joined) = set.join_next().await {
        match joined.unwrap() {
            (true, Ok(Err(OpenError::Held { left: Some(left) })), took) => {
                assert_eq!((left, took), (FIRST_WAIT, Duration::ZERO));
                on += 1;
            }
            (false, Ok(Err(OpenError::Connect { .. })), took) => {
                assert_eq!(took, FIRST_WAIT + Duration::from_millis(100), "the probe went after the wait");
                probed += 1;
            }
            (false, Err(_), took) => {
                assert_eq!(took, limit);
                waited += 1;
            }
            (successor, other, took) => panic!("{successor} {other:?} after {took:?}"),
        }
    }
    assert_eq!(dials.load(Ordering::SeqCst), 2, "the first failure, then one probe");
    assert_eq!((on, probed, waited), (32, 1, 31));
    let (wait, _, probing, epoch) = gates.held(&a).expect("closed");
    assert_eq!((wait, probing, epoch), (FIRST_WAIT * 2, false, 2), "the probe's failure doubled the wait");
}

/// A failure of an older epoch lengthens the wait from its own time and
/// moves no ladder; an answer of an older epoch leaves the gate closed; the
/// probe's answer opens it.
#[tokio::test(start_paused = true)]
async fn a_verdict_of_an_older_epoch_lengthens_the_wait_and_never_shortens_it() {
    let (gates, a) = (Gates::default(), relay("a.example"));
    let one = gates.admit(&a, false).await.unwrap();
    let two = gates.admit(&a, false).await.unwrap();
    let three = gates.admit(&a, false).await.unwrap();
    one.settle(Verdict::Failed(None));
    tokio::time::sleep(Duration::from_millis(500)).await;
    two.settle(Verdict::Failed(None));
    assert_eq!(gates.held(&a), Some((FIRST_WAIT, FIRST_WAIT, false, 1)), "lengthened to 1.5 s, the ladder as it was");
    three.settle(Verdict::Alive);
    assert!(gates.held(&a).is_some(), "an answer of the old wave shortens nothing");
    let t = Instant::now();
    let probe = tokio::time::timeout(Duration::from_secs(10), gates.admit(&a, false)).await.unwrap().unwrap();
    assert_eq!(t.elapsed(), FIRST_WAIT);
    assert!(probe.probe());
    probe.settle(Verdict::Alive);
    assert_eq!(gates.held(&a), None, "the probe's answer opens the gate");
}

/// The verdict of each end: a session and the relay's own refusals show
/// the host alive; a failure that the record keeps is one, with a mint's
/// Retry-After in seconds; an error of this side, or of each host, is none.
#[test]
fn each_end_has_its_verdict() {
    assert_eq!(verdict(&Ok(())), Verdict::Alive);
    assert_eq!(verdict::<()>(&Err(refused(403, "forward: x:25 not in the ALLOW list"))), Verdict::Alive);
    assert_eq!(verdict::<()>(&Err(refused(502, "relay: cannot reach x:22"))), Verdict::Alive);
    assert_eq!(verdict::<()>(&Err(OpenError::Token(TokenError::NotIssued))), Verdict::Alive);
    for host_s in [refused(503, "paused"), refused(429, "slow down"), OpenError::Deadline, refused_dial()] {
        assert_eq!(verdict::<()>(&Err(host_s)), Verdict::Failed(None));
    }
    let limited = |after: &str| OpenError::Token(TokenError::RateLimited { retry_after: Some(after.into()) });
    assert_eq!(verdict::<()>(&Err(limited("7"))), Verdict::Failed(Some(Duration::from_secs(7))));
    assert_eq!(verdict::<()>(&Err(limited("Wed, 21 Oct 2026 07:28:00 GMT"))), Verdict::Failed(None));
    let proxy_407 = ConnectError::Dial(DialError::ProxyRefused {
        proxy: "proxy:3128".into(),
        target: "a.example:443".into(),
        status: 407,
        reason: "Proxy Authentication Required".into(),
    });
    let mine = [
        OpenError::Offline,
        OpenError::Token(TokenError::BadEnvironment),
        OpenError::Held { left: None },
        OpenError::Connect { error: proxy_407, origin: Origin::Minted },
    ];
    for none in mine {
        assert_eq!(verdict::<()>(&Err(none)), Verdict::Neither);
    }
}

/// A policy's 403 and the target's 502 at the probe open the gate.
#[tokio::test(start_paused = true)]
async fn a_403_or_a_502_at_the_probe_opens_the_gate() {
    for answer in [403, 502] {
        let (gates, a) = (Gates::default(), relay("a.example"));
        gates.admit(&a, false).await.unwrap().settle(Verdict::Failed(None));
        let body = if answer == 403 { "forward: x:25 not in the ALLOW list" } else { "relay: cannot reach x:22" };
        let probed = guarded(&gates, &a, false, DEADLINE, async { Err::<(), _>(refused(answer, body)) }).await;
        assert!(matches!(probed, Err(OpenError::Connect { .. })), "{probed:?}");
        assert_eq!(gates.held(&a), None, "{answer} opens the gate");
    }
}

/// A lease dropped with no verdict frees its slot and says nothing of the
/// host; a probe dropped so lets the next attempt be the probe.
#[tokio::test(start_paused = true)]
async fn a_lease_dropped_with_no_verdict_frees_its_slot() {
    let (gates, a) = (Gates::default(), relay("a.example"));
    let mut leases = Vec::new();
    for _ in 0..MOST_AT_ONCE {
        leases.push(gates.admit(&a, true).await.unwrap());
    }
    let (next, a2) = (gates.clone(), a.clone());
    let ninth = tokio::spawn(async move {
        let t = Instant::now();
        next.admit(&a2, true).await.map(|lease| (t.elapsed(), lease.probe()))
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(leases.pop());
    let waited = tokio::time::timeout(Duration::from_secs(10), ninth).await.expect("the slot was freed").unwrap();
    assert_eq!(waited.unwrap(), (Duration::from_millis(300), false));
    assert_eq!(gates.held(&a), None, "a drop says nothing of the host");
    drop(leases);
    gates.admit(&a, false).await.unwrap().settle(Verdict::Failed(None));
    tokio::time::sleep(FIRST_WAIT).await;
    let probe = gates.admit(&a, false).await.unwrap();
    assert!(probe.probe());
    let (next, a2) = (gates.clone(), a.clone());
    let second = tokio::spawn(async move {
        let t = Instant::now();
        next.admit(&a2, false).await.map(|lease| (t.elapsed(), lease.probe()))
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(probe);
    let waited = tokio::time::timeout(Duration::from_secs(10), second).await.expect("the probe's place").unwrap();
    assert_eq!(waited.unwrap(), (Duration::from_millis(200), true));
}

/// A wait longer than the attempt's deadline: held at once with a next
/// host, with its line; with none, the wait, then the attempt within its own
/// deadline, which opens, and is never read as a timeout.
#[tokio::test(start_paused = true)]
async fn the_wait_never_counts_against_the_deadline() {
    let (gates, a) = (Gates::default(), relay("a.example"));
    gates.admit(&a, false).await.unwrap().settle(Verdict::Failed(Some(Duration::from_secs(60))));
    let held = guarded(&gates, &a, true, DEADLINE, async { Ok::<(), OpenError>(()) }).await.unwrap_err();
    assert_eq!(held.lines("x:22"), ["waits 60 s after a failure of this process; trying the next host"]);
    let t = Instant::now();
    let deadline = Duration::from_secs(2);
    let opens = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok::<(), OpenError>(())
    };
    let opened = guarded(&gates, &a, false, deadline, opens).await;
    assert!(opened.is_ok(), "the wait was read as a timeout: {opened:?}");
    assert_eq!(t.elapsed(), Duration::from_secs(61));
    assert_eq!(gates.held(&a), None, "the probe's session opened the gate");
}

/// Each failed probe doubles the wait up to the longest; a Retry-After
/// holds the gate up to its own bound, and one of 0 shortens nothing.
#[tokio::test(start_paused = true)]
async fn the_ladder_doubles_up_to_its_longest_and_a_retry_after_lengthens_it() {
    let (gates, a) = (Gates::default(), relay("a.example"));
    let mut waits = Vec::new();
    for _ in 0..8 {
        let lease = tokio::time::timeout(Duration::from_secs(60), gates.admit(&a, false)).await.unwrap().unwrap();
        lease.settle(Verdict::Failed(None));
        waits.push(gates.held(&a).unwrap().0.as_secs());
    }
    assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30, 30]);
    let b = relay("b.example");
    gates.admit(&b, false).await.unwrap().settle(Verdict::Failed(Some(Duration::from_secs(7200))));
    assert_eq!(gates.held(&b).unwrap().1, RETRY_AFTER_MOST);
    let c = relay("c.example");
    gates.admit(&c, false).await.unwrap().settle(Verdict::Failed(Some(Duration::ZERO)));
    assert_eq!(gates.held(&c).unwrap().1, FIRST_WAIT);
}

/// The line of a run whose every host is held names its last; a host of
/// another case is the same origin, and another port another one.
#[tokio::test(start_paused = true)]
async fn the_line_of_a_run_whose_every_host_is_held_names_the_last() {
    let gates = Gates::default();
    let (a, b) = (relay("A.example"), relay("b.example"));
    let list = [a.clone(), b.clone()];
    assert_eq!(gates.all_held(&list), None);
    gates.admit(&a, false).await.unwrap().settle(Verdict::Failed(None));
    assert_eq!(gates.all_held(&list), None, "b is open");
    gates.admit(&b, false).await.unwrap().settle(Verdict::Failed(Some(Duration::from_secs(5))));
    let line = "b.example: waits 5 s after a failure of this process";
    assert_eq!(gates.all_held(&list).as_deref(), Some(line));
    assert!(gates.held(&relay("a.EXAMPLE")).is_some(), "one origin in any case");
    assert!(gates.held(&Relay { host: "a.example".into(), port: 8443 }).is_none(), "another port");
}
