//! The resume deadline that a far end sets (T-306), on tokio's paused clock.
//! A far end that keeps a lost session 3 h names that in its `GREETING`; a
//! client that comes back 2 h after a loss resumes the session, and one whose
//! clock stood still while the far end's ran 4 h, as on a host that slept,
//! is refused, and says that the far end forgot the session and how long it
//! was away by the wall clock. A client's own deadline only shortens the far
//! end's.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::Instant;

use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{deadline, far, Ask, End, Ended, OsEntropy, Role, Settings};

const PIPE: usize = 256 * 1024;
const HOUR: Duration = Duration::from_secs(3600);

/// A link through a stand-in relay host, both ways until `cut` is told; then
/// both ends are dropped with no word, as when the client's host loses its
/// network.
fn relayed() -> (DuplexStream, DuplexStream, Arc<Notify>) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    let cut = Arc::new(Notify::new());
    let cutting = cut.clone();
    tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        tokio::select! {
            _ = tokio::io::copy(&mut cr, &mut fw) => {}
            _ = tokio::io::copy(&mut fr, &mut cw) => {}
            () = cutting.notified() => {}
        }
    });
    (client, far, cut)
}

/// A far end that keeps a lost session `kept`, as `podssh node
/// --resume-deadline` does: its settings name the deadline, its keeper keeps
/// the session as long, and each 10 s it forgets each session whose deadline
/// passed. A new session's target goes to `targets`.
fn far_end(
    kept: Duration,
    mut links: mpsc::UnboundedReceiver<DuplexStream>,
    targets: mpsc::UnboundedSender<DuplexStream>,
) -> Arc<Keeper<DuplexStream>> {
    let settings = Settings { resume_deadline: kept, ..Settings::default() };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = keeper.clone();
    tokio::spawn(async move {
        while let Some(link) = links.recv().await {
            let (keeper, targets) = (serving.clone(), targets.clone());
            tokio::spawn(async move {
                let Ok(accepted) = far::accept(link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy).await
                else {
                    return;
                };
                if accepted.established().resumed {
                    let _ = keeper.run_resumed(accepted).await;
                } else {
                    let (target, app) = tokio::io::duplex(PIPE);
                    let _ = targets.send(app);
                    keeper.run_new(accepted, target).await;
                }
            });
        }
    });
    // The sweep of a node (`reverse::layered`), each 10 s.
    let sweeping = keeper.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            sweeping.expire().await;
        }
    });
    keeper
}

/// The notes of a session, for the test to read.
fn noted() -> (Arc<Mutex<Vec<Note>>>, impl FnMut(Note) + Send + 'static) {
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let kept = notes.clone();
    (notes, move |n: Note| kept.lock().unwrap().push(n))
}

/// `bytes` from `from`, which must come within `limit`.
async fn carried<R: tokio::io::AsyncRead + Unpin>(from: &mut R, len: usize, limit: Duration) -> Vec<u8> {
    let mut got = vec![0u8; len];
    tokio::time::timeout(limit, from.read_exact(&mut got)).await.expect("the bytes came in time").unwrap();
    got
}

#[tokio::test(start_paused = true)]
async fn a_far_end_that_keeps_3_h_lets_its_client_resume_after_2_h() {
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    let _keeper = far_end(3 * HOUR, links_rx, targets_tx);
    let (client_link, far_link, cut) = relayed();
    links_tx.send(far_link).unwrap();
    // A client with the defaults: it learns the far end's deadline.
    let client = client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy).await.unwrap();
    let told = client.established().and_then(|e| e.peer_deadline);
    assert_eq!(told, Some(3 * HOUR), "the far end names its deadline");
    let connect = move |_: &Ended| {
        let links_tx = links_tx.clone();
        async move {
            // The client's host comes back 2 h after the loss.
            tokio::time::sleep(2 * HOUR).await;
            let (client_link, far_link, _cut) = relayed();
            links_tx.send(far_link).unwrap();
            Next::Link(client_link)
        }
    };
    let (notes, note) = noted();
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });

    let target = targets_rx.recv().await.unwrap();
    let (mut target_r, mut target_w) = tokio::io::split(target);
    let (mut app_r, mut app_w) = tokio::io::split(app);
    app_w.write_all(b"before").await.unwrap();
    assert_eq!(carried(&mut target_r, 6, Duration::from_secs(30)).await, b"before");
    let lost_at = Instant::now();
    cut.notify_one();

    // After the resume, the session goes on, each way.
    app_w.write_all(b"after").await.unwrap();
    assert_eq!(carried(&mut target_r, 5, 3 * HOUR).await, b"after");
    target_w.write_all(b"back").await.unwrap();
    assert_eq!(carried(&mut app_r, 4, Duration::from_secs(30)).await, b"back");
    assert!(lost_at.elapsed() >= 2 * HOUR, "the client came back after {:?}", lost_at.elapsed());
    {
        let notes = notes.lock().unwrap();
        let resumed = notes.iter().any(|n| matches!(n, Note::Resumed { after, .. } if *after >= 2 * HOUR));
        assert!(resumed, "{notes:?}");
    }

    // The application ends its bytes: the session ends plainly.
    drop((app_r, app_w));
    let outcome = tokio::time::timeout(Duration::from_secs(60), session).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd | End::Closed(_))),
        "{outcome:?}"
    );
}

/// The wall clock of the client of the next test: a fixed time, and the
/// time that the test says passed while the host slept.
static SLEPT: AtomicU64 = AtomicU64::new(0);

fn wall() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000 + SLEPT.load(Ordering::SeqCst))
}

#[tokio::test(start_paused = true)]
async fn a_client_whose_clock_stood_still_is_refused_and_says_how_long_it_was_away() {
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    let keeper = far_end(3 * HOUR, links_rx, targets_tx);
    let (client_link, far_link, cut) = relayed();
    links_tx.send(far_link).unwrap();
    let settings = Settings { wall_clock: wall, ..Settings::default() };
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    // The new link comes only once the test opens the gate.
    let (gate_tx, gate_rx) = oneshot::channel::<()>();
    let gate = Arc::new(tokio::sync::Mutex::new(Some(gate_rx)));
    let connect = move |_: &Ended| {
        let (gate, links_tx) = (gate.clone(), links_tx.clone());
        async move {
            if let Some(rx) = gate.lock().await.take() {
                let _ = rx.await;
            }
            let (client_link, far_link, _cut) = relayed();
            links_tx.send(far_link).unwrap();
            Next::Link(client_link)
        }
    };
    let (_notes, note) = noted();
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });
    let target = targets_rx.recv().await.unwrap();
    let (mut target_r, _target_w) = tokio::io::split(target);
    let (_app_r, mut app_w) = tokio::io::split(app);
    app_w.write_all(b"before").await.unwrap();
    assert_eq!(carried(&mut target_r, 6, Duration::from_secs(30)).await, b"before");
    cut.notify_one();

    // The host sleeps: the far end's clock runs 4 h, the client's stands
    // still, and the far end forgets the session once it has seen the loss.
    let mut forgotten = 0;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        forgotten += keeper.expire_at(Instant::now() + 4 * HOUR).await;
        if forgotten > 0 {
            break;
        }
    }
    assert_eq!(forgotten, 1, "the far end forgot the session");
    SLEPT.fetch_add(4 * 3600, Ordering::SeqCst);
    gate_tx.send(()).unwrap();

    let outcome = tokio::time::timeout(Duration::from_secs(120), session).await.unwrap().unwrap();
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    let End::GaveUp(reason) = &ended.end else { panic!("{ended:?}") };
    assert!(reason.contains("did not resume") && reason.contains("no such session"), "{reason}");
    assert!(reason.contains("the far end forgot the session: it keeps one 3 h after a loss"), "{reason}");
    assert!(reason.contains("this side was away for 4 h by the wall clock"), "{reason}");
}

/// A client whose user set 1 h waits 1 h, though the far end keeps 3 h.
#[tokio::test(start_paused = true)]
async fn a_client_deadline_shortens_the_far_ends() {
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    let _keeper = far_end(3 * HOUR, links_rx, targets_tx);
    let (client_link, far_link, cut) = relayed();
    links_tx.send(far_link).unwrap();
    let settings = Settings { client_deadline: Some(HOUR), ..Settings::default() };
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let connect = |_: &Ended| async { Next::<DuplexStream>::Retry("the relay host is down".into()) };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, |_| {}, &mut OsEntropy).await });
    let target = targets_rx.recv().await.unwrap();
    let (mut target_r, _target_w) = tokio::io::split(target);
    let (_app_r, mut app_w) = tokio::io::split(app);
    app_w.write_all(b"before").await.unwrap();
    assert_eq!(carried(&mut target_r, 6, Duration::from_secs(30)).await, b"before");
    let lost_at = Instant::now();
    cut.notify_one();

    let outcome = tokio::time::timeout(3 * HOUR, session).await.unwrap().unwrap();
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    let End::GaveUp(reason) = &ended.end else { panic!("{ended:?}") };
    assert!(reason.contains("no new link within 3600 s"), "{reason}");
    assert!(lost_at.elapsed() <= HOUR + Duration::from_secs(60), "{:?}", lost_at.elapsed());
}

/// The name that carries the deadline, and the client's wait from it.
#[test]
fn the_deadline_rides_in_a_feature_name() {
    let names = |list: &[&str]| list.iter().map(|n| n.to_string()).collect::<Vec<_>>();
    assert_eq!(deadline::name(3 * HOUR), "deadline.10800");
    assert_eq!(deadline::of(&names(&["replay.v1", "deadline.10800"])), Some(3 * HOUR));
    // None, or a name that is not a number of seconds: the side keeps 10 min.
    for list in [&[][..], &["deadline."][..], &["deadline.x"][..], &["deadline.0"][..], &["deadline.1h"][..]] {
        assert_eq!(deadline::of(&names(list)), None, "{list:?}");
    }
    // A far end that names more than a pair's life is held to it.
    assert_eq!(deadline::of(&names(&["deadline.99999999999999999999999"])), Some(deadline::LONGEST));
    // The far end's names keep their features, then the deadline.
    let settings = Settings { resume_deadline: 3 * HOUR, ..Settings::default() };
    assert_eq!(deadline::offered(&settings), names(&["replay.v1", "heartbeat.v1", "move.v1", "deadline.10800"]));
    // The client's own deadline only shortens.
    let own = |d: Option<Duration>| Settings { client_deadline: d, ..Settings::default() };
    assert_eq!(deadline::client_wait(&own(None), Some(3 * HOUR)), 3 * HOUR);
    assert_eq!(deadline::client_wait(&own(Some(HOUR)), Some(3 * HOUR)), HOUR);
    assert_eq!(deadline::client_wait(&own(Some(5 * HOUR)), Some(3 * HOUR)), 3 * HOUR);
    assert_eq!(deadline::client_wait(&own(None), None), Duration::from_secs(600));
    assert_eq!(deadline::span(Duration::from_secs(45)), "45 s");
    assert_eq!(deadline::span(Duration::from_secs(600)), "10 min");
    assert_eq!(deadline::span(3 * HOUR + Duration::from_secs(300)), "3 h 5 min");
}
