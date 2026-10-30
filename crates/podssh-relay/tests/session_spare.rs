//! A spare link beside a silent one (T-305), on tokio's paused clock. A
//! stand-in relay host stops carrying the bytes of a link, with no word to
//! either end, as when the client's address changes: the client opens a
//! spare link 3 s after its bytes went unanswered, and the spare's resume
//! takes the session in seconds, where the heartbeat alone finds the link
//! dead after 30 s (the control, with no spare link). A link that stalls
//! and speaks again before the spare greets keeps the session, and the
//! spare closes before its handshake. A spare that greets and then fails in
//! its handshake gives way to the next link, and the loss is said once.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::pump::DEAD_AFTER;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{far, Ask, End, Ended, OsEntropy, Role, Settings};

const PIPE: usize = 256 * 1024;
const LIMIT: Duration = Duration::from_secs(120);

/// Copy `from` into `to`, holding each piece while `stalled` is set.
async fn carry<R, W>(mut from: R, mut to: W, stalled: Arc<AtomicBool>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        while stalled.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

/// A link through a stand-in relay host that holds each byte both ways
/// while its flag is set, and never closes.
fn relayed(stalled: bool) -> (DuplexStream, DuplexStream, Arc<AtomicBool>) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    let flag = Arc::new(AtomicBool::new(stalled));
    let (cr, cw) = tokio::io::split(relay_client);
    let (fr, fw) = tokio::io::split(relay_far);
    tokio::spawn(carry(cr, fw, flag.clone()));
    tokio::spawn(carry(fr, cw, flag.clone()));
    (client, far, flag)
}

/// A link that carries the far end's bytes, its `GREETING` among them, and
/// ends both ways at this side's first bytes: a spare that greets and fails
/// in its handshake.
fn greets_then_breaks() -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    let (mut cr, mut cw) = tokio::io::split(relay_client);
    let (mut fr, _fw) = tokio::io::split(relay_far);
    tokio::spawn(async move {
        let (mut buf, mut first) = (vec![0u8; 16 * 1024], [0u8; 1]);
        loop {
            tokio::select! {
                n = fr.read(&mut buf) => match n {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if cw.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                },
                // This side's `HELLO`: each half drops, and the link ends.
                _ = cr.read(&mut first) => return,
            }
        }
    });
    (client, far)
}

/// A far end that keeps its sessions, as a node does; a new session's
/// target goes to `targets`.
fn far_end(mut links: mpsc::UnboundedReceiver<DuplexStream>, targets: mpsc::UnboundedSender<DuplexStream>) {
    let keeper: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(600)));
    let settings = Settings::default();
    tokio::spawn(async move {
        while let Some(link) = links.recv().await {
            let (keeper, targets) = (keeper.clone(), targets.clone());
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
}

/// `len` bytes from `from`, within the limit.
async fn carried<R: AsyncRead + Unpin>(from: &mut R, len: usize) -> Vec<u8> {
    let mut got = vec![0u8; len];
    tokio::time::timeout(LIMIT, from.read_exact(&mut got)).await.expect("the bytes came in time").unwrap();
    got
}

/// A session whose first link stalls once `before` has passed, and whose
/// new links are stalled as `spare_stalled` says, the first of them broken
/// in its handshake when `first_breaks`; `recover` lets the first link go
/// on after that long. The time from the stall to the bytes that waited in
/// it, and the session's notes.
async fn stall(
    spares: bool,
    spare_stalled: bool,
    recover: Option<Duration>,
    first_breaks: bool,
) -> (Duration, Vec<Note>) {
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    far_end(links_rx, targets_tx);
    let (client_link, far_link, first) = relayed(false);
    links_tx.send(far_link).unwrap();
    let settings = Settings { spare_links: spares, ..Settings::default() };
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let opened = Arc::new(AtomicUsize::new(0));
    let connect = move |_: &Ended| {
        let links_tx = links_tx.clone();
        let broken = first_breaks && opened.fetch_add(1, Ordering::SeqCst) == 0;
        async move {
            let (client_link, far_link) = if broken {
                greets_then_breaks()
            } else {
                let (client_link, far_link, _flag) = relayed(spare_stalled);
                (client_link, far_link)
            };
            links_tx.send(far_link).unwrap();
            Next::Link(client_link)
        }
    };
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let note = {
        let notes = notes.clone();
        move |n: Note| notes.lock().unwrap().push(n)
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });
    let target = targets_rx.recv().await.unwrap();
    let (mut target_r, mut target_w) = tokio::io::split(target);
    let (mut app_r, mut app_w) = tokio::io::split(app);
    app_w.write_all(b"before").await.unwrap();
    assert_eq!(carried(&mut target_r, 6).await, b"before");

    // The relay host stops carrying the first link; bytes wait in it.
    first.store(true, Ordering::SeqCst);
    let stalled = Instant::now();
    if let Some(after) = recover {
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            first.store(false, Ordering::SeqCst);
        });
    }
    app_w.write_all(b"after").await.unwrap();
    assert_eq!(carried(&mut target_r, 5).await, b"after");
    let took = stalled.elapsed();
    // The session goes on, each way.
    target_w.write_all(b"back").await.unwrap();
    assert_eq!(carried(&mut app_r, 4).await, b"back");
    drop((app_r, app_w));
    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd | End::Closed(_))),
        "{outcome:?}"
    );
    let notes = notes.lock().unwrap().clone();
    (took, notes)
}

#[tokio::test(start_paused = true)]
async fn a_spare_link_beside_a_silent_one_resumes_the_session_in_seconds() {
    let (took, notes) = stall(true, false, None, false).await;
    assert!(took < Duration::from_secs(10), "the bytes came {took:?} after the stall: {notes:?}");
    assert!(notes.iter().any(|n| matches!(n, Note::Spare { .. })), "{notes:?}");
    let lost = notes.iter().filter(|n| matches!(n, Note::Lost { why } if why.contains("a spare link answered")));
    assert_eq!(lost.count(), 1, "{notes:?}");
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "{notes:?}");
}

#[tokio::test(start_paused = true)]
async fn a_link_that_speaks_again_first_keeps_the_session_and_the_spare_closes() {
    // The spare's far end never greets; the first link goes on after 5 s.
    let (took, notes) = stall(true, true, Some(Duration::from_secs(5)), false).await;
    assert!(took >= Duration::from_secs(5), "{took:?}");
    assert!(!notes.iter().any(|n| matches!(n, Note::Lost { .. })), "no loss: {notes:?}");
    let closed = notes.iter().any(|n| matches!(n, Note::SpareClosed { why } if why == "the link spoke again"));
    assert!(closed, "{notes:?}");
}

/// The control: with no spare link, the heartbeat finds the silent link
/// dead after 30 s, and only then does a resume carry the session on.
#[tokio::test(start_paused = true)]
async fn with_no_spare_link_the_session_waits_for_the_heartbeat() {
    let (took, notes) = stall(false, false, None, false).await;
    assert!(took >= DEAD_AFTER, "the bytes came {took:?} after the stall: {notes:?}");
    assert!(!notes.iter().any(|n| matches!(n, Note::Spare { .. })), "{notes:?}");
}

#[tokio::test(start_paused = true)]
async fn a_spare_that_greets_and_fails_its_handshake_gives_way_and_the_loss_is_said_once() {
    let (took, notes) = stall(true, false, None, true).await;
    assert!(took < Duration::from_secs(10), "the bytes came {took:?} after the stall: {notes:?}");
    assert_eq!(notes.iter().filter(|n| matches!(n, Note::Lost { .. })).count(), 1, "one loss: {notes:?}");
    // The old link had stopped: no line says that it goes on.
    let goes_on = notes.iter().any(|n| matches!(n, Note::SpareClosed { .. } | Note::MoveFailed { .. }));
    assert!(!goes_on, "{notes:?}");
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "{notes:?}");
}
