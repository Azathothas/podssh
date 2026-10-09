//! A session across links (T-153). A stand-in relay cuts each link at a
//! random point, in the middle of a record, with no word to either end,
//! while 32 MiB go each way; the client resumes on a new link through
//! another stand-in host each time, and the bytes at both ends have equal
//! SHA-256 digests. After the deadline, the far end has forgotten the
//! session, and the client ends with its refusal.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};

use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{far, Ask, End, OsEntropy, Role, Settings};

const PIPE: usize = 256 * 1024;
const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(120);

fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Copy `from` into `to` until `left` (bytes of both ways together) runs
/// out: the part before the cut goes through, and the rest never does.
async fn copy_until<R, W>(from: &mut R, to: &mut W, left: &AtomicI64)
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
        let before = left.fetch_sub(n as i64, Ordering::SeqCst);
        if before <= n as i64 {
            let _ = to.write_all(&buf[..before.max(0) as usize]).await;
            return;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

/// A link through a stand-in relay host: both ways until `cut` bytes have
/// passed, then both ends are dropped with no word, as when the relay's side
/// drops a socket. `None` never cuts.
fn relayed(cut: Option<usize>) -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let left = AtomicI64::new(cut.map_or(i64::MAX, |c| c as i64));
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        tokio::select! {
            _ = copy_until(&mut cr, &mut fw, &left) => {}
            _ = copy_until(&mut fr, &mut cw, &left) => {}
        }
    });
    (client, far)
}

/// A far end that takes each link from `links`: a new session gets a target
/// whose other end goes to `targets`; a resume goes on through the keeper.
fn far_end(
    keeper: Arc<Keeper<DuplexStream>>,
    settings: Settings,
    mut links: mpsc::UnboundedReceiver<DuplexStream>,
    targets: mpsc::UnboundedSender<DuplexStream>,
) {
    tokio::spawn(async move {
        while let Some(link) = links.recv().await {
            let keeper = keeper.clone();
            let targets = targets.clone();
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

/// Write `out` and read as many bytes at once, then wait for the end.
async fn exchange(stream: DuplexStream, out: Vec<u8>) -> Vec<u8> {
    let (mut r, mut w) = tokio::io::split(stream);
    let len = out.len();
    let writer = tokio::spawn(async move {
        w.write_all(&out).await.unwrap();
        w
    });
    let mut got = vec![0u8; len];
    r.read_exact(&mut got).await.unwrap();
    let mut w = writer.await.unwrap();
    w.shutdown().await.unwrap();
    got
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_survives_links_cut_at_random_points() {
    let settings = Settings { resume_deadline: Duration::from_secs(30), ..Settings::default() };
    let keeper = Arc::new(Keeper::new(Duration::from_secs(30)));
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    far_end(keeper.clone(), settings, links_rx, targets_tx);

    // Four cuts at random points, each link's own count; the fifth link holds.
    let mut x: u32 = 0x5eed_1234;
    let mut cuts: Vec<Option<usize>> = (0..4)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            Some(256 * 1024 + (x as usize) % (12 * MIB))
        })
        .collect();
    cuts.push(None);
    let cuts = Arc::new(Mutex::new(cuts.into_iter()));

    let first_cut = cuts.lock().unwrap().next().flatten();
    let (client_link, far_link) = relayed(first_cut);
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();

    let hosts: Arc<Mutex<Vec<&'static str>>> = Arc::default();
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let connect = {
        let (cuts, hosts, links_tx) = (cuts.clone(), hosts.clone(), links_tx.clone());
        move |_: &podssh_relay::session::Ended| {
            let mut hosts = hosts.lock().unwrap();
            // Each new link through the other stand-in host.
            let host = if hosts.len() % 2 == 0 { "host-b" } else { "host-a" };
            hosts.push(host);
            let (client_link, far_link) = relayed(cuts.lock().unwrap().next().flatten());
            links_tx.send(far_link).unwrap();
            async move { Next::Link(client_link) }
        }
    };
    let note = {
        let notes = notes.clone();
        move |n: Note| notes.lock().unwrap().push(n)
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });

    let target = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().unwrap();
    let up = pseudo_random(32 * MIB, 1);
    let down = pseudo_random(32 * MIB, 2);
    let (at_server, at_client) =
        tokio::time::timeout(LIMIT, async { tokio::join!(exchange(target, down.clone()), exchange(app, up.clone())) })
            .await
            .expect("the bytes came through within the limit");
    assert_eq!(Sha256::digest(&at_server), Sha256::digest(&up), "the client's bytes reached the target whole");
    assert_eq!(Sha256::digest(&at_client), Sha256::digest(&down), "the target's bytes reached the client whole");

    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd | End::Closed(_))),
        "{outcome:?}"
    );
    let notes = notes.lock().unwrap().clone();
    let lost = notes.iter().filter(|n| matches!(n, Note::Lost { .. })).count();
    let resumed: Vec<u64> =
        notes.iter().filter_map(|n| if let Note::Resumed { resent, .. } = n { Some(*resent) } else { None }).collect();
    assert_eq!((lost, resumed.len()), (4, 4), "{notes:?}");
    let hosts = hosts.lock().unwrap().clone();
    assert!(hosts.contains(&"host-a") && hosts.contains(&"host-b"), "{hosts:?}");
}

/// A link lost, and no new one for longer than the far end's deadline: the
/// far end forgets the session, and the client's resume gets its refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_deadline_the_far_end_refuses_and_the_session_ends() {
    let settings = Settings { resume_deadline: Duration::from_secs(20), ..Settings::default() };
    let keeper = Arc::new(Keeper::new(Duration::from_millis(500)));
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    far_end(keeper.clone(), settings, links_rx, targets_tx);

    let (client_link, far_link) = relayed(Some(300_000));
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let (gate_tx, gate_rx) = oneshot::channel::<()>();
    let gate = Arc::new(tokio::sync::Mutex::new(Some(gate_rx)));
    let connect = {
        let links_tx = links_tx.clone();
        move |_: &podssh_relay::session::Ended| {
            let (gate, links_tx) = (gate.clone(), links_tx.clone());
            async move {
                // The new link comes only once the far end has forgotten.
                if let Some(rx) = gate.lock().await.take() {
                    let _ = rx.await;
                }
                let (client_link, far_link) = relayed(None);
                links_tx.send(far_link).unwrap();
                Next::Link(client_link)
            }
        }
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, |_| {}, &mut OsEntropy).await });
    let target = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().unwrap();
    // Bytes until the cut. The application reads each one: a client whose
    // application stops reading waits on it, and sees no loss until then.
    let (mut app_r, _app_w) = tokio::io::split(app);
    let (_target_r, mut target_w) = tokio::io::split(target);
    let drained = tokio::spawn(async move {
        let mut all = Vec::new();
        let _ = app_r.read_to_end(&mut all).await;
        all.len()
    });
    let _ = tokio::time::timeout(Duration::from_secs(5), target_w.write_all(&vec![7; 4 * MIB])).await;

    // The keeper's deadline passes with no link; it forgets the session.
    let mut forgotten = 0;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        forgotten += keeper.expire().await;
        if forgotten > 0 {
            break;
        }
    }
    assert_eq!(forgotten, 1);
    gate_tx.send(()).unwrap();

    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    let End::GaveUp(reason) = &ended.end else { panic!("{ended:?}") };
    assert!(reason.contains("did not resume") && reason.contains("no such session"), "{reason}");
    assert!(drained.await.unwrap() > 0, "bytes came before the cut");
}

/// No new link at all: the client stops at its own deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_new_link_the_client_stops_at_its_deadline() {
    let settings = Settings { resume_deadline: Duration::from_secs(3), ..Settings::default() };
    let keeper = Arc::new(Keeper::new(Duration::from_secs(30)));
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    far_end(keeper, settings, links_rx, targets_tx);
    let (client_link, far_link) = relayed(Some(10_000));
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let connect =
        |_: &podssh_relay::session::Ended| async { Next::<DuplexStream>::Retry("the relay host is down".into()) };
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let note = {
        let notes = notes.clone();
        move |n: Note| notes.lock().unwrap().push(n)
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let started = tokio::time::Instant::now();
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });
    let target = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().unwrap();
    let (_target_r, mut target_w) = tokio::io::split(target);
    let _ = tokio::time::timeout(Duration::from_secs(5), target_w.write_all(&vec![1; MIB])).await;
    drop(app);

    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    let elapsed = started.elapsed();
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    let End::GaveUp(reason) = &ended.end else { panic!("{ended:?}") };
    assert!(reason.contains("no new link within 3 s"), "{reason}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    let notes = notes.lock().unwrap().clone();
    assert!(notes.iter().any(|n| matches!(n, Note::Retry { why, .. } if why.contains("host is down"))), "{notes:?}");
}
