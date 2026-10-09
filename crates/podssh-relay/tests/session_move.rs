//! A session that moves to a new link before the relay's limits (T-155). A
//! stand-in relay caps each link at 1 MiB both ways, as the relay caps a
//! session at 64 MiB; the client moves at 768 KiB, its 75 %. 8 MiB go each
//! way over more than 8 links, with equal SHA-256 digests, and no link meets
//! its cap: each move opened a new link while the old one still carried the
//! session, then retired the old one. The same at full speed both ways, with
//! a move each 256 KiB: the offsets of each new link's handshake are taken
//! after the old link stopped, so none is one that the other side no longer
//! keeps (T-262).

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{far, Ask, End, Ended, OsEntropy, Role, Settings};

const PIPE: usize = 256 * 1024;
const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;
/// The stand-in relay's cap on each link, both ways together.
const CAP: usize = MIB;
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

async fn copy_until<R, W>(from: &mut R, to: &mut W, left: &AtomicI64) -> bool
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * KIB];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => n,
        };
        let before = left.fetch_sub(n as i64, Ordering::SeqCst);
        if before <= n as i64 {
            let _ = to.write_all(&buf[..before.max(0) as usize]).await;
            return true;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return false;
        }
    }
}

/// A link through a stand-in relay that ends it at `cap` bytes both ways,
/// as the relay ends a session with `1009 session byte cap`; each cap met is
/// counted in `capped`.
fn capped_link(capped: Arc<AtomicUsize>, cap: usize) -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let left = AtomicI64::new(cap as i64);
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        let met = tokio::select! {
            met = copy_until(&mut cr, &mut fw, &left) => met,
            met = copy_until(&mut fr, &mut cw, &left) => met,
        };
        if met {
            capped.fetch_add(1, Ordering::SeqCst);
        }
    });
    (client, far)
}

/// Write `out`, at about 16 MiB/s as through a relay when `paced`, else at
/// once, and read as many bytes.
async fn exchange(stream: DuplexStream, out: Vec<u8>, paced: bool) -> Vec<u8> {
    let (mut r, mut w) = tokio::io::split(stream);
    let len = out.len();
    let writer = tokio::spawn(async move {
        for chunk in out.chunks(32 * KIB) {
            w.write_all(chunk).await.unwrap();
            if paced {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        w
    });
    let mut got = vec![0u8; len];
    r.read_exact(&mut got).await.unwrap();
    let mut w = writer.await.unwrap();
    w.shutdown().await.unwrap();
    got
}

/// 8 MiB each way through links capped at `cap`, with a move at `move_at`:
/// the notes, and the count of links that met their cap.
async fn moved(move_at: usize, cap: usize, paced: bool) -> (Vec<Note>, usize) {
    let settings = Settings { move_bytes: move_at as u64, ..Settings::default() };
    let capped = Arc::new(AtomicUsize::new(0));
    let keeper = Arc::new(Keeper::new(Duration::from_secs(30)));
    let (links_tx, mut links_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel::<DuplexStream>();
    {
        let keeper = keeper.clone();
        tokio::spawn(async move {
            while let Some(link) = links_rx.recv().await {
                let (keeper, targets) = (keeper.clone(), targets_tx.clone());
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

    let (client_link, far_link) = capped_link(capped.clone(), cap);
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let connect = {
        let (links_tx, capped) = (links_tx.clone(), capped.clone());
        move |_: &Ended| {
            let (client_link, far_link) = capped_link(capped.clone(), cap);
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
    let up = pseudo_random(8 * MIB, 3);
    let down = pseudo_random(8 * MIB, 4);
    let (at_target, at_client) = tokio::time::timeout(LIMIT, async {
        tokio::join!(exchange(target, down.clone(), paced), exchange(app, up.clone(), paced))
    })
    .await
    .expect("the bytes came through within the limit");
    assert_eq!(Sha256::digest(&at_target), Sha256::digest(&up), "the client's bytes reached the target whole");
    assert_eq!(Sha256::digest(&at_client), Sha256::digest(&down), "the target's bytes reached the client whole");

    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Outcome::Layer(e) if matches!(e.end, End::LocalEnd | End::Closed(_))), "{outcome:?}");
    let notes = notes.lock().unwrap().clone();
    (notes, capped.load(Ordering::SeqCst))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_moves_before_each_cap() {
    let (notes, capped) = moved(CAP * 3 / 4, CAP, true).await;
    let moves = notes.iter().filter(|n| matches!(n, Note::Moved { .. })).count();
    let losses: Vec<&Note> = notes.iter().filter(|n| !matches!(n, Note::Moved { .. })).collect();
    assert!(moves > 8, "{moves} moves for 16 MiB under a cap of 1 MiB");
    assert!(losses.is_empty(), "no loss, no failed move: {losses:?}");
    assert_eq!(capped, 0, "no link met its cap");
}

/// Both ends send as fast as they can, and the session moves each 256 KiB:
/// the old link carries acknowledgements until it stops, and no move fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_moves_while_both_ends_send_at_full_speed() {
    let (notes, capped) = moved(256 * KIB, 64 * MIB, false).await;
    let moves = notes.iter().filter(|n| matches!(n, Note::Moved { .. })).count();
    let losses: Vec<&Note> = notes.iter().filter(|n| !matches!(n, Note::Moved { .. })).collect();
    assert!(moves > 16, "{moves} moves for 16 MiB, with a mark at 256 KiB of each link");
    assert!(losses.is_empty(), "no loss, no failed move: {losses:?}");
    assert_eq!(capped, 0);
}
