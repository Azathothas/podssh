//! A session whose far application echoes each byte, as a node in front of
//! an echo server or a shell does, while the client writes and reads at once
//! (T-387). Each side's application waits for the other side's bytes, so a
//! reader that stops reading the link while its application is slow never
//! sees the acknowledgements that would free its own replay buffer: both
//! ends wait until the link is taken for dead, 30 s later, and resume with
//! the whole buffer again. 32 MiB, eight replay windows, go through the echo
//! and a stand-in relay with a round trip of 100 ms and 1 MiB held each
//! way, within 25 s, with no link lost, and each byte back whole.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{far, Ask, End, Ended, OsEntropy, Role, Settings};

/// Small pipes on each side of the session, so that a slow application
/// pushes back at once.
const PIPE: usize = 64 * 1024;
/// What the stand-in relay holds for each direction, as the relay keeps
/// 1 MiB for a slow receiver.
const HELD: usize = MIB;
/// Each direction's delay through the stand-in relay: a round trip of
/// 100 ms, so that an acknowledgement is under way while megabytes are.
const DELAY: Duration = Duration::from_millis(50);
const MIB: usize = 1 << 20;
const LEN: usize = 32 * MIB;
/// Below the 30 s after which a silent link is taken for dead.
const WITHIN: Duration = Duration::from_secs(25);

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

/// One direction of the stand-in relay: each read goes on after `DELAY`,
/// with at most `HELD` bytes on their way.
async fn delayed(mut from: tokio::io::ReadHalf<DuplexStream>, mut to: tokio::io::WriteHalf<DuplexStream>) {
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(HELD / (64 * 1024));
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send((Instant::now() + DELAY, buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    while let Some((at, bytes)) = rx.recv().await {
        tokio::time::sleep_until(at.into()).await;
        if to.write_all(&bytes).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
    reader.abort();
}

/// A link through the stand-in relay: its two ends.
fn relayed_link() -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    let (cr, cw) = tokio::io::split(relay_client);
    let (fr, fw) = tokio::io::split(relay_far);
    tokio::spawn(delayed(cr, fw));
    tokio::spawn(delayed(fr, cw));
    (client, far)
}

/// Each byte that comes from the session goes back into it.
async fn echo(target: DuplexStream) {
    let (mut r, mut w) = tokio::io::split(target);
    let _ = tokio::io::copy(&mut r, &mut w).await;
    let _ = w.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_far_end_that_echoes_takes_eight_windows_at_once_and_loses_no_link() {
    let settings = Settings::default();
    let keeper = Arc::new(Keeper::new(Duration::from_secs(30)));
    let (links_tx, mut links_rx) = mpsc::unbounded_channel::<DuplexStream>();
    {
        let keeper = keeper.clone();
        tokio::spawn(async move {
            while let Some(link) = links_rx.recv().await {
                let keeper = keeper.clone();
                tokio::spawn(async move {
                    let Ok(accepted) = far::accept(link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy).await
                    else {
                        return;
                    };
                    if accepted.established().resumed {
                        let _ = keeper.run_resumed(accepted).await;
                    } else {
                        let (target, app) = tokio::io::duplex(PIPE);
                        tokio::spawn(echo(app));
                        keeper.run_new(accepted, target).await;
                    }
                });
            }
        });
    }

    let (client_link, far_link) = relayed_link();
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let connect = {
        let links_tx = links_tx.clone();
        move |_: &Ended| {
            let (client_link, far_link) = relayed_link();
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

    let sent = pseudo_random(LEN, 7);
    let started = Instant::now();
    let (mut r, mut w) = tokio::io::split(app);
    let back = tokio::time::timeout(WITHIN, async {
        let writer = {
            let sent = sent.clone();
            tokio::spawn(async move {
                for chunk in sent.chunks(32 * 1024) {
                    w.write_all(chunk).await.unwrap();
                }
                w
            })
        };
        let mut back = vec![0u8; LEN];
        r.read_exact(&mut back).await.unwrap();
        let mut w = writer.await.unwrap();
        w.shutdown().await.unwrap();
        back
    })
    .await
    .unwrap_or_else(|_| {
        let notes = notes.lock().unwrap().clone();
        panic!("32 MiB did not come back through the echo within {} s; the notes: {notes:?}", WITHIN.as_secs())
    });
    assert_eq!(Sha256::digest(&back), Sha256::digest(&sent), "each byte came back whole");
    eprintln!("32 MiB through the echo and back in {:.1} s", started.elapsed().as_secs_f64());

    let outcome = tokio::time::timeout(Duration::from_secs(60), session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Outcome::Layer(e) if matches!(e.end, End::LocalEnd | End::Closed(_))), "{outcome:?}");
    // A move before the relay's limit is planned; a loss, a resume or a
    // spare link is what a stalled link gives.
    let notes = notes.lock().unwrap().clone();
    let stalled: Vec<_> = notes.iter().filter(|n| !matches!(n, Note::Moved { .. })).collect();
    assert!(stalled.is_empty(), "no link was lost or taken for silent: {notes:?}");
}
