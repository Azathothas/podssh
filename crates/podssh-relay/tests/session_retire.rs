//! A moved session's old link is ended by the far end, never by the client
//! (T-410). On a node's road the client's end of a link is the operator
//! leg's end, whose Close crosses the node's bytes still on their way; the
//! relay then ends the node's whole socket for a frame of an id that it
//! forgot (`1003 unknown session id`), which the live relay did at the first
//! move of each bulk session through a node. Here a stand-in relay notes
//! which side of each link ends first, while a session moves at 256 KiB.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc;

use podssh_relay::session::client;
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{far, Ask, Ended, OsEntropy, Role, Settings};

const PIPE: usize = 64 * 1024;

/// When each side of each link ended its bytes, by the link's number.
#[derive(Default)]
struct Ends {
    client: Vec<(usize, Instant)>,
    far: Vec<(usize, Instant)>,
}

/// One direction of the stand-in relay, from the client when `from_client`:
/// the bytes go on until a side ends, which is noted. The sender ended when
/// its bytes end; the receiver, when a write to it fails, as a side that
/// dropped its link takes nothing more. Then the other side's reading ends.
async fn carry(
    mut from: ReadHalf<DuplexStream>,
    mut to: WriteHalf<DuplexStream>,
    link: usize,
    from_client: bool,
    ends: Arc<Mutex<Ends>>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    let client_ended = loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => break from_client,
            Ok(n) => {
                if to.write_all(&buf[..n]).await.is_err() {
                    break !from_client;
                }
            }
        }
    };
    {
        let mut ends = ends.lock().unwrap();
        let list = if client_ended { &mut ends.client } else { &mut ends.far };
        list.push((link, Instant::now()));
    }
    let _ = to.shutdown().await;
}

/// A link through the stand-in relay, numbered: its two ends.
fn relayed(link: usize, ends: &Arc<Mutex<Ends>>) -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    let (cr, cw) = tokio::io::split(relay_client);
    let (fr, fw) = tokio::io::split(relay_far);
    tokio::spawn(carry(cr, fw, link, true, ends.clone()));
    tokio::spawn(carry(fr, cw, link, false, ends.clone()));
    (client, far)
}

async fn echo(target: DuplexStream) {
    let (mut r, mut w) = tokio::io::split(target);
    let _ = tokio::io::copy(&mut r, &mut w).await;
    let _ = w.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_far_end_ends_a_moved_link_before_the_client_does() {
    let settings = Settings { move_bytes: 256 * 1024, ..Settings::default() };
    let keeper = Arc::new(Keeper::new(Duration::from_secs(30)));
    let ends = Arc::new(Mutex::new(Ends::default()));
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
    let (client_link, far_link) = relayed(0, &ends);
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let count = Arc::new(Mutex::new(0usize));
    let connect = {
        let (links_tx, ends, count) = (links_tx.clone(), ends.clone(), count.clone());
        move |_: &Ended| {
            let link = {
                let mut count = count.lock().unwrap();
                *count += 1;
                *count
            };
            let (client_link, far_link) = relayed(link, &ends);
            links_tx.send(far_link).unwrap();
            async move { Next::Link(client_link) }
        }
    };
    let note = {
        let notes = notes.clone();
        move |n: Note| notes.lock().unwrap().push(n)
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });

    // 2 MiB through the echo: some moves at 256 KiB each.
    let sent: Vec<u8> = (0..2 << 20).map(|i: u32| (i % 251) as u8).collect();
    let (mut r, mut w) = tokio::io::split(app);
    let writer = {
        let sent = sent.clone();
        tokio::spawn(async move {
            w.write_all(&sent).await.unwrap();
            w
        })
    };
    let mut back = vec![0u8; sent.len()];
    tokio::time::timeout(Duration::from_secs(30), r.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(back, sent);
    let _w = writer.await.unwrap();
    let moved = notes.lock().unwrap().iter().filter(|n| matches!(n, Note::Moved { .. })).count();
    assert!(moved >= 1, "the session moved: {:?}", notes.lock().unwrap());

    // The links that the moves left end within a few seconds, the far end's
    // side first.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let ends = ends.lock().unwrap();
    for (link, far_at) in ends.far.iter().filter(|(link, _)| *link < moved) {
        if let Some((_, client_at)) = ends.client.iter().find(|(l, _)| l == link) {
            let notes = notes.lock().unwrap();
            assert!(
                far_at <= client_at,
                "link {link}: the client ended it before the far end did; moved {moved}; {notes:?}"
            );
        }
    }
    for link in 0..moved {
        assert!(ends.far.iter().any(|(l, _)| *l == link), "link {link}: the far end ended it");
        assert!(
            !ends.client.iter().any(|(l, at)| *l == link && !ends.far.iter().any(|(fl, fat)| fl == l && fat <= at)),
            "link {link}: the client ended it first"
        );
    }
}
