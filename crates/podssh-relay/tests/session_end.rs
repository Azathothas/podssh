//! The end of a session on the resumable layer (T-262). A side whose
//! application ended sends `CLOSE` after its last bytes, and the peer answers
//! with its own `CLOSE`; only then is the session over at that side. A link
//! that ends between the two leaves the session to a resume, which sends the
//! `CLOSE` again. And a link whose writes fail still gives what it carried
//! before: the far end's last bytes and its `CLOSE` are read, not lost.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{
    far, Acceptance, Ask, Decoder, End, Ended, Hello, Nonce, OsEntropy, Record, Role, SessionId, Settings,
};

const PIPE: usize = 256 * 1024;
const LIMIT: Duration = Duration::from_secs(30);
/// Long before the far end's deadline: a session that waits for it fails.
const SOON: Duration = Duration::from_secs(20);

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

/// The far end's records, from the bytes of a real `GREETING` with
/// `features` to an `ACCEPT` of a new session once the client's `OPEN`
/// came.
async fn greet_and_accept(far: &mut DuplexStream, features: &[&str]) {
    let hello = Hello {
        version: 1,
        role: Role::NODE,
        nonce: Nonce([7; 32]),
        features: features.iter().map(|f| f.to_string()).collect(),
    };
    far.write_all(&Record::Greeting(hello).to_bytes().unwrap()).await.unwrap();
    let mut decoder = Decoder::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if let Some(record) = decoder.next().unwrap() {
            assert!(matches!(record, Record::Open { .. }), "{record:?}");
            break;
        }
        let n = far.read(&mut buf).await.unwrap();
        assert!(n > 0, "the client ended the link");
        decoder.push(&buf[..n]);
    }
    // RFC 7748's public key of Bob: any key that is not of low order.
    let public: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83,
        0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    ];
    let accept = Record::Accept(Acceptance::New { id: SessionId([5; 16]), public });
    far.write_all(&accept.to_bytes().unwrap()).await.unwrap();
}

/// A far end that sends 1 MiB and its `CLOSE`, and then is gone, as when the
/// relay closes the link after the node's last bytes: the client's `ACK`
/// cannot go out, and the bytes and the `CLOSE` wait to be read. Each byte
/// reaches the application, and the session ends with the far end's reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_that_fails_its_writes_still_gives_what_came() {
    // Room for all that the far end sends, so that it can go before the
    // client reads.
    let (client_link, mut far) = tokio::io::duplex(4 << 20);
    let sent = pseudo_random(1 << 20, 41);
    let script = {
        let sent = sent.clone();
        tokio::spawn(async move {
            greet_and_accept(&mut far, &["replay.v1"]).await;
            let mut bytes = Vec::new();
            for (i, chunk) in sent.chunks(32 * 1024).enumerate() {
                let offset = (i * 32 * 1024) as u64;
                bytes.extend(Record::Data { offset, bytes: chunk.to_vec() }.to_bytes().unwrap());
            }
            bytes.extend(Record::Close { reason: "done".into() }.to_bytes().unwrap());
            far.write_all(&bytes).await.unwrap();
            // Gone: a write to the link now fails; its bytes stay to be read.
            drop(far);
        })
    };
    let client = tokio::time::timeout(LIMIT, client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(LIMIT, script).await.unwrap().unwrap();

    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let run = tokio::spawn(client.run(app_end));
    let mut got = Vec::new();
    tokio::time::timeout(LIMIT, app.read_to_end(&mut got)).await.unwrap().unwrap();
    assert_eq!(got.len(), sent.len(), "each byte that came before the CLOSE");
    assert_eq!(Sha256::digest(&got), Sha256::digest(&sent));
    let outcome = tokio::time::timeout(LIMIT, run).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Outcome::Layer(Ended { end: End::Closed(reason), .. }) if reason == "done"),
        "{outcome:?}"
    );
}

/// Which side's first `CLOSE` the stand-in relay keeps from the other.
#[derive(Clone, Copy)]
enum From {
    Client,
    Far,
}

/// Copy records from `from` to `to` until the first `CLOSE`, which never
/// passes.
async fn until_close<R, W>(from: &mut R, to: &mut W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = Decoder::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        decoder.push(&buf[..n]);
        while let Ok(Some(record)) = decoder.next() {
            if matches!(record, Record::Close { .. }) {
                return;
            }
            if to.write_all(&record.to_bytes().unwrap()).await.is_err() {
                return;
            }
        }
    }
}

/// A link through a stand-in relay that ends it, with no word to either
/// end, where the first `CLOSE` of `from` would pass: that `CLOSE` is lost
/// with the link.
fn cut_at_close(from: From) -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        match from {
            From::Client => tokio::select! {
                _ = until_close(&mut cr, &mut fw) => {}
                _ = tokio::io::copy(&mut fr, &mut cw) => {}
            },
            From::Far => tokio::select! {
                _ = tokio::io::copy(&mut cr, &mut fw) => {}
                _ = until_close(&mut fr, &mut cw) => {}
            },
        }
    });
    (client, far)
}

/// A link through a stand-in relay that cuts nothing.
fn plain() -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        tokio::select! {
            _ = tokio::io::copy(&mut cr, &mut fw) => {}
            _ = tokio::io::copy(&mut fr, &mut cw) => {}
        }
    });
    (client, far)
}

/// A session whose first link loses the first `CLOSE` of `from`, and whose
/// next links cut nothing: the client's application, the target, the
/// session's end and its notes.
struct Run {
    app: DuplexStream,
    target: DuplexStream,
    session: tokio::task::JoinHandle<Outcome>,
    notes: Arc<Mutex<Vec<Note>>>,
    /// Held for the whole test, as a node holds its keeper: a keeper that
    /// is dropped drops the targets that it keeps.
    _keeper: Arc<Keeper<DuplexStream>>,
}

async fn start(from: From) -> Run {
    let settings = Settings::default();
    // The far end keeps a lost session for a minute: longer than the test.
    let keeper = Arc::new(Keeper::new(Duration::from_secs(60)));
    let (links_tx, mut links_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let held = keeper.clone();
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
    let (client_link, far_link) = cut_at_close(from);
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let connect = move |_: &Ended| {
        let (client_link, far_link) = plain();
        links_tx.send(far_link).unwrap();
        async move { Next::Link(client_link) }
    };
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let note = {
        let notes = notes.clone();
        move |n: Note| notes.lock().unwrap().push(n)
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });
    let target = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().unwrap();
    Run { app, target, session, notes, _keeper: held }
}

/// The client's application ends; the relay loses the client's `CLOSE` with
/// the link. The client resumes, and its `CLOSE` goes again: the target
/// learns that the session ended long before the far end's deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_that_its_link_lost_goes_again_on_the_next() {
    let run = start(From::Client).await;
    let sent = pseudo_random(100_000, 43);
    let (_app_r, mut app_w) = tokio::io::split(run.app);
    app_w.write_all(&sent).await.unwrap();
    app_w.shutdown().await.unwrap();
    let (mut target_r, _target_w) = tokio::io::split(run.target);
    let mut got = Vec::new();
    tokio::time::timeout(SOON, target_r.read_to_end(&mut got))
        .await
        .expect("the session ended at the far end before its deadline")
        .unwrap();
    assert_eq!(Sha256::digest(&got), Sha256::digest(&sent));
    let outcome = tokio::time::timeout(LIMIT, run.session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Outcome::Layer(Ended { end: End::LocalEnd, .. })), "{outcome:?}");
    let notes = run.notes.lock().unwrap().clone();
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "{notes:?}");
}

/// The target ends; the relay loses the far end's `CLOSE` with the link. The
/// far end keeps the session, the client resumes it, and the `CLOSE` comes
/// on the new link: the session ends with it, not with a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_far_ends_close_that_its_link_lost_comes_on_the_next() {
    let run = start(From::Far).await;
    let sent = pseudo_random(100_000, 47);
    let (mut target_r, mut target_w) = tokio::io::split(run.target);
    target_w.write_all(&sent).await.unwrap();
    target_w.shutdown().await.unwrap();
    let (mut app_r, _app_w) = tokio::io::split(run.app);
    let mut got = Vec::new();
    tokio::time::timeout(SOON, app_r.read_to_end(&mut got)).await.unwrap().unwrap();
    assert_eq!(Sha256::digest(&got), Sha256::digest(&sent));
    let outcome = tokio::time::timeout(LIMIT, run.session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Outcome::Layer(Ended { end: End::Closed(_), .. })), "{outcome:?}");
    // The far end forgets the session once the client's answer came.
    let mut rest = Vec::new();
    tokio::time::timeout(SOON, target_r.read_to_end(&mut rest)).await.expect("the target's session ended").unwrap();
    let notes = run.notes.lock().unwrap().clone();
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "{notes:?}");
}
