//! The far end's last record on a link: a `CLOSE` or a `REFUSE` after which
//! it has nothing more to say (T-354). The client writes on until it reads
//! that record, and a relay that ends both ways when one fails, as the relay
//! ends a session, would drop the record still on its way at the client's
//! first write to a link that is gone. The far end keeps the link until the
//! client ends it. And a client whose write in the handshake fails reads what
//! came before: a `REFUSE` says why, where a failed link would not.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use podssh_relay::session::client::{self, ClientError, Outcome};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{
    far, Ask, Decoder, End, Ended, HandshakeError, Hello, Nonce, OsEntropy, Record, RefuseCode, Role, Secret,
    SessionId, Settings,
};

const PIPE: usize = 256 * 1024;
const LIMIT: Duration = Duration::from_secs(30);
/// How late the stand-in relays carry the far end's bytes, as over a slower
/// path to the client.
const LATE: Duration = Duration::from_millis(300);
/// How long [`records_late`] holds each record of the client.
const RECORD_LATE: Duration = Duration::from_millis(100);

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

/// The bytes of `from`, each read given to `to` [`LATE`] after it came.
async fn late<R, W>(from: &mut R, to: &mut W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        tokio::time::sleep(LATE).await;
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

/// A link through a stand-in relay that cuts nothing until `cut` is told,
/// then ends both ways with no word to either end.
fn cut_when(cut: Arc<Notify>) -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        tokio::select! {
            _ = tokio::io::copy(&mut cr, &mut fw) => {}
            _ = tokio::io::copy(&mut fr, &mut cw) => {}
            () = cut.notified() => {}
        }
    });
    (client, far)
}

/// A link through a stand-in relay that ends both ways when either way ends
/// or fails, and that carries the far end's bytes [`LATE`]. The far end's
/// side holds little, so that the client's bytes wait on it.
fn slow_to_client() -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        tokio::select! {
            _ = tokio::io::copy(&mut cr, &mut fw) => {}
            () = late(&mut fr, &mut cw) => {}
        }
    });
    (client, far)
}

/// A link through a stand-in relay that ends both ways when either way ends
/// or fails, that gives each record of the client [`RECORD_LATE`] after the
/// one before, and the far end's bytes [`LATE`].
fn records_late() -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        let records = async {
            let (mut decoder, mut buf) = (Decoder::new(), vec![0u8; 64 * 1024]);
            loop {
                while let Ok(Some(record)) = decoder.next() {
                    tokio::time::sleep(RECORD_LATE).await;
                    if fw.write_all(&record.to_bytes().unwrap()).await.is_err() {
                        return;
                    }
                }
                match cr.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => decoder.push(&buf[..n]),
                }
            }
        };
        tokio::select! {
            () = records => {}
            () = late(&mut fr, &mut cw) => {}
        }
    });
    (client, far)
}

/// The notes of a session, and the closure that takes them, which also
/// tells `resumed` of each resume.
fn notes(resumed: Arc<Notify>) -> (Arc<Mutex<Vec<Note>>>, impl FnMut(Note) + Send + 'static) {
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let taken = notes.clone();
    let note = move |n: Note| {
        if let Note::Resumed { .. } = n {
            resumed.notify_one();
        }
        taken.lock().unwrap().push(n);
    };
    (notes, note)
}

/// The client's application, which writes until the session ends.
fn writes_on(app: DuplexStream) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (_app_r, mut app_w) = tokio::io::split(app);
        let chunk = pseudo_random(4096, 59);
        while app_w.write_all(&chunk).await.is_ok() {}
    })
}

/// The far end accepts a resume on a new link, and the session ends at the
/// far end before that link carries it, as when the old link's `CLOSE` came
/// first: here its deadline passes. The far end's `CLOSE` on the new link
/// goes through a relay that ends both ways at the client's next write to a
/// link that is gone, and slower than that write. The far end keeps the link
/// until the client read it: the session ends with that `CLOSE`, not with a
/// second loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_far_ends_last_close_on_a_new_link_waits_for_the_client() {
    let settings = Settings::default();
    let keeper = Arc::new(Keeper::<DuplexStream>::new(Duration::from_secs(60)));
    let (cut, resumed) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let (links_tx, mut links_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let (far_end, far_resumed) = (keeper.clone(), resumed.clone());
    tokio::spawn(async move {
        while let Some(link) = links_rx.recv().await {
            let (keeper, targets, resumed) = (far_end.clone(), targets_tx.clone(), far_resumed.clone());
            tokio::spawn(async move {
                let Ok(accepted) = far::accept(link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy).await
                else {
                    return;
                };
                if !accepted.established().resumed {
                    let (target, app) = tokio::io::duplex(PIPE);
                    let _ = targets.send(app);
                    keeper.run_new(accepted, target).await;
                    return;
                }
                // Once the client took the resume, the session's deadline
                // passes at the far end, before the new link carries it.
                resumed.notified().await;
                let later = Instant::now() + Duration::from_secs(120);
                while keeper.expire_at(later).await == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let _ = keeper.run_resumed(accepted).await;
            });
        }
    });
    let (client_link, far_link) = cut_when(cut.clone());
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let connect = move |_: &Ended| {
        let (client_link, far_link) = slow_to_client();
        links_tx.send(far_link).unwrap();
        async move { Next::Link(client_link) }
    };
    let (notes, note) = notes(resumed);
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });
    let _target = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().unwrap();
    // The client's application writes on, through the loss and the resume.
    let writer = writes_on(app);
    cut.notify_one();
    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Outcome::Layer(Ended { end: End::Closed(_), .. })), "{outcome:?}");
    let notes = notes.lock().unwrap().clone();
    assert_eq!(notes.iter().filter(|n| matches!(n, Note::Lost { .. })).count(), 1, "one loss: {notes:?}");
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "{notes:?}");
    writer.abort();
}

/// A resume of a session that the far end does not know: the far end refuses
/// at the `OPEN`, while the client's `PROOF` is still on its way. The `PROOF`
/// reaches it after its `REFUSE` left, through a relay that ends both ways at
/// a write to a link that is gone; the far end keeps the link until the
/// client read the `REFUSE`, and the client hears that the session is
/// unknown, not that the link failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_in_the_handshake_waits_for_the_client() {
    let settings = Settings::default();
    let keeper = Arc::new(Keeper::<DuplexStream>::new(Duration::from_secs(60)));
    let (client_link, far_link) = records_late();
    let far_end = keeper.clone();
    tokio::spawn(async move {
        let _ = far::accept(far_link, Role::NODE, settings, &far_end.sessions, &mut OsEntropy).await;
    });
    let ask = Ask::Resume { id: SessionId([9; 16]), secret: Secret::from_bytes([3; 32]), received: 0 };
    let started = tokio::time::timeout(LIMIT, client::start(client_link, ask, settings, &mut OsEntropy)).await.unwrap();
    let error = started.err().expect("no session to resume");
    assert!(
        matches!(error, ClientError::Handshake(HandshakeError::Refused { code: RefuseCode::UNKNOWN_SESSION, .. })),
        "{error:?}"
    );
}

/// A far end that refuses a resume and is gone before the client's first
/// record: the client's write fails, and it reads the `REFUSE` that came
/// before, which says why, in place of a link that failed.
#[tokio::test]
async fn a_refusal_that_came_before_a_failed_write_is_read() {
    let (client_link, mut far) = tokio::io::duplex(PIPE);
    let hello = Hello { version: 1, role: Role::NODE, nonce: Nonce([7; 32]), features: vec!["replay.v1".into()] };
    let mut bytes = Record::Greeting(hello).to_bytes().unwrap();
    let refusal = Record::Refuse { code: RefuseCode::UNKNOWN_SESSION, reason: "no such session here".into() };
    bytes.extend(refusal.to_bytes().unwrap());
    far.write_all(&bytes).await.unwrap();
    // Gone: a write to the link now fails; its records stay to be read.
    drop(far);
    let ask = Ask::Resume { id: SessionId([9; 16]), secret: Secret::from_bytes([3; 32]), received: 0 };
    let started = tokio::time::timeout(LIMIT, client::start(client_link, ask, Settings::default(), &mut OsEntropy))
        .await
        .unwrap();
    let error = started.err().expect("no session to resume");
    assert!(
        matches!(error, ClientError::Handshake(HandshakeError::Refused { code: RefuseCode::UNKNOWN_SESSION, .. })),
        "{error:?}"
    );
}

/// A far end whose target cannot be reached ends the new session at once,
/// with the reason in its `CLOSE`, while the client's application writes: the
/// reason reaches the client through a relay that ends both ways at the
/// client's next write to a link that is gone, and slower than that write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reason_that_ends_a_new_session_waits_for_the_client() {
    let settings = Settings::default();
    let keeper = Arc::new(Keeper::<DuplexStream>::new(Duration::from_secs(60)));
    let started = Arc::new(Notify::new());
    let (client_link, far_link) = slow_to_client();
    let (far_end, far_started) = (keeper.clone(), started.clone());
    tokio::spawn(async move {
        // The target fails once the client's session has started, so that
        // the `CLOSE` comes on its own, after the `ACCEPT`.
        let open = || async move {
            far_started.notified().await;
            Err::<DuplexStream, String>("no target here".into())
        };
        far::serve(far_link, Role::NODE, settings, &far_end, 64 << 20, open).await;
    });
    let client = tokio::time::timeout(LIMIT, client::start(client_link, Ask::New, settings, &mut OsEntropy))
        .await
        .unwrap()
        .unwrap();
    started.notify_one();
    let connect = |_: &Ended| async { Next::<DuplexStream>::Stop("this test opens no second link".into()) };
    let (notes, note) = notes(Arc::new(Notify::new()));
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });
    let writer = writes_on(app);
    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Outcome::Layer(Ended { end: End::Closed(reason), .. }) if reason.contains("no target here")),
        "{outcome:?}"
    );
    let notes = notes.lock().unwrap().clone();
    assert!(notes.is_empty(), "no loss: {notes:?}");
    writer.abort();
}
