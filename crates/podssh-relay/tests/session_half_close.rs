//! The end of one direction on the resumable layer (T-632, GitHub #130).
//! Where both sides name `end.v1`, a side whose application ended its bytes
//! sends `END`, the peer shuts its application's write side and reads on, and
//! the reply after the end still comes; the second side's end is its `CLOSE`,
//! and the session ends when that is answered. An `END` that its link lost
//! comes again after a resume. A far end that names no `end.v1`, and a client
//! that does not ask, end with `CLOSE` as before, and no `END` crosses; a
//! read that fails ends the whole session.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use podssh_relay::session::client::{self, Found, Outcome};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::record::kind;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{
    far, half_close, Acceptance, Ask, Decoder, End, Ended, Event, Hello, Link, LinkError, Nonce, OffsetError,
    OsEntropy, Record, Role, SessionId, Settings,
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

/// A client that asks for the end of one direction, as `podssh proxy` does.
fn asking() -> Settings {
    Settings { half_close: true, ..Settings::default() }
}

/// The state of a session whose sides both named `end.v1`.
fn ending() -> Link {
    Link::new(0, 0).with_ends()
}

fn data(offset: u64, bytes: &[u8]) -> Record {
    Record::Data { offset, bytes: bytes.to_vec() }
}

/// The peer's `END` is taken at the offset after its last byte, once; a
/// resume sends it again, which is nothing; no byte comes after it. One past
/// the bytes that came is a gap, one below them bytes after the end, and a
/// session that did not agree on it takes none.
#[test]
fn a_link_takes_the_peers_end_once_at_its_received_offset() {
    let mut link = ending();
    assert_eq!(link.on_record(data(0, b"abc")), Ok(Event::Deliver(b"abc".to_vec())));
    assert_eq!(link.on_record(Record::End { offset: 3 }), Ok(Event::Ended { closes: false }));
    assert!(link.peer_ended());
    assert_eq!(link.on_record(data(0, b"abc")), Ok(Event::Nothing), "sent again by a resume");
    assert_eq!(link.on_record(Record::End { offset: 3 }), Ok(Event::Nothing), "sent again by a resume");
    assert_eq!(link.on_record(data(3, b"d")), Err(LinkError::End("DATA after the peer's END")));

    let mut ahead = ending();
    ahead.on_record(data(0, b"abc")).unwrap();
    let gap = LinkError::Offset(OffsetError::Gap { expected: 3, got: 5 });
    assert_eq!(ahead.on_record(Record::End { offset: 5 }), Err(gap));
    let mut behind = ending();
    behind.on_record(data(0, b"abc")).unwrap();
    let below = behind.on_record(Record::End { offset: 2 });
    assert_eq!(below, Err(LinkError::End("an END below bytes that came before it")));
    let mut unasked = Link::new(0, 0);
    let refused = unasked.on_record(Record::End { offset: 0 });
    assert_eq!(refused, Err(LinkError::End("an END, which this side did not ask for")));
}

/// This side's end is `END`, at its sent offset, on each link, until the
/// peer's own `END` came: its `CLOSE` is due then. With no agreement, and
/// after a read that failed, its end is `CLOSE`.
#[test]
fn a_link_says_its_end_until_the_peers_came_and_then_closes() {
    let mut link = ending();
    link.send(b"request", &mut Vec::new()).unwrap();
    assert!(!link.closes_at_end());
    assert_eq!(link.end(), Some(Record::End { offset: 7 }));
    assert_eq!(link.end(), Some(Record::End { offset: 7 }), "each link says it again");
    assert_eq!(link.on_record(Record::End { offset: 0 }), Ok(Event::Ended { closes: true }));
    assert!(link.closes_at_end());
    assert_eq!(link.end(), None, "the CLOSE now");
    assert_eq!(Link::new(0, 0).end(), None, "a peer that names no end.v1");
    let mut failed = ending();
    failed.app_failed();
    assert_eq!(failed.end(), None, "an application that is gone");
}

/// What a stand-in relay saw: the type of each record that crossed it, from
/// the client (`up`) and from the far end (`down`).
#[derive(Default)]
struct Seen {
    up: Mutex<Vec<u8>>,
    down: Mutex<Vec<u8>>,
}

impl Seen {
    fn ends(&self) -> (usize, usize) {
        let count = |kinds: &Mutex<Vec<u8>>| kinds.lock().unwrap().iter().filter(|k| **k == kind::END).count();
        (count(&self.up), count(&self.down))
    }
}

/// Copy records from `from` to `to`, noting each type in `seen`, until the
/// first record of type `cut`, which never passes.
async fn records<R, W>(from: &mut R, to: &mut W, seen: &Mutex<Vec<u8>>, cut: Option<u8>)
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
            if Some(record.kind()) == cut {
                return;
            }
            seen.lock().unwrap().push(record.kind());
            if to.write_all(&record.to_bytes().unwrap()).await.is_err() {
                return;
            }
        }
    }
}

/// A link through a stand-in relay that notes each record, and ends both
/// ways, with no word to either end, at the client's first record of type
/// `cut`, which is lost with the link.
fn relayed(seen: Arc<Seen>, cut: Option<u8>) -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        tokio::select! {
            _ = records(&mut cr, &mut fw, &seen.up, cut) => {}
            _ = records(&mut fr, &mut cw, &seen.down, None) => {}
        }
    });
    (client, far)
}

/// A session between a client of `settings` with `app`, and a far end of this
/// build with a target of its own; its first link is lost at the client's
/// first record of type `cut`, and its next links lose nothing.
struct Run {
    /// The far end's target, as the test plays it.
    target: DuplexStream,
    session: JoinHandle<Outcome>,
    notes: Arc<Mutex<Vec<Note>>>,
    seen: Arc<Seen>,
    /// Held for the whole test, as a node holds its keeper.
    keeper: Arc<Keeper<DuplexStream>>,
    found: Found,
}

async fn begin<A>(settings: Settings, cut: Option<u8>, app: A) -> Run
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let keeper = Arc::new(Keeper::new(Duration::from_secs(60)));
    let (links_tx, mut links_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let held = keeper.clone();
    // The far end's own settings: it names `end.v1` whatever they say.
    let far_settings = Settings::default();
    tokio::spawn(async move {
        while let Some(link) = links_rx.recv().await {
            let (keeper, targets) = (keeper.clone(), targets_tx.clone());
            tokio::spawn(async move {
                let Ok(accepted) = far::accept(link, Role::NODE, far_settings, &keeper.sessions, &mut OsEntropy).await
                else {
                    return;
                };
                if accepted.established().resumed {
                    let _ = keeper.run_resumed(accepted).await;
                } else {
                    let (target, played) = tokio::io::duplex(PIPE);
                    let _ = targets.send(played);
                    keeper.run_new(accepted, target).await;
                }
            });
        }
    });
    let seen = Arc::new(Seen::default());
    let (client_link, far_link) = relayed(seen.clone(), cut);
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let found = client.found().clone();
    let next_seen = seen.clone();
    let connect = move |_: &Ended| {
        let (client_link, far_link) = relayed(next_seen.clone(), None);
        let _ = links_tx.send(far_link);
        async move { Next::Link(client_link) }
    };
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let note = {
        let notes = notes.clone();
        move |n: Note| notes.lock().unwrap().push(n)
    };
    let session = tokio::spawn(async move { resume::run(client, app, connect, note, &mut OsEntropy).await });
    let target = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().unwrap();
    Run { target, session, notes, seen, keeper: held, found }
}

/// [`begin`] with an application that the test plays.
async fn start(settings: Settings, cut: Option<u8>) -> (DuplexStream, Run) {
    let (app, played) = tokio::io::duplex(PIPE);
    (app, begin(settings, cut, played).await)
}

fn ended_well(outcome: &Outcome) -> bool {
    matches!(outcome, Outcome::Layer(Ended { end: End::Closed(_) | End::LocalEnd, .. }))
}

/// Until the far end keeps no session: one that ended is forgotten at once.
async fn until_forgotten(keeper: &Keeper<DuplexStream>) {
    let deadline = tokio::time::Instant::now() + SOON;
    while keeper.kept() > 0 {
        assert!(tokio::time::Instant::now() < deadline, "the far end still keeps {} sessions", keeper.kept());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The issue's case: the client sends a request and ends its bytes; the
/// target reads to the end of its input, which the `END` gave it, and only
/// then answers with 1 MiB; the answer comes back whole, and the session
/// ends with the far end's `CLOSE`, as its target ended second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_side_whose_bytes_ended_still_gets_the_reply_then_the_session_ends() {
    let (app, run) = start(asking(), None).await;
    let agreed = matches!(&run.found, Found::Layer { features, .. } if half_close::agreed(features));
    assert!(agreed, "both sides named end.v1: {:?}", run.found);
    let request = pseudo_random(300_000, 61);
    let (mut app_r, mut app_w) = tokio::io::split(app);
    app_w.write_all(&request).await.unwrap();
    app_w.shutdown().await.unwrap();
    let (mut target_r, mut target_w) = tokio::io::split(run.target);
    let mut got = Vec::new();
    let read = tokio::time::timeout(SOON, target_r.read_to_end(&mut got)).await;
    read.expect("the target had the end of its input").unwrap();
    assert_eq!(Sha256::digest(&got), Sha256::digest(&request), "the request, whole");
    let reply = pseudo_random(1 << 20, 67);
    let answer = async {
        target_w.write_all(&reply).await.unwrap();
        target_w.shutdown().await.unwrap();
    };
    let mut back = Vec::new();
    let (_, read) = tokio::join!(answer, tokio::time::timeout(SOON, app_r.read_to_end(&mut back)));
    read.expect("the reply after the end came").unwrap();
    assert_eq!(back.len(), reply.len(), "each byte of the reply after the end");
    assert_eq!(Sha256::digest(&back), Sha256::digest(&reply));
    let outcome = tokio::time::timeout(LIMIT, run.session).await.unwrap().unwrap();
    assert!(ended_well(&outcome), "{outcome:?}");
    until_forgotten(&run.keeper).await;
    assert_eq!(run.seen.ends(), (1, 0), "the client's END, and the far end's CLOSE after it");
}

/// Both sides end their bytes at once: each gets the other's last bytes and
/// end, each `CLOSE` is due, and the session ends at both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ends_at_once_end_the_session_at_both_sides() {
    let (app, run) = start(asking(), None).await;
    let (mut app_r, mut app_w) = tokio::io::split(app);
    let (mut target_r, mut target_w) = tokio::io::split(run.target);
    let client_ends = async {
        app_w.write_all(b"the client's last").await.unwrap();
        app_w.shutdown().await.unwrap();
    };
    let target_ends = async {
        target_w.write_all(b"the target's last").await.unwrap();
        target_w.shutdown().await.unwrap();
    };
    tokio::join!(client_ends, target_ends);
    let (mut to_target, mut to_app) = (Vec::new(), Vec::new());
    let (a, b) = tokio::join!(
        tokio::time::timeout(SOON, target_r.read_to_end(&mut to_target)),
        tokio::time::timeout(SOON, app_r.read_to_end(&mut to_app))
    );
    a.expect("the client's end reached the target").unwrap();
    b.expect("the target's end reached the client").unwrap();
    assert_eq!((&to_target[..], &to_app[..]), (&b"the client's last"[..], &b"the target's last"[..]));
    let outcome = tokio::time::timeout(LIMIT, run.session).await.unwrap().unwrap();
    assert!(ended_well(&outcome), "{outcome:?}");
    until_forgotten(&run.keeper).await;
}

/// The relay loses the client's `END` with its link: the client resumes, its
/// `END` goes again after the bytes that the resume sends again, the target
/// gets the end of its input, and its answer still comes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_end_that_its_link_lost_comes_again_after_a_resume() {
    let (app, run) = start(asking(), Some(kind::END)).await;
    let request = pseudo_random(100_000, 71);
    let (mut app_r, mut app_w) = tokio::io::split(app);
    app_w.write_all(&request).await.unwrap();
    app_w.shutdown().await.unwrap();
    let (mut target_r, mut target_w) = tokio::io::split(run.target);
    let mut got = Vec::new();
    let read = tokio::time::timeout(SOON, target_r.read_to_end(&mut got)).await;
    read.expect("the END came again on the next link").unwrap();
    assert_eq!(Sha256::digest(&got), Sha256::digest(&request));
    target_w.write_all(b"the answer").await.unwrap();
    target_w.shutdown().await.unwrap();
    let mut back = Vec::new();
    tokio::time::timeout(SOON, app_r.read_to_end(&mut back)).await.expect("the answer").unwrap();
    assert_eq!(back, b"the answer");
    let outcome = tokio::time::timeout(LIMIT, run.session).await.unwrap().unwrap();
    assert!(ended_well(&outcome), "{outcome:?}");
    let notes = run.notes.lock().unwrap().clone();
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "{notes:?}");
    assert_eq!(run.seen.ends(), (1, 0), "the lost END passed no relay; the next link carried it once");
}

/// A client that does not ask keeps the old end against a far end of this
/// build: its end of its bytes is a `CLOSE`, which ends the session though
/// the target still holds its own bytes open, and no `END` crosses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_does_not_ask_ends_the_session_at_the_end_of_its_bytes() {
    let (app, run) = start(Settings::default(), None).await;
    let agreed = matches!(&run.found, Found::Layer { features, .. } if half_close::agreed(features));
    assert!(!agreed, "the client did not ask: {:?}", run.found);
    let (_app_r, mut app_w) = tokio::io::split(app);
    app_w.write_all(b"request").await.unwrap();
    app_w.shutdown().await.unwrap();
    let (mut target_r, _target_w) = tokio::io::split(run.target);
    let mut got = Vec::new();
    tokio::time::timeout(SOON, target_r.read_to_end(&mut got)).await.expect("the target's end").unwrap();
    assert_eq!(got, b"request");
    let outcome = tokio::time::timeout(LIMIT, run.session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Outcome::Layer(Ended { end: End::LocalEnd, .. })), "{outcome:?}");
    until_forgotten(&run.keeper).await;
    assert_eq!(run.seen.ends(), (0, 0), "no END either way");
}

/// An application whose read fails: it is gone, which is no end of one
/// direction.
struct Gone;

impl AsyncRead for Gone {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::other("the application is gone")))
    }
}

/// With both sides naming `end.v1`, a read that fails still ends the whole
/// session with `CLOSE`, at once: the target's input ends while it holds its
/// own bytes open, and no `END` goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_that_fails_ends_the_whole_session() {
    let run = begin(asking(), None, tokio::io::join(Gone, tokio::io::sink())).await;
    let (mut target_r, _target_w) = tokio::io::split(run.target);
    let mut got = Vec::new();
    tokio::time::timeout(SOON, target_r.read_to_end(&mut got)).await.expect("the target's end").unwrap();
    let outcome = tokio::time::timeout(LIMIT, run.session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Outcome::Layer(Ended { end: End::LocalEnd, .. })), "{outcome:?}");
    until_forgotten(&run.keeper).await;
    assert_eq!(run.seen.ends(), (0, 0), "a CLOSE, not an END");
}

/// The far end's records, as a far end of an older build gives them: a real
/// `GREETING` with `features`, which name no `end.v1`, then an `ACCEPT` of a
/// new session once the client's `OPEN` came.
async fn greet_and_accept(far: &mut DuplexStream, features: &[&str], decoder: &mut Decoder) {
    let hello = Hello {
        version: 1,
        role: Role::NODE,
        nonce: Nonce([7; 32]),
        features: features.iter().map(|f| f.to_string()).collect(),
    };
    far.write_all(&Record::Greeting(hello).to_bytes().unwrap()).await.unwrap();
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

/// A client that asks, against a far end of an older build that names no
/// `end.v1`: no `END` reaches it, which it could not decode; the client's
/// bytes come, then its `CLOSE`, as before, and the session ends when the
/// far end answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_end_that_names_no_end_gets_close_after_the_bytes_as_before() {
    let (client_link, mut far) = tokio::io::duplex(PIPE);
    let script = tokio::spawn(async move {
        let mut decoder = Decoder::new();
        greet_and_accept(&mut far, &["replay.v1", "heartbeat.v1"], &mut decoder).await;
        let (mut kinds, mut got) = (Vec::new(), Vec::new());
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            while let Some(record) = decoder.next().expect("records that an older far end decodes") {
                kinds.push(record.kind());
                match record {
                    Record::Data { bytes, .. } => got.extend(bytes),
                    Record::Close { .. } => {
                        far.write_all(&Record::Close { reason: String::new() }.to_bytes().unwrap()).await.unwrap();
                        return (kinds, got);
                    }
                    _ => {}
                }
            }
            let n = far.read(&mut buf).await.unwrap();
            assert!(n > 0, "the client ended the link before its CLOSE: {kinds:?}");
            decoder.push(&buf[..n]);
        }
    });
    let client = client::start(client_link, Ask::New, asking(), &mut OsEntropy).await.unwrap();
    let agreed = matches!(client.found(), Found::Layer { features, .. } if half_close::agreed(features));
    assert!(!agreed, "the far end named none: {}", client.found());
    let (mut app, played) = tokio::io::duplex(PIPE);
    let run = tokio::spawn(client.run(played));
    app.write_all(b"request").await.unwrap();
    app.shutdown().await.unwrap();
    let (kinds, got) = tokio::time::timeout(LIMIT, script).await.unwrap().unwrap();
    assert_eq!(got, b"request");
    assert!(!kinds.contains(&kind::END), "{kinds:?}");
    assert_eq!(kinds.last(), Some(&kind::CLOSE), "{kinds:?}");
    let outcome = tokio::time::timeout(LIMIT, run).await.unwrap().unwrap();
    assert!(matches!(&outcome, Outcome::Layer(Ended { end: End::LocalEnd, .. })), "{outcome:?}");
}
