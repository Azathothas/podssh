//! The node's far end of the resumable layer (T-153), called as the node's
//! serve loop calls a handler: each session of the relay is one link. A
//! session whose links are cut resumes on new ones, with one connection to
//! the target for the whole session; a target that cannot be reached, and a
//! node past its budget, end the session with the reason. A session whose
//! target ended, and whose client went away before it answered the `CLOSE`,
//! holds nothing of the budget, and a resume of it gets the `CLOSE` (T-586).
#![cfg(feature = "pair")]

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use podssh_relay::reverse::{Handler, Layered, Opening, SessionId as RelayId};
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::resume::{self, Next};
use podssh_relay::session::{Ask, Decoder, End, Ended, OsEntropy, Record, Settings};

const PIPE: usize = 256 * 1024;
const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(60);
/// How long a target of [`Byes`] waits after its `bye`: more than the
/// client's 200 ms before it acknowledges fewer than 64 KiB.
const ACKED: Duration = Duration::from_millis(600);

/// A target that echoes each byte, or refuses to open; it counts its opens.
struct Echo {
    opened: Arc<AtomicUsize>,
    refuse: bool,
}

/// Each byte of `theirs` back, until its end.
async fn echo(mut theirs: DuplexStream) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match theirs.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if theirs.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: RelayId) -> Opening<DuplexStream> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        let refuse = self.refuse;
        Box::pin(async move {
            if refuse {
                return Err("connection refused".to_string());
            }
            let (ours, theirs) = tokio::io::duplex(PIPE);
            tokio::spawn(echo(theirs));
            Ok(ours)
        })
    }
}

/// For its first `byes` sessions, a target that says `bye` and ends
/// [`ACKED`] later, as sshd ends after a command; an echo for each after
/// them. It counts its opens.
struct Byes {
    opened: Arc<AtomicUsize>,
    byes: usize,
}

impl Handler for Byes {
    type Stream = DuplexStream;

    fn open(&self, _id: RelayId) -> Opening<DuplexStream> {
        let bye = self.opened.fetch_add(1, Ordering::SeqCst) < self.byes;
        Box::pin(async move {
            let (ours, mut theirs) = tokio::io::duplex(PIPE);
            tokio::spawn(async move {
                if !bye {
                    return echo(theirs).await;
                }
                let _ = theirs.write_all(b"bye").await;
                tokio::time::sleep(ACKED).await;
                drop(theirs);
            });
            Ok(ours)
        })
    }
}

/// `done` within [`LIMIT`], looked at each 20 ms.
async fn until(what: &str, done: impl Fn() -> bool) {
    let looked = async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(LIMIT, looked).await.unwrap_or_else(|_| panic!("not within {LIMIT:?}: {what}"));
}

fn relay_id(n: u8) -> RelayId {
    RelayId::parse(format!("{:032x}", n).as_bytes()).unwrap()
}

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

/// One session of the relay: the handler's stream on one side, the
/// client's end returned, cut after `cut` bytes both ways together.
async fn session_of<H: Handler<Stream = DuplexStream>>(handler: &H, id: RelayId, cut: Option<usize>) -> DuplexStream {
    let node_side = handler.open(id).await.unwrap();
    let (client, relay_client) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let left = AtomicI64::new(cut.map_or(i64::MAX, |c| c as i64));
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut nr, mut nw) = tokio::io::split(node_side);
        tokio::select! {
            _ = copy_until(&mut cr, &mut nw, &left) => {}
            _ = copy_until(&mut nr, &mut cw, &left) => {}
        }
    });
    client
}

/// Which `CLOSE` a link loses.
#[derive(Clone, Copy)]
enum Lost {
    /// The client's answer to the node's: the client went away, as an
    /// operator that its OpenSSH hung up did (GitHub #112).
    ClientsAnswer,
    /// The node's own: the client never heard it.
    NodesClose,
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

/// One session of the relay whose link ends, with no word to either end,
/// where the `CLOSE` that `lost` names would pass.
async fn session_losing<H: Handler<Stream = DuplexStream>>(handler: &H, id: RelayId, lost: Lost) -> DuplexStream {
    let node_side = handler.open(id).await.unwrap();
    let (client, relay_client) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut nr, mut nw) = tokio::io::split(node_side);
        match lost {
            Lost::ClientsAnswer => tokio::select! {
                _ = until_close(&mut cr, &mut nw) => {}
                _ = tokio::io::copy(&mut nr, &mut cw) => {}
            },
            Lost::NodesClose => tokio::select! {
                _ = tokio::io::copy(&mut cr, &mut nw) => {}
                _ = until_close(&mut nr, &mut cw) => {}
            },
        }
    });
    client
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_session_resumes_with_one_connection_to_the_target() {
    let opened = Arc::new(AtomicUsize::new(0));
    let settings = Settings::default();
    let node = Arc::new(Layered::new(Echo { opened: opened.clone(), refuse: false }, settings, 64 * MIB));
    let first = session_of(node.as_ref(), relay_id(1), Some(3 * MIB)).await;
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await.unwrap();

    let cuts = Arc::new(std::sync::Mutex::new(vec![Some(5 * MIB), None].into_iter()));
    let ids = Arc::new(AtomicUsize::new(2));
    let connect = {
        let node = node.clone();
        move |_: &Ended| {
            let (node, cut) = (node.clone(), cuts.lock().unwrap().next().flatten());
            let id = relay_id(ids.fetch_add(1, Ordering::SeqCst) as u8);
            async move { Next::Link(session_of(node.as_ref(), id, cut).await) }
        }
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, |_| {}, &mut OsEntropy).await });

    let sent = (0..8 * MIB).map(|i| (i * 31 % 251) as u8).collect::<Vec<u8>>();
    let (mut r, mut w) = tokio::io::split(app);
    let writer = {
        let sent = sent.clone();
        tokio::spawn(async move {
            w.write_all(&sent).await.unwrap();
            w
        })
    };
    let mut back = vec![0u8; sent.len()];
    tokio::time::timeout(LIMIT, r.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(Sha256::digest(&back), Sha256::digest(&sent), "the echo came back whole across the cuts");
    let mut w = writer.await.unwrap();
    w.shutdown().await.unwrap();

    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    assert!(matches!(&outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd)), "{outcome:?}");
    assert_eq!(opened.load(Ordering::SeqCst), 1, "a resume reuses the session's connection to the target");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_that_cannot_be_reached_ends_the_session_with_the_reason() {
    let settings = Settings::default();
    let node = Layered::new(Echo { opened: Arc::default(), refuse: true }, settings, 64 * MIB);
    let link = session_of(&node, relay_id(1), None).await;
    let client = client::start(link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let (_app, app_end) = tokio::io::duplex(PIPE);
    let outcome = tokio::time::timeout(LIMIT, client.run(app_end)).await.unwrap();
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    let End::Closed(reason) = &ended.end else { panic!("{ended:?}") };
    assert_eq!(reason, "the node could not reach its target: connection refused");
    assert_eq!(node.kept(), 0, "the session is forgotten");
}

/// A node keeps a whole replay buffer for each session that it keeps: a new
/// session past its budget ends with the reason, and the others go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_past_its_replay_budget_ends_a_new_session() {
    let settings = Settings::default();
    let budget = 2 * settings.replay_capacity;
    let node = Layered::new(Echo { opened: Arc::default(), refuse: false }, settings, budget);
    let mut apps = Vec::new();
    for n in 1..=2 {
        let link = session_of(&node, relay_id(n), None).await;
        let client = client::start(link, Ask::New, settings, &mut OsEntropy).await.unwrap();
        let (app, app_end) = tokio::io::duplex(PIPE);
        tokio::spawn(client.run(app_end));
        apps.push(app);
    }
    // Both run: an echo through each.
    for app in &mut apps {
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        tokio::time::timeout(LIMIT, app.read_exact(&mut got)).await.unwrap().unwrap();
        assert_eq!(&got, b"ping");
    }
    let link = session_of(&node, relay_id(3), None).await;
    let client = client::start(link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let (_app, app_end) = tokio::io::duplex(PIPE);
    let outcome = tokio::time::timeout(LIMIT, client.run(app_end)).await.unwrap();
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    let End::Closed(reason) = &ended.end else { panic!("{ended:?}") };
    // What holds the budget, and what changes it (T-586).
    let head = "this node keeps 2 resumable sessions (8 MiB of replay buffers): 2 with a link, none waiting for its \
                client; --resume-deadline and PODSSH_REPLAY_BUFFER of the node change its budget";
    assert_eq!(reason, head);
    assert_eq!(node.kept(), 2);
}

/// GitHub #112 (T-586): a session whose target ended, and whose client had
/// each byte but went away before it answered the `CLOSE`, holds nothing of
/// the budget. With room for 2 sessions, two such sessions, then two that
/// run at once, are each admitted; a fifth is refused, with the counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_whose_target_ended_holds_only_its_unacknowledged_bytes() {
    let settings = Settings::default();
    let opened = Arc::new(AtomicUsize::new(0));
    let node = Layered::new(Byes { opened: opened.clone(), byes: 2 }, settings, 2 * settings.replay_capacity);
    for n in 1..=2 {
        let link = session_losing(&node, relay_id(n), Lost::ClientsAnswer).await;
        let client = client::start(link, Ask::New, settings, &mut OsEntropy).await.unwrap();
        let (mut app, app_end) = tokio::io::duplex(PIPE);
        let run = tokio::spawn(client.run(app_end));
        let mut got = Vec::new();
        tokio::time::timeout(LIMIT, app.read_to_end(&mut got)).await.unwrap().unwrap();
        assert_eq!(got, b"bye", "session {n}");
        tokio::time::timeout(LIMIT, run).await.unwrap().unwrap();
    }
    // Each link ended with the node's `CLOSE` unanswered.
    until("the two sessions keep their ids alone", || node.kept() == 0 && node.closed() == 2).await;
    let mut apps = Vec::new();
    for n in 3..=4 {
        let link = session_of(&node, relay_id(n), None).await;
        let client = client::start(link, Ask::New, settings, &mut OsEntropy).await.unwrap();
        let (mut app, app_end) = tokio::io::duplex(PIPE);
        tokio::spawn(client.run(app_end));
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        tokio::time::timeout(LIMIT, app.read_exact(&mut got)).await.unwrap().expect("admitted, and echoed");
        assert_eq!(&got, b"ping", "session {n}");
        apps.push(app);
    }
    // The budget still holds: two live sessions fill it.
    let link = session_of(&node, relay_id(5), None).await;
    let client = client::start(link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let (_app, app_end) = tokio::io::duplex(PIPE);
    let outcome = tokio::time::timeout(LIMIT, client.run(app_end)).await.unwrap();
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    let End::Closed(reason) = &ended.end else { panic!("{ended:?}") };
    assert!(
        reason.starts_with("this node keeps 2 resumable sessions (8 MiB of replay buffers): 2 with a link"),
        "{reason}"
    );
    assert_eq!(opened.load(Ordering::SeqCst), 4, "the refused session dialled nothing");
}

/// The node's `CLOSE` is lost with the link, after the client acknowledged
/// each byte: the node keeps the session's id alone, and the client's resume
/// gets the `CLOSE`, as a resume of a session that ended on its old link
/// does, with no new dial of the target (T-586).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resume_of_a_closed_session_gets_its_close() {
    let settings = Settings::default();
    let opened = Arc::new(AtomicUsize::new(0));
    let node = Arc::new(Layered::new(Byes { opened: opened.clone(), byes: 1 }, settings, 64 * MIB));
    let first = session_losing(node.as_ref(), relay_id(1), Lost::NodesClose).await;
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let ids = Arc::new(AtomicUsize::new(2));
    let connect = {
        let node = node.clone();
        move |_: &Ended| {
            let node = node.clone();
            let id = relay_id(ids.fetch_add(1, Ordering::SeqCst) as u8);
            async move {
                // The node has seen its link end before the resume comes.
                until("the session keeps its id alone", || node.closed() == 1).await;
                Next::Link(session_of(node.as_ref(), id, None).await)
            }
        }
    };
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, |_| {}, &mut OsEntropy).await });
    let mut got = Vec::new();
    tokio::time::timeout(LIMIT, app.read_to_end(&mut got)).await.unwrap().unwrap();
    assert_eq!(got, b"bye");
    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    let closed = matches!(&outcome, Outcome::Layer(ended) if matches!(&ended.end, End::Closed(why) if why.is_empty()));
    assert!(closed, "the session ends with the node's CLOSE: {outcome:?}");
    assert_eq!(opened.load(Ordering::SeqCst), 1, "the resume dialled nothing");
    assert_eq!((node.kept(), node.closed()), (0, 1), "the id waits for its deadline, with nothing else");
}
