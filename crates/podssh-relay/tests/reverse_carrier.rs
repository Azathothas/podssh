//! A carrier (T-595): podssh's own node (`reverse::serve`) on one end of a
//! pair of pipes, and the relay role's side of its socket (T-427), in the
//! process of the carrier's client, on the other, with each operator's leg a
//! pipe to that role. Two sessions of 2 MiB each way carry their bytes whole,
//! and the client's Close ends the node with 1000; a stream that the client
//! was given has one life, and one that it started is started again for the
//! next leg; the role tells when its node left the stream (T-596); a node
//! that has not read the stream gets no `open`, only the role's `hello`; and
//! the role takes no node's path.
#![cfg(feature = "serve")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::relay::Relay;
use podssh_relay::reverse::{self, operator, End, Handler, Opening, OperatorConfig, OperatorLimits, Outcome};
use podssh_relay::reverse::{RelayClose, SessionId, Settings, Wire};
use podssh_relay::serve::reverse::carrier::{self, Again, Door, Link, Role, NAME};
use podssh_ws::client::ConnectError;
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

const MIB: usize = 1 << 20;
/// The bound on each step of a test.
const LIMIT: Duration = Duration::from_secs(30);
/// Each direction of the stream: small, so that it fills.
const STREAM: usize = 64 * 1024;

/// Bytes from a fixed xorshift, so that a byte out of place shows.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Each session echoes what it takes.
struct Echo;

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async {
            let (ours, theirs) = tokio::io::duplex(256 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(ours)
        })
    }
}

/// Each session stays open: its local side never ends nor speaks, and
/// `opened` hears that the node opened it.
struct Hold {
    opened: Arc<tokio::sync::Notify>,
}

impl Handler for Hold {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        let opened = self.opened.clone();
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _held = theirs;
                std::future::pending::<()>().await
            });
            opened.notify_one();
            Ok(ours)
        })
    }
}

/// podssh's node on `stream`, as `podssh node --carrier` runs it: its first
/// frame, then its sessions until the stream ends.
async fn node<S: AsyncRead + AsyncWrite + Send + 'static>(stream: S) -> End {
    node_with(stream, Arc::new(Echo)).await
}

/// [`node`] with the sessions of `handler`.
async fn node_with<S: AsyncRead + AsyncWrite + Send + 'static, H: Handler>(stream: S, handler: Arc<H>) -> End {
    let session = carrier::node_socket(stream);
    carrier::greet(&session).await.expect("the node's first frame");
    let mut stop = Box::pin(std::future::pending::<()>());
    reverse::serve(session, handler, Settings::default(), &mut stop).await
}

/// A node on a new pipe: its task, and the client's end of the pipe.
fn new_node() -> (JoinHandle<End>, Link) {
    let (near, far) = tokio::io::duplex(STREAM);
    let link: Link = Box::new(near);
    (tokio::spawn(node(far)), link)
}

/// The role over `link`, with what it says in `said`.
fn door_over(link: Link, again: Option<Again>, said: &Arc<Mutex<Vec<String>>>) -> Door {
    let said = said.clone();
    let events: podssh_relay::serve::Events = Box::new(move |line: &str| said.lock().unwrap().push(line.into()));
    let role = Role::new("a pipe of the test", again, Some(events)).expect("a role");
    role.attach(link).expect("the node's socket");
    Door::of(role)
}

/// An operator's session through `door`: `sent` goes up and as much comes
/// back, then the input ends. Its outcome, and what came back.
async fn operate(door: Door, sent: Vec<u8>, limit: Duration) -> (Result<Outcome, ConnectError>, Vec<u8>) {
    let relay = Relay { host: NAME.into(), port: 0 };
    let config = OperatorConfig {
        relay: &relay,
        name: NAME,
        connect_token: "",
        trust: &Trust::Default,
        proxy: &ProxyChoice::Direct,
        timeout: limit,
        limits: OperatorLimits::default(),
        wire: Wire::Carrier(door),
    };
    let (app, leg) = tokio::io::duplex(64 * 1024);
    let (mut r, mut w) = tokio::io::split(app);
    let want = sent.len();
    let carry = async {
        let writing = async {
            // A leg that never opened takes nothing.
            let _ = w.write_all(&sent).await;
            w
        };
        let reading = async {
            let (mut got, mut buf) = (Vec::new(), vec![0u8; 16 * 1024]);
            while got.len() < want {
                match r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            got
        };
        let (mut w, got) = tokio::join!(writing, reading);
        let _ = w.shutdown().await;
        got
    };
    tokio::join!(operator::run(&config, leg), carry)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sessions_of_2_mib_each_way_cross_a_carrier_whole() {
    let said = Arc::new(Mutex::new(Vec::new()));
    let (node, link) = new_node();
    let door = door_over(link, None, &said);
    let ((a, got_a), (b, got_b)) = tokio::time::timeout(4 * LIMIT, async {
        tokio::join!(operate(door, pattern(2 * MIB, 1), LIMIT), operate(door, pattern(2 * MIB, 2), LIMIT))
    })
    .await
    .expect("in time");
    let (a, b) = (a.expect("leg a"), b.expect("leg b"));
    assert_eq!(Sha256::digest(&got_a), Sha256::digest(pattern(2 * MIB, 1)), "session a: {a:?}");
    assert_eq!(Sha256::digest(&got_b), Sha256::digest(pattern(2 * MIB, 2)), "session b: {b:?}");
    assert!(a.is_success() && b.is_success(), "{a:?} {b:?}");
    // The client's end: the node hears its Close, and ends with 1000.
    door.role().close(LIMIT).await;
    let end = tokio::time::timeout(LIMIT, node).await.expect("the node ends").expect("the node's task");
    assert!(matches!(&end, End::Closed(RelayClose { code: 1000, .. })), "{end:?}");
    let said = said.lock().unwrap();
    assert!(!said.iter().any(|l| l.starts_with("reverse node closed")), "no fault of the node: {said:?}");
    assert_eq!(said.iter().filter(|l| *l == "reverse open").count(), 2, "{said:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_that_the_client_was_given_has_one_life() {
    let said = Arc::new(Mutex::new(Vec::new()));
    let (node, link) = new_node();
    let door = door_over(link, None, &said);
    let (first, got) = operate(door, pattern(64 * 1024, 3), LIMIT).await;
    assert!(first.expect("the first leg").is_success(), "{got:?}");
    // The stream ends: its node goes, and its end of the pipe with it.
    node.abort();
    let deadline = tokio::time::Instant::now() + LIMIT;
    let refused = loop {
        match operate(door, Vec::new(), LIMIT).await.0 {
            Err(e) => break e,
            Ok(_) => assert!(tokio::time::Instant::now() < deadline, "a leg still opened"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // Final, as a new leg would meet it again.
    assert!(matches!(&refused, ConnectError::Refused { status: 410, .. }), "{refused:?}");
    assert!(refused.to_string().contains("a pipe of the test"), "{refused}");
}

/// The role says whether its node is joined, so that a client of a stream
/// with one life ends with it (T-596): at once after the attach, and no more
/// once the stream ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_role_says_when_its_node_left_the_stream() {
    let said = Arc::new(Mutex::new(Vec::new()));
    let (node, link) = new_node();
    let door = door_over(link, None, &said);
    assert!(door.role().joined(), "the node's socket, joined at the attach");
    node.abort();
    let left = tokio::time::timeout(Duration::from_secs(5), async {
        while door.role().joined() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(left.is_ok(), "the role tells the end of the stream: {:?}", said.lock().unwrap());
}

/// A node that goes while a session of it is open takes the stream with
/// it: its writer held the stream while the session's tasks lived, so the
/// role never saw the end, and each leg after waited for a node that read
/// nothing (T-601; the macOS runner's order of the test before).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_goes_with_a_session_open_ends_the_stream() {
    let said = Arc::new(Mutex::new(Vec::new()));
    let opened = Arc::new(tokio::sync::Notify::new());
    let (near, far) = tokio::io::duplex(STREAM);
    let node = tokio::spawn(node_with(far, Arc::new(Hold { opened: opened.clone() })));
    let door = door_over(Box::new(near), None, &said);
    let leg = tokio::spawn(operate(door, Vec::new(), LIMIT));
    tokio::time::timeout(LIMIT, opened.notified()).await.expect("the node opens the session");
    node.abort();
    let gone = tokio::time::timeout(Duration::from_secs(5), async {
        while !said.lock().unwrap().iter().any(|l| l == "reverse node gone") {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(gone.is_ok(), "the role sees the stream end: {:?}", said.lock().unwrap());
    let refused = operate(door, Vec::new(), Duration::from_secs(5)).await.0;
    assert!(matches!(&refused, Err(ConnectError::Refused { status: 410, .. })), "{refused:?}");
    leg.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_that_the_client_started_is_started_again_for_the_next_leg() {
    let said = Arc::new(Mutex::new(Vec::new()));
    let (first_node, link) = new_node();
    let starts = Arc::new(AtomicUsize::new(0));
    let again: Again = {
        let starts = starts.clone();
        Box::new(move || -> Result<Link, String> {
            starts.fetch_add(1, Ordering::SeqCst);
            // The new node's task goes on by itself.
            let (_node, link) = new_node();
            Ok(link)
        })
    };
    let door = door_over(link, Some(again), &said);
    let (first, _) = operate(door, pattern(64 * 1024, 4), LIMIT).await;
    assert!(first.expect("the first leg").is_success());
    first_node.abort();
    // The first leg that finds the stream ended starts it again; one that
    // crossed the end may fail, as a lost leg does, and the next one goes.
    let deadline = tokio::time::Instant::now() + LIMIT;
    let got = loop {
        let (outcome, got) = operate(door, pattern(MIB, 6), LIMIT).await;
        if starts.load(Ordering::SeqCst) > 0 && outcome.as_ref().is_ok_and(Outcome::is_success) {
            break got;
        }
        assert!(tokio::time::Instant::now() < deadline, "no leg on a new stream: {outcome:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(Sha256::digest(&got), Sha256::digest(pattern(MIB, 6)));
    assert_eq!(starts.load(Ordering::SeqCst), 1, "one new stream for the one that ended");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_has_not_read_the_stream_gets_its_hello_and_no_open() {
    let said = Arc::new(Mutex::new(Vec::new()));
    let (near, mut far) = tokio::io::duplex(STREAM);
    let door = door_over(Box::new(near), None, &said);
    let (outcome, _) = operate(door, Vec::new(), Duration::from_millis(300)).await;
    let refused = outcome.expect_err("no node read the stream");
    assert!(matches!(&refused, ConnectError::Timeout { .. }), "{refused:?}");
    // What the role wrote to the stream: its hello alone.
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(LIMIT, far.read(&mut buf)).await.expect("the role's hello").expect("a read");
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.contains("\"type\":\"hello\""), "{text}");
    assert!(!text.contains("\"open\""), "{text}");
}

#[tokio::test]
async fn the_role_of_a_carrier_takes_no_node_s_path() {
    let said = Arc::new(Mutex::new(Vec::new()));
    let (near, _far) = tokio::io::duplex(STREAM);
    let door = door_over(Box::new(near), None, &said);
    let path = podssh_relay::relay::node_path(NAME).unwrap();
    let refused = door.role().open(&path, LIMIT).await.expect_err("a node's path");
    assert!(matches!(&refused, ConnectError::Config(why) if why.contains("operators' legs alone")), "{refused:?}");
}
