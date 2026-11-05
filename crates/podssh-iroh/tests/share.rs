//! The sessions of one process to one node over the iroh road (T-666), on
//! this machine's loopback: iroh's relay server, reached through a stand-in
//! CONNECT proxy, and a far end of podssh. A second session of the process
//! takes a lease of the dialer that the first made, and a new stream of its
//! one connection, in a copy's lane: the far end sees one connection and two
//! sessions, each of which carries its bytes, and the connection and its
//! endpoint close with the last lease. A copy's stream goes below a
//! terminal's at each end that reads its lane, and a far end of before
//! takes it as any session.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use iroh::{Endpoint, EndpointAddr, PublicKey, RelayUrl, SecretKey};
use podssh_iroh::{share, Dialer, Lane, Options, Stream, ALPN, ALPN_LANES};
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::{Ask, OsEntropy, Settings};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use common::{options, proxy, relay, LIMIT};

const PIPE: usize = 256 * 1024;
const MIB: usize = 1 << 20;

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

/// Write `out` and read as many bytes at once, then end the bytes.
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

/// A far end of podssh that counts its connections (each key that its
/// allowlist is asked about) and its sessions (each target that it opens),
/// and hands each target to the test.
struct Far {
    endpoint: Endpoint,
    connections: Arc<AtomicUsize>,
    sessions: Arc<AtomicUsize>,
    targets: mpsc::UnboundedReceiver<DuplexStream>,
}

async fn far(relay: &RelayUrl, proxy: SocketAddr, client: PublicKey) -> Far {
    let endpoint = podssh_iroh::bind(&options(relay, proxy, true)).await.expect("the far end");
    tokio::time::timeout(LIMIT, endpoint.online()).await.expect("the far end has its home relay");
    let (tx, targets) = mpsc::unbounded_channel::<DuplexStream>();
    let sessions = Arc::new(AtomicUsize::new(0));
    let opened = sessions.clone();
    let open = move || {
        let (tx, opened) = (tx.clone(), opened.clone());
        async move {
            opened.fetch_add(1, Ordering::SeqCst);
            let (target, test_end) = tokio::io::duplex(PIPE);
            tx.send(test_end).map_err(|e| e.to_string())?;
            Ok::<_, String>(target)
        }
    };
    let connections = Arc::new(AtomicUsize::new(0));
    let asked = connections.clone();
    let admit = move |key: &PublicKey| {
        asked.fetch_add(1, Ordering::SeqCst);
        *key == client
    };
    tokio::spawn(podssh_iroh::far::serve(endpoint.clone(), Settings::default(), 64 * MIB, open, admit));
    Far { endpoint, connections, sessions, targets }
}

/// The dialer of the client of `secret` to `node`, on an endpoint of its own.
async fn dialer(relay: &RelayUrl, proxy: SocketAddr, secret: &SecretKey, node: EndpointAddr) -> Result<Dialer, String> {
    let options = Options { secret: Some(secret.clone()), ..options(relay, proxy, false) };
    let endpoint = podssh_iroh::bind(&options).await.map_err(|e| e.to_string())?;
    Ok(Dialer::new(endpoint, node))
}

/// A session of the layer on `stream`: the app's end, and its run.
async fn session(stream: Stream) -> (DuplexStream, JoinHandle<Outcome>) {
    let mut entropy = OsEntropy;
    let started = client::start(stream, Ask::New, Settings::default(), &mut entropy);
    let started = tokio::time::timeout(LIMIT, started).await.unwrap().expect("the layer's handshake");
    let (app, app_end) = tokio::io::duplex(PIPE);
    (app, tokio::spawn(started.run(app_end)))
}

/// The far end's next target.
async fn next(targets: &mut mpsc::UnboundedReceiver<DuplexStream>) -> DuplexStream {
    tokio::time::timeout(LIMIT, targets.recv()).await.unwrap().expect("a session's target")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sessions_of_one_process_share_one_connection_on_two_streams() {
    let (relay_url, _relay) = relay().await;
    let (proxy, _) = proxy(relay_url.port().unwrap()).await;
    let secret = SecretKey::from_bytes(&[7; 32]);
    let mut far = far(&relay_url, proxy, secret.public()).await;
    let node = EndpointAddr::new(far.endpoint.id()).with_relay_url(relay_url.clone());

    // A terminal's session, then a copy's beside it, as one process makes them.
    let made = AtomicUsize::new(0);
    let make = |secret: SecretKey| {
        made.fetch_add(1, Ordering::SeqCst);
        let (relay_url, node) = (relay_url.clone(), node.clone());
        async move { dialer(&relay_url, proxy, &secret, node).await }
    };
    let terminal = share::lease(secret.public(), node.id, || make(secret.clone())).await;
    let terminal = terminal.expect("the terminal's lease");
    let copy = Lane::Bulk.scope(share::lease(secret.public(), node.id, || make(secret.clone())));
    let copy = copy.await.expect("the copy's lease");
    assert_eq!(made.load(Ordering::SeqCst), 1, "the copy's lease made no endpoint of its own");
    assert!(!terminal.joined() && copy.joined());
    assert!(std::ptr::eq(terminal.dialer(), copy.dialer()), "both leases hold one dialer");
    assert_eq!((terminal.lane(), copy.lane()), (Lane::Interactive, Lane::Bulk));
    assert_eq!(copy.holders(), 2);

    // A stream of each lease, each a session of the layer.
    let first = terminal.link().await.expect("the terminal's stream");
    let second = copy.link().await.expect("the copy's stream");
    assert_eq!((first.priority(), second.priority()), (Some(0), Some(-1)), "the copy's bytes go after");
    let id = terminal.dialer().connection_id().await.expect("a connection");
    let (terminal_app, terminal_run) = session(first).await;
    let terminal_target = next(&mut far.targets).await;
    let (copy_app, copy_run) = session(second).await;
    let copy_target = next(&mut far.targets).await;

    // The copy carries 4 MiB each way while the terminal's key and echo go.
    let (up, down) = (pseudo_random(4 * MIB, 0x0666), pseudo_random(4 * MIB, 0x6660));
    let copied = async { tokio::join!(exchange(copy_target, down.clone()), exchange(copy_app, up.clone())) };
    let typed = async {
        tokio::join!(exchange(terminal_target, b"echo".to_vec()), exchange(terminal_app, b"key!".to_vec()))
    };
    let both = tokio::time::timeout(LIMIT, async { tokio::join!(copied, typed) }).await;
    let ((at_target, at_client), (key, echo)) = both.expect("each session's bytes within the limit");
    assert_eq!(Sha256::digest(&at_target), Sha256::digest(&up), "the copy's bytes reached the node whole");
    assert_eq!(Sha256::digest(&at_client), Sha256::digest(&down), "the node's bytes reached the copy whole");
    assert_eq!((key.as_slice(), echo.as_slice()), (&b"key!"[..], &b"echo"[..]));
    for run in [terminal_run, copy_run] {
        tokio::time::timeout(LIMIT, run).await.expect("the session ends").expect("its task");
    }

    // One connection, two sessions: the second login opened no connection.
    assert_eq!(far.connections.load(Ordering::SeqCst), 1, "the far end saw one connection");
    assert_eq!(far.sessions.load(Ordering::SeqCst), 2, "and two sessions on it");
    assert_eq!(copy.dialer().connection_id().await, Some(id), "the same connection, still open");

    // Another key of this client is another endpoint, which nothing shares.
    let other = SecretKey::from_bytes(&[8; 32]);
    let alone = share::lease(other.public(), node.id, || make(other.clone())).await.expect("another key's lease");
    assert!(!alone.joined() && !std::ptr::eq(alone.dialer(), terminal.dialer()));
    assert_eq!((made.load(Ordering::SeqCst), alone.holders()), (2, 1));
    alone.release().await;

    // The connection and the endpoint close with the last lease alone.
    let endpoint = terminal.dialer().endpoint().clone();
    terminal.release().await;
    terminal.release().await;
    assert_eq!(copy.holders(), 1, "a second release of one lease gives nothing more back");
    assert!(!endpoint.is_closed(), "the copy's lease keeps the endpoint open");
    copy.release().await;
    assert!(endpoint.is_closed(), "the last lease closed the endpoint");
    far.endpoint.close().await;
}

/// A copy's stream goes below a terminal's at the far end too, which reads
/// its first byte on a connection of the ALPN of lanes; a far end of before,
/// which knows the first ALPN alone, takes it as any session, and only this
/// end's bytes of it go below.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_s_stream_goes_below_a_terminal_s_at_each_end_that_reads_its_lane() {
    let (relay_url, _relay) = relay().await;
    let (proxy, _) = proxy(relay_url.port().unwrap()).await;
    for lanes in [true, false] {
        let far = podssh_iroh::bind(&options(&relay_url, proxy, true)).await.expect("the far end");
        if !lanes {
            far.set_alpns(vec![ALPN.to_vec()]);
        }
        tokio::time::timeout(LIMIT, far.online()).await.expect("the far end has its home relay");
        let accepting = far.clone();
        let accepted = tokio::spawn(async move {
            let incoming = accepting.accept().await.expect("a connection");
            let connection = incoming.await.expect("its handshake");
            let first = podssh_iroh::accept_session(&connection).await.expect("the terminal's stream");
            let second = podssh_iroh::accept_session(&connection).await.expect("the copy's stream");
            (connection.alpn().to_vec(), first.priority(), second.priority(), connection)
        });
        let near = podssh_iroh::bind(&options(&relay_url, proxy, false)).await.expect("the client");
        let dialer = Dialer::new(near.clone(), EndpointAddr::new(far.id()).with_relay_url(relay_url.clone()));
        let terminal = dialer.link_as(Lane::Interactive).await.expect("the terminal's stream");
        let copy = dialer.link_as(Lane::Bulk).await.expect("the copy's stream");
        let (alpn, far_terminal, far_copy, _kept) = tokio::time::timeout(LIMIT, accepted).await.unwrap().unwrap();
        assert_eq!((terminal.priority(), copy.priority()), (Some(0), Some(-1)), "this end's copy bytes go after");
        let (want_alpn, want_copy) = if lanes { (ALPN_LANES, Some(-1)) } else { (ALPN, Some(0)) };
        assert_eq!(alpn, want_alpn, "lanes: {lanes}");
        assert_eq!((far_terminal, far_copy), (Some(0), want_copy), "the far end's bytes, lanes: {lanes}");
        dialer.close().await;
        near.close().await;
        far.close().await;
    }
}
