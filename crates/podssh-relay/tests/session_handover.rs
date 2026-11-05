//! A far end's sessions handed to the binary that takes its place (T-668),
//! within one process: the first keeper hands each session over in the
//! middle of 8 MiB each way, its state goes through its bytes, as between
//! two binaries, and a second keeper takes it, with the same TCP connection
//! to the target; the client resumes on a link to the second keeper, and
//! the bytes at both ends have equal SHA-256 digests. Once with the layer
//! over the target as it is (a node of `--no-e2e`), once with the
//! end-to-end channel above it, whose keys and nonces move too; and a
//! session whose target cannot move ends at its resume with why.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use podssh_relay::e2e::ends::{self, Node};
use podssh_relay::e2e::hold;
use podssh_relay::identity::Identity;
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::handover::{Handed, LayerState, Moved};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next};
use podssh_relay::session::{far, Ask, End, OsEntropy, Role, Settings};

const PIPE: usize = 256 * 1024;
const MIB: usize = 1 << 20;
const BYTES: usize = 8 * MIB;
const LIMIT: Duration = Duration::from_secs(120);
const BUDGET: usize = 1 << 30;

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

/// A link through a stand-in relay: both ways, until either end goes.
fn relayed() -> (DuplexStream, DuplexStream) {
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

/// The target: a TCP server that takes the session's `up` and sends `down`,
/// and counts its connections, which a handover must not add to.
async fn target(down: Vec<u8>) -> (std::net::SocketAddr, Arc<AtomicUsize>, oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let (got_tx, got_rx) = oneshot::channel();
    let counted = accepted.clone();
    tokio::spawn(async move {
        let mut got_tx = Some(got_tx);
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let (down, got_tx) = (down.clone(), got_tx.take());
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let writer = tokio::spawn(async move {
                    let _ = w.write_all(&down).await;
                    w
                });
                let mut got = vec![0u8; BYTES];
                let read = r.read_exact(&mut got).await;
                if let (Ok(_), Some(tx)) = (read, got_tx) {
                    let _ = tx.send(got);
                }
                let _ = writer.await;
            });
        }
    });
    (at, accepted, got_rx)
}

/// The keeper that takes each new link now: the first one, then the one
/// that the handover gave the sessions to; none between the two, while a
/// link waits, as a client's resume waits for the next binary's socket.
type Current<A> = Arc<Mutex<Option<Arc<Keeper<A>>>>>;

/// A far end whose links go to the keeper of `current`; a new session's
/// target comes from `open`.
fn far_end<A, O, F>(current: Current<A>, settings: Settings, mut links: mpsc::UnboundedReceiver<DuplexStream>, open: O)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: std::future::Future<Output = Result<A, String>> + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(link) = links.recv().await {
            let (current, open) = (current.clone(), open.clone());
            tokio::spawn(async move {
                let keeper = loop {
                    if let Some(keeper) = current.lock().unwrap().clone() {
                        break keeper;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };
                far::serve(link, Role::NODE, settings, &keeper, BUDGET, open).await;
            });
        }
    });
}

/// The client's application: `up` out, `down` in, with a word once `at`
/// bytes came in.
async fn exchange(app: DuplexStream, up: Vec<u8>, at: usize, half: oneshot::Sender<()>) -> Vec<u8> {
    let (mut r, mut w) = tokio::io::split(app);
    let writer = tokio::spawn(async move {
        w.write_all(&up).await.unwrap();
        w
    });
    let (mut got, mut half) = (Vec::with_capacity(BYTES), Some(half));
    let mut buf = vec![0u8; 64 * 1024];
    while got.len() < BYTES {
        let n = r.read(&mut buf).await.unwrap();
        assert!(n > 0, "the session ended after {} bytes", got.len());
        got.extend_from_slice(&buf[..n]);
        if got.len() >= at {
            if let Some(half) = half.take() {
                let _ = half.send(());
            }
        }
    }
    let _ = writer.await;
    got
}

/// Each session through its bytes, as between two binaries.
fn through_bytes(handed: Vec<Handed>) -> Vec<Handed> {
    handed
        .into_iter()
        .map(|Handed { state, target }| {
            let state = LayerState::decode(&state.encode()).unwrap();
            let target = target.map(|Moved { socket, channel }| Moved { socket, channel });
            Handed { state, target }
        })
        .collect()
}

fn settings() -> Settings {
    Settings { resume_deadline: Duration::from_secs(60), ..Settings::default() }
}

/// The client's session over links that `links_tx` gives the far end.
async fn client_session(
    links_tx: mpsc::UnboundedSender<DuplexStream>,
    app_end: DuplexStream,
) -> tokio::task::JoinHandle<Outcome> {
    let (client_link, far_link) = relayed();
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings(), &mut OsEntropy).await.unwrap();
    let connect = move |_: &podssh_relay::session::Ended| {
        let (client_link, far_link) = relayed();
        let _ = links_tx.send(far_link);
        async move { Next::Link(client_link) }
    };
    tokio::spawn(async move { resume::run(client, app_end, connect, |_| {}, &mut OsEntropy).await })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_over_its_target_as_it_is_goes_on_across_a_handover_its_bytes_whole() {
    let (up, down) = (pseudo_random(BYTES, 1), pseudo_random(BYTES, 2));
    let (at, accepted, got) = target(down.clone()).await;
    let first: Arc<Keeper<TcpStream>> = Arc::new(Keeper::new(Duration::from_secs(60)));
    let current: Current<TcpStream> = Arc::new(Mutex::new(Some(first.clone())));
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let open = move || async move { TcpStream::connect(at).await.map_err(|e| e.to_string()) };
    far_end(current.clone(), settings(), links_rx, open);

    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = client_session(links_tx, app_end).await;
    let (half_tx, half_rx) = oneshot::channel();
    let at_client = tokio::spawn(exchange(app, up.clone(), BYTES / 4, half_tx));

    tokio::time::timeout(LIMIT, half_rx).await.unwrap().unwrap();
    let second: Arc<Keeper<TcpStream>> = Arc::new(Keeper::new(Duration::from_secs(60)));
    *current.lock().unwrap() = None;
    let handed = through_bytes(first.hand_over().await);
    assert_eq!(handed.len(), 1, "one session handed over");
    let said = second.take_over(handed, |_, moved| {
        moved.socket.set_nonblocking(true).map_err(|e| e.to_string())?;
        TcpStream::from_std(moved.socket).map_err(|e| e.to_string())
    });
    assert!(said.is_empty(), "{said:?}");
    assert_eq!(first.kept(), 0, "the first keeper holds nothing after");
    *current.lock().unwrap() = Some(second.clone());

    let at_client = tokio::time::timeout(LIMIT, at_client).await.unwrap().unwrap();
    let at_server = tokio::time::timeout(LIMIT, got).await.unwrap().unwrap();
    assert_eq!(Sha256::digest(&at_server), Sha256::digest(&up), "the client's bytes reached the target whole");
    assert_eq!(Sha256::digest(&at_client), Sha256::digest(&down), "the target's bytes reached the client whole");
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "the same connection to the target");
    session.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_of_the_channel_goes_on_across_a_handover_with_its_keys_and_nonces() {
    let (up, down) = (pseudo_random(BYTES, 3), pseudo_random(BYTES, 4));
    let (at, accepted, got) = target(down.clone()).await;
    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let say = {
        let lines = lines.clone();
        Arc::new(move |line: String| lines.lock().unwrap().push(line))
    };
    let node = Node::open_to_all(Arc::new(Identity::from_seed(&[2; 32])), say);
    let first: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(60)));
    let current: Current<DuplexStream> = Arc::new(Mutex::new(Some(first.clone())));
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let open = {
        let node = node.clone();
        move || {
            let node = node.clone();
            async move {
                // As a node's handler: the channel's task takes a hold by the
                // layer's id of the session, which the far end set.
                let (ours, theirs) = tokio::io::duplex(PIPE);
                let dial = move || async move { TcpStream::connect(at).await.map_err(|e| e.to_string()) };
                tokio::spawn(hold::holding(async move { ends::serve_node(theirs, &node, dial).await }));
                Ok::<_, String>(ours)
            }
        }
    };
    far_end(current.clone(), settings(), links_rx, open);

    let (app, app_end) = tokio::io::duplex(PIPE);
    let (cipher, operator) = ends::operator(app_end, Arc::new(Identity::from_seed(&[1; 32])), |_| Ok(()));
    let operator = tokio::spawn(operator);
    let session = client_session(links_tx, cipher).await;
    let (half_tx, half_rx) = oneshot::channel();
    let at_client = tokio::spawn(exchange(app, up.clone(), BYTES / 4, half_tx));

    tokio::time::timeout(LIMIT, half_rx).await.unwrap().unwrap();
    let second: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(60)));
    *current.lock().unwrap() = None;
    let handed = through_bytes(first.hand_over().await);
    assert_eq!(handed.len(), 1, "one session handed over");
    assert!(handed[0].target.as_ref().is_ok_and(|moved| moved.channel.is_some()), "its channel moved");
    let said = second.take_over(handed, |id, moved| {
        moved.socket.set_nonblocking(true).map_err(|e| e.to_string())?;
        let tcp = TcpStream::from_std(moved.socket).map_err(|e| e.to_string())?;
        let channel = moved.channel.as_ref().map_or(&[][..], |bytes| bytes.as_slice());
        hold::resume(id, channel, tcp, &node)
    });
    assert!(said.is_empty(), "{said:?}");
    *current.lock().unwrap() = Some(second.clone());

    let at_client = tokio::time::timeout(LIMIT, at_client).await.unwrap().unwrap();
    let at_server = tokio::time::timeout(LIMIT, got).await.unwrap().unwrap();
    assert_eq!(Sha256::digest(&at_server), Sha256::digest(&up), "the operator's bytes reached the target whole");
    assert_eq!(Sha256::digest(&at_client), Sha256::digest(&down), "the target's bytes reached the operator whole");
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "the same connection to the target");
    let lines = lines.lock().unwrap().clone();
    assert!(!lines.iter().any(|line| line.contains("ended")), "no session of the channel ended: {lines:?}");
    session.abort();
    operator.abort();
}

/// A target that runs no channel and is no TCP connection cannot move: the
/// next keeper keeps its id, and the client's resume hears `CLOSE` with
/// why, never a session that the far end forgot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_whose_target_cannot_move_ends_at_its_resume_with_why() {
    let first: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(60)));
    let current: Current<DuplexStream> = Arc::new(Mutex::new(Some(first.clone())));
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let open = move || {
        let targets_tx = targets_tx.clone();
        async move {
            let (ours, theirs) = tokio::io::duplex(PIPE);
            let _ = targets_tx.send(theirs);
            Ok::<_, String>(ours)
        }
    };
    far_end(current.clone(), settings(), links_rx, open);
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let session = client_session(links_tx, app_end).await;
    let mut far_app = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().unwrap();
    app.write_all(b"before").await.unwrap();
    let mut before = [0u8; 6];
    far_app.read_exact(&mut before).await.unwrap();

    let second: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(60)));
    *current.lock().unwrap() = None;
    let handed = through_bytes(first.hand_over().await);
    assert!(handed[0].target.is_err());
    let said = second.take_over(handed, |_, _| Err("never asked".to_string()));
    assert!(said.iter().any(|line| line.contains("could not move")), "{said:?}");
    *current.lock().unwrap() = Some(second.clone());

    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    match &ended.end {
        End::Closed(reason) => assert!(reason.contains("upgrade could not move"), "{reason}"),
        other => panic!("the session ends with the far end's CLOSE, not {other:?}"),
    }
}
