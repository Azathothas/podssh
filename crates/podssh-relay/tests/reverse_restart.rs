//! A planned stop of podssh's relay role (T-255), as `podssh relay serve`
//! makes one at Ctrl-C or SIGTERM, during two sessions of the resumable layer
//! through podssh's own node and operator: each socket hears `1012 relay
//! restarting`, the node says so and connects again at once, the role comes
//! back with the pairs of its file (`--pairs FILE`), and both sessions resume,
//! their echoes whole. The role's listener outlives its run, as a socket that
//! a service manager holds across a restart: the node's first try waits in
//! its queue for the role that comes back, so that "at once" is seen, not
//! raced against a new bind.
#![cfg(all(feature = "serve", feature = "plain-ws"))]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::pair::{self, Pair};
use podssh_relay::relay::Relay;
use podssh_relay::reverse::{self, operator, Exit, Handler, Layered, NodeConfig, Opening, OperatorConfig};
use podssh_relay::reverse::{OperatorLimits, Outcome as LegOutcome, SessionId, Wire};
use podssh_relay::serve::{self, Config, Mint};
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{Ask, End, Ended, OsEntropy, Settings};
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

/// The bound on each step.
const LIMIT: Duration = Duration::from_secs(30);
/// The bytes of each session, each way: half before the stop, half after.
const SIZE: usize = 2 << 20;
/// Each direction of a pipe between a leg, the layer and the application.
const PIPE: usize = 256 * 1024;
/// How long a planned stop waits for its Closes, as `podssh relay serve`.
const STOP_WAIT: Duration = Duration::from_secs(3);
/// How long a lost leg may take to say how it ended, and how long a leg of
/// the layer waits for the node to end it, as `podssh ssh node://` sets them.
const LEG_WAIT: Duration = Duration::from_secs(5);
const NODE_ENDS: Duration = Duration::from_secs(35);
/// What a node that connects again at once takes, at most, to be online
/// again: the backoff of a try that is not at once is 500 ms at least.
const AT_ONCE: Duration = Duration::from_secs(1);

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

/// The layer's settings on the pair's road, as podssh's node and client run.
fn layer() -> Settings {
    Settings::default().on_the_pair()
}

/// Lines with the time that each came.
type Lines = Arc<Mutex<Vec<(Instant, String)>>>;

/// One run of the role on a copy of the test's listener, its pairs in a
/// file: what it said, and its tasks, which a stop ends as the binary's
/// runtime does.
struct Run {
    cfg: Arc<Config>,
    said: Lines,
    accepting: JoinHandle<()>,
    serving: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Run {
    fn start(listener: &std::net::TcpListener, file: &Path) -> Run {
        let copy = listener.try_clone().expect("a copy of the listener");
        copy.set_nonblocking(true).expect("a listener that does not block");
        let tcp = tokio::net::TcpListener::from_std(copy).expect("the listener in the runtime");
        let said: Lines = Arc::default();
        let events: serve::Events = {
            let said = said.clone();
            Box::new(move |line: &str| said.lock().unwrap().push((Instant::now(), line.to_string())))
        };
        let cfg = Arc::new(Config {
            version: "podssh test".into(),
            mint: Mint::Anyone,
            tokens: serve::tokens::Tokens::new([5; 32]),
            policy: Default::default(),
            egress: Default::default(),
            limits: Default::default(),
            pairs: serve::reverse::Pairs::open(Some(file.to_path_buf())).expect("the file of pairs"),
            resumes: Default::default(),
            answered: Default::default(),
            brake: Default::default(),
            usage: Default::default(),
            events: Some(events),
        });
        let serving: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let accepting = {
            let (cfg, serving) = (cfg.clone(), serving.clone());
            tokio::spawn(async move {
                while let Ok((stream, peer)) = tcp.accept().await {
                    let task = tokio::spawn(serve::serve_from(stream, cfg.clone(), None, Some(peer.ip())));
                    serving.lock().unwrap().push(task);
                }
            })
        };
        Run { cfg, said, accepting, serving }
    }

    /// How many lines of the role are `line`.
    fn count(&self, line: &str) -> usize {
        self.said.lock().unwrap().iter().filter(|(_, said)| said == line).count()
    }

    /// Until the role said `line` `n` times, [`LIMIT`] at most.
    async fn until_said(&self, line: &str, n: usize) {
        let deadline = Instant::now() + LIMIT;
        while self.count(line) < n {
            assert!(Instant::now() < deadline, "the role said {line:?} less than {n} times: {:?}", self.said);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A planned stop, as at SIGTERM: no more accepts, the role's Closes and
    /// their answers, then each of its tasks ends, as the binary's runtime
    /// ends them. Whether each Close went out and was answered in time.
    async fn stop(self) -> bool {
        self.accepting.abort();
        let _ = self.accepting.await;
        let closed = self.cfg.pairs.restart(STOP_WAIT).await;
        for task in self.serving.lock().unwrap().drain(..) {
            task.abort();
        }
        closed
    }
}

/// A pair of the role's, as podssh's client reads the answer of `/v1/pair`.
fn pair_of(run: &Run, relay: &Relay) -> Pair {
    let now = serve::tokens::now_ms();
    let made = run.cfg.pairs.make(now).expect("a pair");
    let body = serde_json::json!({
        "name": made.name, "node_token": made.node, "connect_token": made.connect,
        "stop_token": made.stop, "expires": made.expires_ms,
    });
    pair::parse(relay, body.to_string().as_bytes(), now as i64).expect("the role's pair, as podssh reads it")
}

/// Each session echoes what it takes.
struct Echo;

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async {
            let (ours, theirs) = tokio::io::duplex(PIPE);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(ours)
        })
    }
}

/// podssh's node for `pair`, with the layer, on the plain wire, until
/// `stop`; each of its lines into `lines`.
async fn node(pair: Pair, lines: Lines, stop: oneshot::Receiver<()>) -> Exit {
    let (trust, proxy) = (Trust::Default, ProxyChoice::Direct);
    let say = move |line: String| lines.lock().unwrap().push((Instant::now(), line));
    let mut config = NodeConfig {
        pair,
        label: None,
        trust: &trust,
        proxy: &proxy,
        timeout: LIMIT,
        settings: reverse::Settings::default(),
        repair: None,
        wire: Wire::PlainLoopback,
        say: Some(&say),
    };
    let handler = Arc::new(Layered::new(Echo, layer(), reverse::layered::NODE_BUDGET));
    reverse::run(&mut config, handler, async {
        let _ = stop.await;
    })
    .await
}

/// The legs of one session, as `podssh ssh node://` opens them: each to the
/// pair's name, and how each one before the last ended.
struct Legs {
    relay: Relay,
    name: String,
    token: String,
    current: Mutex<Option<JoinHandle<LegOutcome>>>,
    ended: Mutex<Vec<LegOutcome>>,
}

impl Legs {
    fn new(relay: &Relay, name: &str, token: &str) -> Arc<Legs> {
        let (current, ended) = (Mutex::default(), Mutex::default());
        Arc::new(Legs { relay: relay.clone(), name: name.into(), token: token.into(), current, ended })
    }

    /// A new leg: the pipe to it.
    async fn open(&self) -> Result<DuplexStream, String> {
        let config = OperatorConfig {
            relay: &self.relay,
            name: &self.name,
            connect_token: &self.token,
            trust: &Trust::Default,
            proxy: &ProxyChoice::Direct,
            timeout: LIMIT,
            // A leg of the layer: the node ends it (T-388).
            limits: OperatorLimits { node_ends: Some(NODE_ENDS), ..OperatorLimits::default() },
            wire: Wire::PlainLoopback,
        };
        let (link, leg) = tokio::io::duplex(PIPE);
        let handle = operator::start(&config, leg).await.map_err(|e| e.to_string())?;
        *self.current.lock().unwrap() = Some(handle);
        Ok(link)
    }

    /// The next link after a loss, with how the lost leg ended kept first;
    /// a move keeps its leg, which still carries the session.
    async fn next(&self, moving: bool) -> Next<DuplexStream> {
        let lost = if moving { None } else { self.current.lock().unwrap().take() };
        if let Some(handle) = lost {
            if let Ok(Ok(outcome)) = tokio::time::timeout(LEG_WAIT, handle).await {
                self.ended.lock().unwrap().push(outcome);
            }
        }
        match self.open().await {
            Ok(link) => Next::Link(link),
            Err(why) => Next::Retry(why),
        }
    }
}

/// One session of the layer through `legs`: [`SIZE`] bytes of `seed` up and
/// back, the first half before the stop, the rest once `go` says that the
/// role stopped; `wrote` counts the first halves. What came back, how the
/// session ended, and the notes of its resumes.
async fn session(legs: Arc<Legs>, seed: u32, wrote: Arc<AtomicUsize>, mut go: watch::Receiver<bool>) -> Carried {
    let first = legs.open().await.expect("the first leg");
    let client = client::start(first, Ask::New, layer(), &mut OsEntropy).await.expect("the layer's handshake");
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let (app, app_end) = tokio::io::duplex(PIPE);
    let run = {
        let (legs, notes) = (legs.clone(), notes.clone());
        tokio::spawn(async move {
            let connect = move |ended: &Ended| {
                let (legs, moving) = (legs.clone(), matches!(ended.end, End::Moving));
                async move { legs.next(moving).await }
            };
            let note = move |note: Note| notes.lock().unwrap().push(note);
            resume::run(client, app_end, connect, note, &mut OsEntropy).await
        })
    };
    let sent = pattern(SIZE, seed);
    let (mut r, mut w) = tokio::io::split(app);
    let writer = {
        let sent = sent.clone();
        tokio::spawn(async move {
            w.write_all(&sent[..SIZE / 2]).await.expect("the first half");
            wrote.fetch_add(1, Ordering::SeqCst);
            let _ = go.wait_for(|go| *go).await;
            w.write_all(&sent[SIZE / 2..]).await.expect("the second half");
            w
        })
    };
    let mut back = vec![0u8; SIZE];
    tokio::time::timeout(4 * LIMIT, r.read_exact(&mut back)).await.expect("the echo in time").expect("the echo");
    let mut w = writer.await.expect("the writer");
    w.shutdown().await.expect("the end of the input");
    let outcome = tokio::time::timeout(LIMIT, run).await.expect("the session's end in time").expect("its task");
    let notes = notes.lock().unwrap().clone();
    Carried { whole: Sha256::digest(&back) == Sha256::digest(&sent), outcome, notes }
}

/// What a session carried, and how.
struct Carried {
    whole: bool,
    outcome: Outcome,
    notes: Vec<Note>,
}

/// A scratch directory of mode 0700, gone at the end.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        let dir = std::env::temp_dir().join(format!("podssh-reverse-restart-{}-{nanos}", std::process::id()));
        podssh_relay::cache::private_dir(&dir).expect("a private directory");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_planned_stop_closes_each_socket_with_1012_and_the_sessions_resume_on_the_role_again() {
    let scratch = Scratch::new();
    let file = scratch.0.join("pairs.json");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port on the loopback");
    let relay = Relay { host: "127.0.0.1".into(), port: listener.local_addr().unwrap().port() };
    let first = Run::start(&listener, &file);
    let first_said = first.said.clone();
    let pair = pair_of(&first, &relay);
    let legs = || Legs::new(&relay, &pair.name, pair.connect_token());
    let (a_legs, b_legs) = (legs(), legs());
    let lines: Lines = Arc::default();
    let (stop_node, node_stops) = oneshot::channel();
    let (go, gone) = watch::channel(false);
    let wrote = Arc::new(AtomicUsize::new(0));

    let test = async {
        first.until_said("reverse node", 1).await;
        let a = tokio::spawn(session(a_legs.clone(), 1, wrote.clone(), gone.clone()));
        let b = tokio::spawn(session(b_legs.clone(), 2, wrote.clone(), gone.clone()));
        // Both sessions carry their first halves: the stop comes with bytes
        // on their way.
        let deadline = Instant::now() + LIMIT;
        while wrote.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline, "the first halves were not written");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let closed = first.stop().await;
        let again = Run::start(&listener, &file);
        let _ = go.send(true);
        let (a, b) = (a.await.expect("session a"), b.await.expect("session b"));
        let _ = stop_node.send(());
        (closed, again, a, b)
    };
    let ((closed, again, a, b), exit) =
        tokio::time::timeout(8 * LIMIT, async { tokio::join!(test, node(pair, lines.clone(), node_stops)) })
            .await
            .expect("in time");

    assert!(closed, "each Close went out, and each peer answered it, within the stop's wait");
    for (name, legs) in [("a", &a_legs), ("b", &b_legs)] {
        let ended = legs.ended.lock().unwrap();
        let restarted = LegOutcome::Ended { code: 1012, reason: "relay restarting".into() };
        assert_eq!(ended.first(), Some(&restarted), "session {name}'s first leg: {ended:?}");
    }
    let lines = lines.lock().unwrap().clone();
    let restart = "the relay is restarting (relay close 1012: relay restarting); connecting again at once";
    let at = lines.iter().position(|(_, line)| line == restart).unwrap_or_else(|| panic!("{lines:?}"));
    let online = lines[at..].iter().find(|(_, line)| line.starts_with("online again"));
    let (online_at, _) = online.unwrap_or_else(|| panic!("not online again after the restart: {lines:?}"));
    let took = online_at.duration_since(lines[at].0);
    assert!(took < AT_ONCE, "online again {took:?} after the restart: {lines:?}");
    again.until_said("reverse node", 1).await;
    assert!(again.count("reverse open") >= 2, "each session resumed on the role again: {:?}", again.said);
    for (name, carried) in [("a", &a), ("b", &b)] {
        assert!(carried.whole, "session {name}'s echo came back whole across the stop");
        let ended = matches!(&carried.outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd));
        assert!(ended, "session {name}: {:?}", carried.outcome);
        let resumed = carried.notes.iter().any(|note| matches!(note, Note::Resumed { .. }));
        assert!(resumed, "session {name} resumed: {:?}", carried.notes);
    }
    assert!(matches!(exit, Exit::Stopped), "{exit:?}");
    for said in [&first_said, &again.said] {
        let faults = said.lock().unwrap().iter().filter(|(_, l)| l.starts_with("reverse node closed")).count();
        assert_eq!(faults, 0, "no fault of the node's bytes: {said:?}");
    }
}
