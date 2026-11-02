//! The layer's window on the pair's road (T-443), against a stand-in of the
//! relay's bound: the relay of the contract holds at most 1 MiB for a slow
//! receiver, and past it drops a frame and closes with `1011 relay
//! backpressure`. Between the node's far end and the operator's client, the
//! stand-in reads each side at once into a queue with no bound, as a relay
//! that reads its sender at once, and gives the other side 4 MiB a second,
//! as to a receiver whose network is slow; it counts the most that waited in
//! each queue. A target that sends 8 MiB and takes 8 MiB, with the settings
//! of the pair's road at both ends: each byte arrives, the session ends
//! well, and no queue passes 1 MiB. With the buffer's 4 MiB as the window,
//! both pass it.
#![cfg(feature = "pair")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc;

use podssh_relay::reverse::{Handler, Layered, Opening, SessionId as RelayId};
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::resume::{self, Next};
use podssh_relay::session::{Ask, End, Ended, OsEntropy, Settings};

const MIB: usize = 1 << 20;
const PIPE: usize = 256 * 1024;
/// What the relay holds for a slow receiver before `1011 relay backpressure`.
const BOUND: usize = MIB;
/// How fast the stand-in gives each side its bytes, a slice at a time.
const RATE: usize = 4 * MIB;
const SLICE: usize = 16 * 1024;
/// Each way: twice the replay buffer, so that the window fills again and
/// again.
const LEN: usize = 8 * MIB;
const LIMIT: Duration = Duration::from_secs(60);

/// Bytes from a fixed xorshift, so that a run repeats.
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

/// What waits in one queue of the stand-in, and the most that ever did.
#[derive(Default)]
struct Held {
    now: AtomicUsize,
    most: AtomicUsize,
}

impl Held {
    fn add(&self, n: usize) {
        let now = self.now.fetch_add(n, Ordering::SeqCst) + n;
        self.most.fetch_max(now, Ordering::SeqCst);
    }

    fn take(&self, n: usize) {
        self.now.fetch_sub(n, Ordering::SeqCst);
    }

    fn most(&self) -> usize {
        self.most.load(Ordering::SeqCst)
    }
}

/// One direction of the stand-in: `from` read at once into a queue with no
/// bound, and given to `to` at [`RATE`].
async fn slow(mut from: ReadHalf<DuplexStream>, mut to: WriteHalf<DuplexStream>, held: Arc<Held>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let reader = {
        let held = held.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match from.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        held.add(n);
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        })
    };
    let pace = Duration::from_secs_f64(SLICE as f64 / RATE as f64);
    while let Some(bytes) = rx.recv().await {
        for slice in bytes.chunks(SLICE) {
            tokio::time::sleep(pace).await;
            if to.write_all(slice).await.is_err() {
                reader.abort();
                return;
            }
            held.take(slice.len());
        }
    }
    let _ = to.shutdown().await;
}

/// A node's target that sends [`LEN`] bytes and takes as many at once, then
/// ends: both ways of the session full. What it took goes into `took`.
struct Both {
    took: Arc<Mutex<Vec<u8>>>,
}

impl Handler for Both {
    type Stream = DuplexStream;

    fn open(&self, _id: RelayId) -> Opening<DuplexStream> {
        let took = self.took.clone();
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(PIPE);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(theirs);
                let send = async {
                    for chunk in pseudo_random(LEN, 1).chunks(32 * 1024) {
                        if w.write_all(chunk).await.is_err() {
                            return;
                        }
                    }
                };
                let take = async {
                    let mut got = Vec::with_capacity(LEN);
                    let mut buf = vec![0u8; 64 * 1024];
                    while got.len() < LEN {
                        match r.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    }
                    *took.lock().unwrap() = got;
                };
                tokio::join!(send, take);
                // Its bytes end only once it took each of the operator's: a
                // `CLOSE` ends the session both ways.
                let _ = w.shutdown().await;
            });
            Ok(ours)
        })
    }
}

/// The relay's session between the node and the client's link, through the
/// stand-in: the link, and what waited for the operator and for the node.
async fn relayed(node: &Layered<Both>) -> (DuplexStream, Arc<Held>, Arc<Held>) {
    let id = RelayId::parse(format!("{:032x}", 1).as_bytes()).unwrap();
    let node_side = node.open(id).await.expect("the node takes the session");
    let (link, relay_client) = tokio::io::duplex(PIPE);
    let (to_operator, to_node) = (Arc::new(Held::default()), Arc::new(Held::default()));
    let (cr, cw) = tokio::io::split(relay_client);
    let (nr, nw) = tokio::io::split(node_side);
    tokio::spawn(slow(nr, cw, to_operator.clone()));
    tokio::spawn(slow(cr, nw, to_node.clone()));
    (link, to_operator, to_node)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_operator_and_a_slow_node_never_wait_past_the_relays_bound() {
    let settings = Settings::default().on_the_pair();
    let took = Arc::new(Mutex::new(Vec::new()));
    let node = Layered::new(Both { took: took.clone() }, settings, 64 * MIB);
    let (link, to_operator, to_node) = relayed(&node).await;
    let client = client::start(link, Ask::New, settings, &mut OsEntropy).await.unwrap();
    // The stand-in cuts no link: a loss is a failure of the test.
    let connect = |_: &Ended| async { Next::<DuplexStream>::Stop("the stand-in cuts no link".into()) };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, |_| {}, &mut OsEntropy).await });

    let sent = pseudo_random(LEN, 2);
    let (mut r, mut w) = tokio::io::split(app);
    let writer = {
        let sent = sent.clone();
        tokio::spawn(async move {
            for chunk in sent.chunks(32 * 1024) {
                w.write_all(chunk).await.unwrap();
            }
            // Its write side stays open: the node's `CLOSE` ends the session.
            w
        })
    };
    let mut got = Vec::new();
    tokio::time::timeout(LIMIT, r.read_to_end(&mut got)).await.expect("the session ends in time").unwrap();
    let _w = writer.await.unwrap();
    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();

    assert_eq!(got.len(), LEN, "each byte of the node's: {outcome:?}");
    assert_eq!(Sha256::digest(&got), Sha256::digest(pseudo_random(LEN, 1)), "the node's bytes whole");
    let took = took.lock().unwrap().clone();
    assert_eq!(Sha256::digest(&took), Sha256::digest(&sent), "the operator's bytes whole");
    assert!(matches!(&outcome, Outcome::Layer(e) if matches!(e.end, End::Closed(_) | End::LocalEnd)), "{outcome:?}");
    for (way, held) in [("for the operator", &to_operator), ("for the node", &to_node)] {
        assert!(
            held.most() <= BOUND,
            "{} bytes waited {way} at the stand-in: the relay would drop a frame and close with 1011 relay \
             backpressure",
            held.most()
        );
    }
    // The control: the stand-in was the slow part, and its queue was met.
    assert!(to_operator.most() > 256 * 1024, "only {} bytes ever waited for the operator", to_operator.most());
}
