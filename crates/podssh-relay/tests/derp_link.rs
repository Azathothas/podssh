//! The DERP road (T-349) through a stand-in DERP server in memory
//! (`derp_stand_in`): 8 MiB both ways over one link with equal digests,
//! with no loss and with 5 % of the packets dropped under the adapter; a
//! session of the resumable layer that goes on after the client's connection
//! is cut; and a client that gives up on a node that is not there within
//! its limit. The tests marked `ignore` run against Tailscale's derper,
//! which `scripts/interop-derp.sh` starts in Podman. A planted adapter that
//! never sends a segment again fails the test with drops.

#![cfg(feature = "derp")]

mod derp_stand_in;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use derp_stand_in::StandIn;
use podssh_relay::derp::conn::Setup;
use podssh_relay::derp::dial::{self, Dial};
use podssh_relay::derp::link::OPEN_LIMIT;
use podssh_relay::derp::{self as road, Conn, Dialer, Key, Link, Node, Secret, Server, Ticket};
use podssh_relay::identity::PublicKey;
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::Note;
use podssh_relay::session::{OsEntropy, Settings};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::Instant;

const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(180);
/// The replay buffers that a node keeps, at most, as a node of the CLI does.
const BUDGET: usize = 64 << 20;

fn say(who: &'static str) -> road::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
}

/// Bytes that a seed fixes (xorshift64*).
fn bytes(size: usize, mut seed: u64) -> Vec<u8> {
    (0..size)
        .map(|_| {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            (seed.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// Write `out` on `link` and end its direction, while the far end's bytes
/// are read to their end: their digest and length.
async fn both_ways(link: Link, out: Vec<u8>) -> (Vec<u8>, usize) {
    let (mut reader, mut writer) = tokio::io::split(link);
    let writing = async move {
        writer.write_all(&out).await.expect("the link takes the bytes");
        writer.shutdown().await.expect("the link's end");
    };
    let reading = async move {
        let mut digest = Sha256::new();
        let mut got = 0;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf).await.expect("the link gives the bytes");
            if n == 0 {
                break;
            }
            digest.update(&buf[..n]);
            got += n;
        }
        (digest.finalize().to_vec(), got)
    };
    let ((), read) = tokio::join!(writing, reading);
    read
}

/// A node's connection to `server` through `dial`, and a client's dialer of
/// its ticket.
async fn ends(dial: Dial, server: Server) -> (Conn, Dialer) {
    let secret = Arc::new(Secret::random(&mut OsEntropy).expect("random bytes"));
    let io = (dial)(&server).await.expect("a pipe to the server");
    let setup = Setup { secret, serves: true, say: say("node") };
    let node = Conn::start(server.clone(), io, setup).await.expect("the node's connection");
    let ticket = Ticket { node: PublicKey([0; 32]), derp: node.key(), server };
    let dialer = Dialer::new(&ticket, dial, say("client")).expect("random bytes");
    (node, dialer)
}

/// 8 MiB each way over one link between the two ends of `dial`.
async fn eight_mib_both_ways(dial: Dial, server: Server) {
    let (node, dialer) = ends(dial, server).await;
    let (client, served) = tokio::join!(dialer.link(), node.accept());
    let (client, served) = (client.expect("the node answers"), served.expect("the node gets the link"));
    let (up, down) = (bytes(8 * MIB, 1), bytes(8 * MIB, 2));
    let (want_up, want_down) = (Sha256::digest(&up).to_vec(), Sha256::digest(&down).to_vec());
    let ((got_down, down_len), (got_up, up_len)) = tokio::join!(both_ways(client, up), both_ways(served, down));
    assert_eq!((up_len, down_len), (8 * MIB, 8 * MIB));
    assert_eq!(got_up, want_up, "the node got the client's bytes");
    assert_eq!(got_down, want_down, "the client got the node's bytes");
    dialer.close().await;
    node.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eight_mib_go_both_ways_through_the_stand_in() {
    let stand_in = StandIn::new(0);
    tokio::time::timeout(LIMIT, eight_mib_both_ways(stand_in.dial(), StandIn::server())).await.expect("in time");
    assert!(stand_in.forwarded.load(std::sync::atomic::Ordering::SeqCst) > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eight_mib_go_both_ways_with_five_percent_of_the_packets_dropped() {
    let stand_in = StandIn::new(5);
    tokio::time::timeout(LIMIT, eight_mib_both_ways(stand_in.dial(), StandIn::server())).await.expect("in time");
    let dropped = stand_in.dropped.load(std::sync::atomic::Ordering::SeqCst);
    assert!(dropped > 0, "the stand-in dropped no packet, so the test proves nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_gives_up_on_a_node_that_is_not_at_its_server_within_its_limit() {
    let stand_in = StandIn::new(0);
    let ticket = Ticket { node: PublicKey([0; 32]), derp: Key([0x42; 32]), server: StandIn::server() };
    let dialer = Dialer::new(&ticket, stand_in.dial(), say("client")).unwrap();
    let started = Instant::now();
    let err = tokio::time::timeout(LIMIT, dialer.link()).await.expect("in time").unwrap_err();
    let took = started.elapsed();
    assert!(took >= OPEN_LIMIT && took < OPEN_LIMIT + Duration::from_secs(5), "{took:?}");
    assert!(err.contains("did not answer"), "{err}");
}

/// An echo of each byte, as a node's target.
async fn echo() -> Result<DuplexStream, String> {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(theirs);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    Ok(ours)
}

/// A session of the layer through `dial` to a node in front of an echo: 2
/// MiB out, and each byte back; with `drops`, the client's connection to the
/// stand-in is cut once a third came back. The notes of the session.
async fn echo_session(dial: Dial, server: Server, drops: Option<Arc<StandIn>>) -> Vec<Note> {
    let settings = Settings { features: road::FEATURES, ..Settings::default() };
    let secret = Arc::new(Secret::random(&mut OsEntropy).unwrap());
    let node = Node { secret, server: server.clone(), dial: dial.clone(), say: say("node") };
    let first = road::far::connect(&node).await.expect("the node's connection");
    let ticket = Ticket { node: PublicKey([0; 32]), derp: first.key(), server };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = tokio::spawn(road::far::serve_from(node, Some(first), settings, BUDGET, echo, keeper));
    let dialer = Dialer::new(&ticket, dial, say("client")).unwrap();
    let notes = Mutex::new(Vec::new());
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out = bytes(2 * MIB, 3);
    let want = Sha256::digest(&out).to_vec();
    // The client's session and its user in one task: the user ends its
    // bytes once each came back, and the session then ends.
    let carrying = road::carry(&dialer, app, settings, |note: Note| notes.lock().unwrap().push(note));
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let writing = async {
            writer.write_all(&out).await.expect("the layer takes the bytes");
        };
        let reading = async {
            let mut back = Vec::with_capacity(out.len());
            let mut buf = vec![0u8; 64 * 1024];
            let mut cut = drops.as_ref();
            while back.len() < out.len() {
                let n = reader.read(&mut buf).await.expect("the echo");
                assert!(n > 0, "the session ended after {} bytes", back.len());
                back.extend_from_slice(&buf[..n]);
                if back.len() >= out.len() / 3 {
                    if let Some(stand_in) = cut.take() {
                        stand_in.cut(&dialer.key().0);
                    }
                }
            }
            back
        };
        let ((), back) = tokio::join!(writing, reading);
        drop((reader, writer));
        back
    };
    let both = async { tokio::join!(carrying, using) };
    let (carried, back) = tokio::time::timeout(LIMIT, both).await.expect("the session ended in time");
    assert_eq!(Sha256::digest(&back).to_vec(), want, "each byte came back once, in order");
    assert!(carried.is_ok(), "{:?}", carried.err());
    serving.abort();
    notes.into_inner().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_of_the_layer_goes_on_after_the_client_s_connection_is_cut() {
    let stand_in = StandIn::new(2);
    let notes = echo_session(stand_in.dial(), StandIn::server(), Some(stand_in.clone())).await;
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "a resume: {notes:?}");
    let logins = stand_in.logins.load(std::sync::atomic::Ordering::SeqCst);
    assert!(logins >= 3, "the node, the client, and the client again: {logins}");
}

/// The server and the trust of the derper of `scripts/interop-derp.sh`.
fn derper() -> (Dial, Server) {
    let server = std::env::var("PODSSH_DERP_TEST_SERVER").expect("PODSSH_DERP_TEST_SERVER=HOST:PORT of a derper");
    let ca = std::env::var("PODSSH_DERP_TEST_CA").expect("PODSSH_DERP_TEST_CA=FILE, the derper's certificate");
    let trust = podssh_ws::Trust::File(ca.into());
    (dial::tls(trust, podssh_ws::ProxyChoice::Direct), Server::parse(&server).expect("HOST:PORT"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a derper: scripts/interop-derp.sh"]
async fn through_derper_eight_mib_go_both_ways() {
    let (dial, server) = derper();
    tokio::time::timeout(LIMIT, eight_mib_both_ways(dial, server)).await.expect("in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a derper: scripts/interop-derp.sh"]
async fn through_derper_a_node_that_is_not_there_is_not_answered() {
    let (dial, server) = derper();
    let ticket = Ticket { node: PublicKey([0; 32]), derp: Key([0x42; 32]), server };
    let dialer = Dialer::new(&ticket, dial, say("client")).unwrap();
    let err = tokio::time::timeout(LIMIT, dialer.link()).await.expect("in time").unwrap_err();
    assert!(err.contains("did not answer"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a derper: scripts/interop-derp.sh"]
async fn through_derper_a_session_of_the_layer_echoes_two_mib() {
    let (dial, server) = derper();
    let notes = echo_session(dial, server, None).await;
    assert!(!notes.iter().any(|n| matches!(n, Note::Lost { .. })), "no link was lost: {notes:?}");
}
