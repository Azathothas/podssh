//! The Piping Server road (T-437) against nwtgck's own servers on the
//! loopback (`piping_harness`): a session of the resumable layer carries
//! 1 MiB each way through a node in front of an echo, with equal digests,
//! over HTTP/1.1 through nwtgck/piping-server (the server of `ppng.io`),
//! over HTTP/2 and HTTP/1.1 through piping-server-rust, and in numbered
//! pieces through a stand-in proxy that holds each request's body until its
//! end, where the streamed form does not flow. A client of another pair
//! finds no node at its door. With two servers, the first down and the
//! second holding bodies, the node and the client meet at the second, in
//! numbered pieces (T-497). The refusal of an upgrade by the stand-in is
//! told from the relay's own word. A test whose server is not here says
//! why it did not run.
//!
//!     PODSSH_TEST_PIPING_JS=piping-server PODSSH_TEST_PIPING_RUST=/path/piping-server \
//!         cargo test -p podssh-relay --features piping --test piping

#![cfg(feature = "piping")]

mod piping_harness;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use piping_harness::{Holding, Kind, REFUSAL};
use podssh_relay::piping::client::DOOR_LIMIT;
use podssh_relay::piping::dial::{Dial, Proto};
use podssh_relay::piping::probe::upgrade_refused;
use podssh_relay::piping::{self as road, Dialer, Http, Node, Secret};
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::Note;
use podssh_relay::session::Settings;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(180);
/// The replay buffers that a node keeps, at most, as a node of the CLI does.
const BUDGET: usize = 64 << 20;

fn say(who: &'static str) -> road::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
}

/// The pair's key, the same at both ends.
fn secret() -> Secret {
    Secret::of_pair("test-pair", "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr")
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

/// A session through `dial` to a node in front of an echo: 1 MiB out, and
/// each byte back, with equal digests. The client's dialer, to read how its
/// links went.
async fn one_mib_each_way(dial: Dial) -> Arc<Dialer> {
    one_mib_each_way_through(vec![dial]).await
}

/// [`one_mib_each_way`], with a server for each of `dials`, in order: the
/// node waits at the first that answers, and the client meets it there.
async fn one_mib_each_way_through(dials: Vec<Dial>) -> Arc<Dialer> {
    let settings = Settings { features: road::FEATURES, ..Settings::default() };
    let http = |dial: &Dial| Http::new(piping_harness::server(), dial.clone());
    let fallbacks = dials[1..].iter().map(|dial| Arc::new(http(dial))).collect();
    let node = Node { secret: Arc::new(secret()), http: Arc::new(http(&dials[0])), fallbacks, say: say("node") };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = tokio::spawn(road::far::serve_kept(node, settings, BUDGET, echo, keeper));
    let dialer = Arc::new(Dialer::with_servers(secret(), dials.iter().map(http).collect(), say("client")));
    let notes = Mutex::new(Vec::new());
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out = bytes(MIB, 3);
    let want = Sha256::digest(&out).to_vec();
    let carrying = Box::pin(road::carry(&dialer, app, settings, |note: Note| notes.lock().unwrap().push(note)));
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let writing = async { writer.write_all(&out).await.expect("the layer takes the bytes") };
        let reading = async {
            let mut back = Vec::with_capacity(out.len());
            let mut buf = vec![0u8; 64 * 1024];
            while back.len() < out.len() {
                let n = reader.read(&mut buf).await.expect("the echo");
                assert!(n > 0, "the session ended after {} bytes", back.len());
                back.extend_from_slice(&buf[..n]);
            }
            back
        };
        let ((), back) = tokio::join!(writing, reading);
        drop((reader, writer));
        back
    };
    let both = async { tokio::join!(carrying, using) };
    let (carried, back) = tokio::time::timeout(LIMIT, both).await.expect("the session ended in time");
    assert_eq!(back.len(), MIB);
    assert_eq!(Sha256::digest(&back).to_vec(), want, "each byte came back once, in order");
    carried.expect("the session ran");
    serving.abort();
    dialer.close().await;
    eprintln!("notes: {:?}", notes.lock().unwrap());
    dialer
}

/// The server of `kind`, or a line that says why the test did not run.
fn server_of(kind: Kind) -> Option<piping_harness::Running> {
    match piping_harness::start(kind) {
        Ok(running) => Some(running),
        Err(why) => {
            eprintln!("did not run: {why}");
            None
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_carries_1_mib_each_way_through_nwtgck_s_piping_server() {
    let Some(server) = server_of(Kind::Js) else { return };
    let dialer = one_mib_each_way(piping_harness::dial(server.port, Proto::H1)).await;
    assert_eq!(dialer.proto(), Some(Proto::H1));
    assert!(!dialer.numbered(), "the streamed form flows with no proxy on the way");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_carries_1_mib_each_way_over_http_2_through_piping_server_rust() {
    let Some(server) = server_of(Kind::Rust) else { return };
    let dialer = one_mib_each_way(piping_harness::dial(server.port, Proto::H2)).await;
    assert_eq!(dialer.proto(), Some(Proto::H2));
    assert!(!dialer.numbered());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_carries_1_mib_each_way_over_http_1_1_through_piping_server_rust() {
    let Some(server) = server_of(Kind::Rust) else { return };
    let dialer = one_mib_each_way(piping_harness::dial(server.port, Proto::H1)).await;
    assert!(!dialer.numbered());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn numbered_pieces_carry_1_mib_each_way_where_a_proxy_holds_each_body_to_its_end() {
    let Some(server) = server_of(Kind::Js) else { return };
    let holding = Holding::start(server.port).await;
    let dialer = one_mib_each_way(piping_harness::dial(holding.port, Proto::H1)).await;
    assert!(dialer.numbered(), "the streamed form cannot flow through a proxy that holds bodies");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_node_and_the_client_meet_at_the_second_server_when_the_first_is_down() {
    for kind in [Kind::Js, Kind::Rust] {
        let Some(server) = server_of(kind) else { continue };
        // The first server: a port of the loopback where nothing listens.
        let down = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).expect("a port").port();
        // The second holds each request's body to its end, as Render's front
        // does: the order of the servers and the numbered pieces, together.
        let holding = Holding::start(server.port).await;
        let dials = vec![piping_harness::dial(down, Proto::H1), piping_harness::dial(holding.port, Proto::H1)];
        let dialer = one_mib_each_way_through(dials).await;
        assert_eq!(dialer.proto(), Some(Proto::H1), "{kind:?}: the client's links went through the second server");
        assert!(dialer.numbered(), "{kind:?}: the second server holds bodies: its links are numbered");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_of_another_pair_finds_no_node_at_its_door() {
    let Some(server) = server_of(Kind::Js) else { return };
    let dial = piping_harness::dial(server.port, Proto::H1);
    let settings = Settings { features: road::FEATURES, ..Settings::default() };
    let node = Node {
        secret: Arc::new(secret()),
        http: Arc::new(Http::new(piping_harness::server(), dial.clone())),
        fallbacks: Vec::new(),
        say: say("node"),
    };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = tokio::spawn(road::far::serve_kept(node, settings, BUDGET, echo, keeper));
    let stranger = Secret::of_pair("test-pair", "another connect token of another pair");
    let dialer = Dialer::new(stranger, Http::new(piping_harness::server(), dial), say("stranger"));
    let failed = tokio::time::timeout(LIMIT, dialer.link()).await.expect("in time").err().expect("no link");
    assert!(failed.contains("no node took the hello"), "{failed}");
    assert!(failed.contains(&format!("{} s", DOOR_LIMIT.as_secs())), "{failed}");
    serving.abort();
}

#[tokio::test]
async fn a_proxy_s_refusal_of_the_upgrade_is_told_from_the_relay_s_own_word() {
    // The stand-in refuses the upgrade before it would reach any server.
    let holding = Holding::start(1).await;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", holding.port)).await.expect("the stand-in");
    let key = podssh_ws::handshake::generate_key().expect("a key");
    let request = format!(
        "GET /v1/node/abc HTTP/1.1\r\nHost: relay.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let refused = podssh_ws::client::upgrade_with(tcp, request.as_bytes(), &key).await.expect_err("refused");
    assert!(
        matches!(&refused, podssh_ws::client::ConnectError::Refused { status: 403, body } if body.contains(REFUSAL)),
        "{refused}"
    );
    assert!(upgrade_refused(&refused), "a proxy's page is the way's refusal, the road's cue");
}
