//! The transit road (T-436) through magic-wormhole's own transit relay on
//! the loopback (`transit_server`): two ends of a pair meet and carry
//! 1 MiB each way with equal digests; a session of the resumable layer
//! moves to another road when the relay stops under it; two ends of one
//! side never meet, and a client gives up on a node that is not there
//! within its wait; a side that knows the token alone is refused by the
//! node, and two clients of one pair never take each other for the node.
//! The tests marked `ignore` run one short session through Least
//! Authority's relay (Q65), from GitHub Actions (`transit-live.yml`).
//! Planted (`scripts/plants/t436-transit-same-side.patch`): each end's line
//! names one side, and the meeting fails.

mod cleanup;
mod transit_server;

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_relay::session::keep::Keeper;
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{client, far as layer_far, Ask, OsEntropy, Role, Settings};
use podssh_relay::transit::meet::{meet, Missed, Part};
use podssh_relay::transit::{self, far, Dialer, Keys, Link, Node, Side};
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::time::Instant;
use transit_server::Relay;

const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(180);
/// The replay buffers that a node keeps, at most, as a node of the CLI does.
const BUDGET: usize = 64 << 20;
const NAME: &str = "0123456789abcdef0123456789abcdef";

fn say(who: &'static str) -> transit::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
}

/// The words of a pair of this run's, so that two runs never share a token.
fn keys() -> Keys {
    let side = Side::random(&mut OsEntropy).unwrap();
    Keys::of_pair(NAME, &format!("connect-token-of-the-test-{}", side.as_str()))
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

/// Write `out` on `link` while as many bytes are read from it: their
/// digest. The relay has no half-close, so each end reads what it expects
/// before it ends the link.
async fn both_ways(link: Link, out: Vec<u8>) -> Vec<u8> {
    let (mut reader, mut writer) = tokio::io::split(link);
    let want = out.len();
    let writing = async {
        writer.write_all(&out).await.expect("the link takes the bytes");
    };
    let reading = async {
        let mut digest = Sha256::new();
        let (mut got, mut buf) = (0, vec![0u8; 64 * 1024]);
        while got < want {
            let n = reader.read(&mut buf[..(want - got).min(64 * 1024)]).await.expect("the link gives the bytes");
            assert!(n > 0, "the link ended after {got} bytes");
            digest.update(&buf[..n]);
            got += n;
        }
        digest.finalize().to_vec()
    };
    let ((), read) = tokio::join!(writing, reading);
    read
}

/// A link that a meeting gave, or why it gave none.
type Meeting = Result<Link, Missed>;

/// A node's meeting at `url`, as `side`, waiting `wait`.
async fn node_meets(url: &WsUrl, proxy: &ProxyChoice, keys: &Keys, side: &Side, wait: Duration) -> Meeting {
    let session = far::dial(url, &Trust::Default, proxy).await.expect("the relay takes a connection");
    let first = meet(&session, keys, side, Part::Node, Some(wait), &mut OsEntropy).await?;
    Ok(Link::start(session, first))
}

fn dialer(url: &WsUrl, keys: &Keys, proxy: ProxyChoice) -> Dialer {
    Dialer::new(url.clone(), keys.clone(), Trust::Default, proxy, say("client")).expect("random bytes")
}

/// 1 MiB each way over one link of two ends that met at `url`.
async fn one_mib_each_way(url: &WsUrl, proxy: ProxyChoice) {
    let keys = keys();
    let node_side = Side::random(&mut OsEntropy).unwrap();
    let mut client = dialer(url, &keys, proxy.clone());
    // The live run's plant (transit-live.yml): one side for both ends, which
    // the relay never pairs, so that the check is seen to fail.
    if std::env::var("PODSSH_TRANSIT_TEST_PLANT").is_ok_and(|v| v == "same-side") {
        client = client.with_side(node_side.clone());
    }
    let wait = transit::client::MEET_LIMIT + Duration::from_secs(5);
    let (served, link) = tokio::join!(node_meets(url, &proxy, &keys, &node_side, wait), client.link());
    // Both ends' results in the message: a live run that fails says which
    // end missed, and why.
    let (served, link) = match (served, link) {
        (Ok(served), Ok(link)) => (served, link),
        (served, link) => panic!("no meeting: the node {:?}, the client {:?}", served.err(), link.err()),
    };
    let (up, down) = (bytes(MIB, 1), bytes(MIB, 2));
    let (want_up, want_down) = (Sha256::digest(&up).to_vec(), Sha256::digest(&down).to_vec());
    let (got_down, got_up) = tokio::join!(both_ways(link, up), both_ways(served, down));
    assert_eq!(got_up, want_up, "the node got the client's bytes");
    assert_eq!(got_down, want_down, "the client got the node's bytes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_ends_meet_and_carry_one_mib_each_way() {
    let Some(relay) = Relay::start("mib") else { return };
    let ran = tokio::time::timeout(LIMIT, one_mib_each_way(&relay.url, ProxyChoice::Direct)).await;
    assert!(ran.is_ok(), "not in time; the relay said: {}", relay.said());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_ends_of_one_side_never_meet_and_the_client_gives_up_within_its_wait() {
    let Some(relay) = Relay::start("side") else { return };
    let (keys, side) = (keys(), Side::random(&mut OsEntropy).unwrap());
    let wait = Duration::from_secs(4);
    let client = dialer(&relay.url, &keys, ProxyChoice::Direct).with_side(side.clone()).with_wait(wait);
    let started = Instant::now();
    let (node, link) = tokio::join!(node_meets(&relay.url, &ProxyChoice::Direct, &keys, &side, wait), client.link());
    let took = started.elapsed();
    assert!(matches!(node, Err(Missed::Alone(_))), "the node met a side of its own: {:?}", node.err());
    let why = link.expect_err("the client met a side of its own");
    assert!(why.contains("no node met this client"), "{why}");
    assert!(took >= wait && took < wait + Duration::from_secs(5), "{took:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_side_that_knows_the_token_alone_is_refused_by_the_node() {
    let Some(relay) = Relay::start("stranger") else { return };
    let keys = keys();
    let stranger = Keys::knowing_only(keys.token());
    let (node_side, its_side) = (Side::random(&mut OsEntropy).unwrap(), Side::random(&mut OsEntropy).unwrap());
    let wait = Duration::from_secs(20);
    let posing = async {
        let session = far::dial(&relay.url, &Trust::Default, &ProxyChoice::Direct).await.unwrap();
        meet(&session, &stranger, &its_side, Part::Client, Some(wait), &mut OsEntropy).await
    };
    let (node, stranger) = tokio::join!(node_meets(&relay.url, &ProxyChoice::Direct, &keys, &node_side, wait), posing);
    assert!(matches!(node, Err(Missed::NotProven(_))), "the node let a stranger in: {:?}", node.err());
    assert!(matches!(stranger, Err(Missed::NotProven(_))), "{stranger:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_clients_of_one_pair_never_take_each_other_for_the_node() {
    let Some(relay) = Relay::start("clients") else { return };
    let keys = keys();
    let wait = Duration::from_secs(4);
    let (one, two) = (dialer(&relay.url, &keys, ProxyChoice::Direct), dialer(&relay.url, &keys, ProxyChoice::Direct));
    let (one, two) = (one.with_wait(wait), two.with_wait(wait));
    let (first, second) = tokio::join!(one.link(), two.link());
    let (first, second) = (first.expect_err("a client met a client"), second.expect_err("a client met a client"));
    assert!(first.contains("no node met") && second.contains("no node met"), "{first}; {second}");
    assert!(first.contains("another client") || second.contains("another client"), "they never met: {first}");
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

/// A link on either road of the test: the transit relay's, or a pipe to the
/// same node's keeper, as the pair's road is in `podssh node`.
enum Road {
    Transit(Link),
    Pipe(DuplexStream),
}

impl AsyncRead for Road {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Road::Transit(link) => Pin::new(link).poll_read(cx, buf),
            Road::Pipe(pipe) => Pin::new(pipe).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Road {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Road::Transit(link) => Pin::new(link).poll_write(cx, buf),
            Road::Pipe(pipe) => Pin::new(pipe).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Road::Transit(link) => Pin::new(link).poll_flush(cx),
            Road::Pipe(pipe) => Pin::new(pipe).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Road::Transit(link) => Pin::new(link).poll_shutdown(cx),
            Road::Pipe(pipe) => Pin::new(pipe).poll_shutdown(cx),
        }
    }
}

/// A session of the layer through the relay at `url` to a node in front of
/// an echo: 1 MiB out and each byte back. With `relay`, the relay stops once
/// a third came back, and each later link is a pipe to the node's keeper.
/// The notes of the session, and the links of the other road.
async fn echo_session(url: &WsUrl, proxy: ProxyChoice, mut relay: Option<&mut Relay>) -> (Vec<Note>, usize) {
    let settings = Settings::default();
    let keys = keys();
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let node = Node {
        url: url.clone(),
        keys: Arc::new({
            let keys = keys.clone();
            move || keys.clone()
        }),
        side: Side::random(&mut OsEntropy).unwrap(),
        trust: Trust::Default,
        proxy: proxy.clone(),
        say: say("node"),
    };
    let serving = tokio::spawn(far::serve_kept(node, settings, BUDGET, echo, keeper.clone()));
    let client = dialer(url, &keys, proxy);
    let piped = AtomicUsize::new(0);
    let first = client.link().await.expect("the client meets the node");
    let started = client::start(Road::Transit(first), Ask::New, settings, &mut OsEntropy).await.expect("the layer");
    let notes = Mutex::new(Vec::new());
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out = bytes(MIB, 3);
    let want = Sha256::digest(&out).to_vec();
    let stopped = AtomicUsize::new(0);
    let connect = |_: &podssh_relay::session::Ended| {
        let (keeper, client, piped, stopped) = (keeper.clone(), &client, &piped, &stopped);
        async move {
            if stopped.load(Ordering::SeqCst) == 0 {
                if let Ok(link) = client.link().await {
                    return Next::Link(Road::Transit(link));
                }
            }
            // The other road: a pipe that the node's far end serves with the
            // keeper of the transit road.
            piped.fetch_add(1, Ordering::SeqCst);
            let (ours, theirs) = tokio::io::duplex(256 * 1024);
            tokio::spawn(async move { layer_far::serve(theirs, Role::NODE, settings, &keeper, BUDGET, echo).await });
            Next::Link(Road::Pipe(ours))
        }
    };
    let mut entropy = OsEntropy;
    // On the heap: the layer's future, polled on the test's own thread, is
    // larger than that thread's stack in a debug build.
    let carrying =
        Box::pin(resume::run(started, app, connect, |note: Note| notes.lock().unwrap().push(note), &mut entropy));
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let writing = async {
            writer.write_all(&out).await.expect("the layer takes the bytes");
        };
        let reading = async {
            let mut back = Vec::with_capacity(out.len());
            let mut buf = vec![0u8; 64 * 1024];
            while back.len() < out.len() {
                let n = reader.read(&mut buf).await.expect("the echo");
                assert!(n > 0, "the session ended after {} bytes", back.len());
                back.extend_from_slice(&buf[..n]);
                if back.len() >= out.len() / 3 {
                    if let Some(relay) = relay.take() {
                        stopped.store(1, Ordering::SeqCst);
                        relay.stop();
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
    let (_, back) = tokio::time::timeout(LIMIT, both).await.expect("the session ended in time");
    assert_eq!(Sha256::digest(&back).to_vec(), want, "each byte came back once, in order");
    serving.abort();
    (notes.into_inner().unwrap(), piped.load(Ordering::SeqCst))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_moves_to_another_road_when_the_transit_relay_stops() {
    let Some(mut relay) = Relay::start("move") else { return };
    let url = relay.url.clone();
    let (notes, piped) = echo_session(&url, ProxyChoice::Direct, Some(&mut relay)).await;
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "a resume: {notes:?}");
    assert!(piped >= 1, "the other road carried no link: {notes:?}");
}

/// Least Authority's relay, or the one of `PODSSH_TRANSIT` (Q65: short
/// runs, from GitHub Actions and a session's own host).
fn least_authority() -> WsUrl {
    let named = std::env::var(transit::ENV).ok();
    match transit::setting(named.as_deref()).expect("PODSSH_TRANSIT") {
        transit::Setting::On(url) => url,
        transit::Setting::Off => WsUrl::parse(transit::DEFAULT_URL).unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: Least Authority's transit relay (Q65), a short run: transit-live.yml"]
async fn through_least_authority_two_ends_meet_and_carry_one_mib_each_way() {
    let url = least_authority();
    tokio::time::timeout(LIMIT, one_mib_each_way(&url, ProxyChoice::FromEnvironment)).await.expect("in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: Least Authority's transit relay (Q65), a short run: transit-live.yml"]
async fn through_least_authority_a_session_of_the_layer_echoes_one_mib() {
    let url = least_authority();
    let (notes, _) = echo_session(&url, ProxyChoice::FromEnvironment, None).await;
    eprintln!("the session's notes: {notes:?}");
}
