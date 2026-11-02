//! The Wisp client of T-438, against a stand-in written from the protocol's
//! document (`wisp_support`) and against wisp-server-python, Mercury
//! Workshop's own server, on the loopback where it is installed. Two
//! streams at once on one WebSocket each carry their bytes; the client
//! sends no DATA past the server's credit, and goes on once a CONTINUE
//! gives more (planted: the credit ignored, and the test of flow control
//! fails); a stream that the server closes gives its reason; version 2
//! opens with both INFOs, and a server that requires a credential is
//! refused; the forwarder's road `wisp+ws://` carries a session with no
//! token.

mod wisp_support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_ws::forwarder::{self, Dial, Ended, Template};
use podssh_ws::url::WsUrl;
use podssh_ws::wisp::{Connect, End, Reason, Wisp, WispError, WispStream};
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wisp_support::{closed_port, echo, greeter, reference, Speaks, StandIn};

const LIMIT: Duration = Duration::from_secs(30);
const MIB: usize = 1 << 20;

static TRUST: Trust = Trust::Default;
static PROXY: ProxyChoice = ProxyChoice::Direct;

type Notes = Arc<Mutex<Vec<String>>>;

fn how(notes: &Notes) -> Connect<'static> {
    let kept = notes.clone();
    let note = Arc::new(move |text: &str| kept.lock().unwrap().push(text.to_string()));
    Connect { trust: &TRUST, proxy: &PROXY, timeout: LIMIT, note }
}

async fn connect(port: u16, notes: &Notes) -> Result<Wisp, WispError> {
    Wisp::connect(&WsUrl::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(), &how(notes)).await
}

fn pattern(size: usize, seed: u32) -> Vec<u8> {
    (0..size as u32).map(|i| (i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

/// `size` bytes through `stream` and back from an echo: the digests of
/// both.
async fn round_trip(stream: WispStream, size: usize, seed: u32) -> ([u8; 32], [u8; 32]) {
    let data = pattern(size, seed);
    let sent: [u8; 32] = Sha256::digest(&data).into();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr
    });
    let mut back = vec![0u8; size];
    tokio::time::timeout(LIMIT, rd.read_exact(&mut back)).await.expect("the echo within the limit").unwrap();
    let _ = writer.await.unwrap();
    (sent, Sha256::digest(&back).into())
}

/// Until `ready` holds, within the limit.
async fn until(what: &str, ready: impl Fn() -> bool) {
    let started = Instant::now();
    while !ready() {
        assert!(started.elapsed() < LIMIT, "{what}: not within {LIMIT:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_streams_at_once_on_one_websocket_each_carry_their_bytes() {
    // A credit of 4 packets: each MiB needs the server's CONTINUE often.
    let stand = StandIn::start(Speaks::V1, 4).await;
    let notes = Notes::default();
    let wisp = connect(stand.port, &notes).await.unwrap();
    assert_eq!((wisp.opened().version, wisp.opened().buffer, wisp.confirms()), ((1, 0), 4, false));
    let (a, b) = (echo().await, echo().await);
    let first = wisp.open("127.0.0.1", a, true).await.unwrap();
    let second = wisp.open("127.0.0.1", b, true).await.unwrap();
    assert_eq!((first.id(), second.id()), (1, 2));
    let (one, two) = tokio::join!(round_trip(first, MIB, 1), round_trip(second, MIB, 2));
    assert_eq!(one.0, one.1, "the first stream's digests");
    assert_eq!(two.0, two.1, "the second stream's digests");
    assert_ne!(one.0, two.0, "two streams, two contents");
    assert_eq!(stand.overruns(), 0, "no DATA past the credit");
    let seen = stand.seen.lock().unwrap();
    assert_eq!(seen.protocols, [Some("wisp-v2".to_string())], "one WebSocket, which offered version 2");
    assert_eq!(seen.connects, [(1, "127.0.0.1".to_string(), a), (2, "127.0.0.1".to_string(), b)]);
}

/// The flow control of the protocol: a stream whose server never gives its
/// credit back sends exactly its credit, and more once a CONTINUE comes;
/// meanwhile another stream of the same WebSocket carries its bytes.
/// Planted: the credit ignored, and this test fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_sends_no_data_past_the_server_s_credit() {
    let stand = StandIn::start(Speaks::V1, 4).await;
    let notes = Notes::default();
    let wisp = connect(stand.port, &notes).await.unwrap();
    let mut held = wisp.open("hold.test", 9, true).await.unwrap();
    assert_eq!(held.id(), 1);
    let filler = tokio::spawn(async move {
        // 2 MiB, past the credit and past the pipe in memory: it blocks.
        let _ = held.write_all(&pattern(2 * MIB, 7)).await;
        held
    });
    until("the credit's 4 packets", || stand.data_of(1) >= 4).await;
    let other = wisp.open("127.0.0.1", echo().await, true).await.unwrap();
    let (sent, back) = round_trip(other, 256 * 1024, 3).await;
    assert_eq!(sent, back, "the other stream is not held up");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!((stand.data_of(1), stand.overruns()), (4, 0), "no DATA past the credit");
    stand.grant(1, 4).await;
    until("4 more after the CONTINUE", || stand.data_of(1) >= 8).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!((stand.data_of(1), stand.overruns()), (8, 0), "the new credit, and no more");
    filler.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_that_the_server_closes_gives_its_reason() {
    let stand = StandIn::start(Speaks::V1, 16).await;
    let notes = Notes::default();
    let wisp = connect(stand.port, &notes).await.unwrap();
    let mut blocked = wisp.open("close-48.test", 22, true).await.unwrap();
    let refused = blocked.opened(LIMIT).await.unwrap_err();
    assert_eq!(refused, WispError::Closed(Reason::BLOCKED));
    assert_eq!(refused.to_string(), "the Wisp server closed the stream: 0x48, the server blocks this destination");
    assert_eq!(blocked.end(), Some(End::Closed(Reason(0x48))));
    // The connection lives on: another stream opens and carries.
    let fine = wisp.open("127.0.0.1", echo().await, true).await.unwrap();
    let (sent, back) = round_trip(fine, 64 * 1024, 5).await;
    assert_eq!(sent, back);
    // Through the forwarder's road, the reason is in the forwarder's line.
    let template = Template::parse(&format!("wisp+ws://127.0.0.1:{}/", stand.port)).unwrap();
    let road = dial(&notes, true);
    let e = forwarder::open(&template, "close-42.test", 22, &road).await.unwrap_err();
    let line = e.line(template.shown());
    let want = format!("the forwarder wisp+ws://127.0.0.1:{}/: the Wisp server closed the stream: 0x42", stand.port);
    assert!(line.starts_with(&want), "{line}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_2_opens_with_both_infos_and_confirms_each_stream() {
    let extensions = vec![(0x01, Vec::new()), (0x04, b"demo and testing only\r\n".to_vec()), (0x05, Vec::new())];
    let stand = StandIn::start(Speaks::V2 { extensions, refuse: None }, 16).await;
    let notes = Notes::default();
    let wisp = connect(stand.port, &notes).await.unwrap();
    assert_eq!((wisp.opened().version, wisp.opened().buffer, wisp.confirms()), ((2, 1), 16, true));
    assert_eq!(wisp.opened().motd.as_deref(), Some("demo and testing only"));
    assert!(notes.lock().unwrap().contains(&"the Wisp server's message: demo and testing only".to_string()));
    // This side's INFO: version 2.1, then the MOTD and the confirmation,
    // each with no payload; no UDP.
    let info = stand.seen.lock().unwrap().client_infos.clone();
    assert_eq!(info, [vec![2, 1, 0x04, 0, 0, 0, 0, 0x05, 0, 0, 0, 0]]);
    let mut stream = wisp.open("127.0.0.1", echo().await, true).await.unwrap();
    stream.opened(LIMIT).await.unwrap();
    let (sent, back) = round_trip(stream, 256 * 1024, 9).await;
    assert_eq!(sent, back);
    let mut refused = wisp.open("close-44.test", 22, true).await.unwrap();
    assert_eq!(refused.opened(LIMIT).await.unwrap_err(), WispError::Closed(Reason::REFUSED));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_2_refusals_say_why() {
    // A server that requires a password: this side's CLOSE 0x04 on stream 0.
    let password = StandIn::start(Speaks::V2 { extensions: vec![(0x02, vec![1])], refuse: None }, 16).await;
    let notes = Notes::default();
    let e = connect(password.port, &notes).await.unwrap_err();
    assert!(e.to_string().contains("requires a user name and a password"), "{e}");
    until("the client's CLOSE", || !password.seen.lock().unwrap().closes.is_empty()).await;
    assert_eq!(password.seen.lock().unwrap().closes, [(0, 0x04)]);
    // A server that refuses the connection: its reason.
    let throttled = StandIn::start(Speaks::V2 { extensions: Vec::new(), refuse: Some(0x49) }, 16).await;
    let e = connect(throttled.port, &notes).await.unwrap_err();
    assert_eq!(e, WispError::Refused(Reason::THROTTLED));
}

fn dial(notes: &Notes, close_at_end: bool) -> Dial<'static> {
    let kept = notes.clone();
    let note = Arc::new(move |text: &str| kept.lock().unwrap().push(text.to_string()));
    Dial { trust: &TRUST, proxy: &PROXY, timeout: LIMIT, close_at_end, note }
}

/// The forwarder's road: a session of 1 MiB each way, no token, and this
/// side's CLOSE at its end, which is an ordinary one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_forwarder_s_road_carries_a_session_and_closes_its_stream_at_the_end() {
    let stand = StandIn::start(Speaks::V1, 8).await;
    let notes = Notes::default();
    let template = Template::parse(&format!("wisp+ws://127.0.0.1:{}/", stand.port)).unwrap();
    let target = echo().await;
    let carried = forwarder::open(&template, "127.0.0.1", target, &dial(&notes, true)).await.unwrap();
    let data = pattern(MIB, 11);
    let (mut rd, mut wr) = tokio::io::split(carried.stream);
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&sent).await.unwrap();
        wr
    });
    let mut back = vec![0u8; MIB];
    tokio::time::timeout(LIMIT, rd.read_exact(&mut back)).await.expect("within the limit").unwrap();
    assert!(back == data, "equal bytes");
    let mut wr = writer.await.unwrap();
    wr.shutdown().await.unwrap();
    until("this side's CLOSE", || !stand.seen.lock().unwrap().closes.is_empty()).await;
    assert_eq!(stand.seen.lock().unwrap().closes, [(1, 0x02)]);
    until("the session's end", || carried.status.get().is_some()).await;
    assert!(matches!(carried.status.get(), Some(Ended::Closed { code: Some(1000), .. })), "{:?}", carried.status.get());
    assert_eq!(stand.overruns(), 0);
    let seen = stand.seen.lock().unwrap();
    assert!(seen.headers[0].iter().all(|h| h != "x-relay-token" && h != "authorization"), "{:?}", seen.headers);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reference_two_streams_at_once_each_carry_their_bytes() {
    let Some(server) = reference::start() else { return };
    let notes = Notes::default();
    let wisp = connect(server.port, &notes).await.unwrap();
    // Version 1 with 128 packets of credit, as its source says.
    assert_eq!((wisp.opened().version, wisp.opened().buffer), ((1, 0), 128));
    let (a, b) = (echo().await, echo().await);
    let first = wisp.open("127.0.0.1", a, true).await.unwrap();
    let second = wisp.open("127.0.0.1", b, true).await.unwrap();
    // 5 MiB each: past 128 packets of 32 KiB, so each goes on only by the
    // server's CONTINUE.
    let (one, two) = tokio::join!(round_trip(first, 5 * MIB, 21), round_trip(second, 5 * MIB, 22));
    assert_eq!(one.0, one.1, "the first stream's digests");
    assert_eq!(two.0, two.1, "the second stream's digests");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reference_a_stream_that_the_server_closes_gives_its_reason() {
    let Some(server) = reference::start() else { return };
    let notes = Notes::default();
    let wisp = connect(server.port, &notes).await.unwrap();
    let mut nowhere = wisp.open("127.0.0.1", closed_port(), true).await.unwrap();
    let refused = nowhere.opened(LIMIT).await.unwrap_err();
    assert_eq!(refused, WispError::Closed(Reason::UNREACHABLE), "its one reason for a stream it cannot open");
    // A target that says its words and closes: its bytes, then 0x02.
    let mut said = wisp.open("127.0.0.1", greeter(b"hello from the target\n").await, false).await.unwrap();
    let mut all = Vec::new();
    tokio::time::timeout(LIMIT, said.read_to_end(&mut all)).await.expect("within the limit").unwrap();
    assert_eq!(all, b"hello from the target\n");
    assert_eq!(said.end(), Some(End::Closed(Reason::VOLUNTARY)));
    // And through the forwarder's road.
    let template = Template::parse(&format!("wisp+ws://127.0.0.1:{}/", server.port)).unwrap();
    let e = forwarder::open(&template, "127.0.0.1", closed_port(), &dial(&notes, true)).await.unwrap_err();
    assert!(e.line(template.shown()).contains("closed the stream: 0x42"), "{}", e.line(template.shown()));
}
