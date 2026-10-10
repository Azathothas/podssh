//! The end-to-end channel above the resumable layer (T-088): one handshake
//! for a session, which each resume on a new link carries on, with one
//! connection to the target; and the channel with no layer, as `podssh node
//! --plain` serves a session.
#![cfg(feature = "pair")]

mod e2e_harness;

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;

use e2e_harness::{identity, node, LIMIT, PIPE};
use podssh_relay::e2e::ends;
use podssh_relay::reverse::{E2e, Handler, Layered, Opening, SessionId as RelayId};
use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::resume::{self, Next};
use podssh_relay::session::{Ask, End, Ended, OsEntropy, Settings};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

const MIB: usize = 1 << 20;

/// A target that echoes each byte; it counts its opens.
struct Echo {
    opened: Arc<AtomicUsize>,
}

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: RelayId) -> Opening<DuplexStream> {
        let ready = e2e_harness::echo(self.opened.clone())();
        Box::pin(ready)
    }
}

fn relay_id(n: u8) -> RelayId {
    RelayId::parse(format!("{:032x}", n).as_bytes()).unwrap()
}

async fn copy_until<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(from: &mut R, to: &mut W, left: &AtomicI64) {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_channel_rides_the_layer_through_cut_links_with_one_handshake() {
    let opened = Arc::new(AtomicUsize::new(0));
    let (node_end, lines) = node(identity(2), |_| Ok(()));
    let settings = Settings::default();
    let handler = Arc::new(Layered::new(E2e::new(Echo { opened: opened.clone() }, node_end), settings, 64 * MIB));
    let first = session_of(handler.as_ref(), relay_id(1), Some(3 * MIB)).await;
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await.unwrap();
    let cuts = Arc::new(std::sync::Mutex::new(vec![Some(5 * MIB), None].into_iter()));
    let ids = Arc::new(AtomicUsize::new(2));
    let connect = {
        let handler = handler.clone();
        move |_: &Ended| {
            let (handler, cut) = (handler.clone(), cuts.lock().unwrap().next().flatten());
            let id = relay_id(ids.fetch_add(1, Ordering::SeqCst) as u8);
            async move { Next::Link(session_of(handler.as_ref(), id, cut).await) }
        }
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let node_public = identity(2).public();
    let (cipher, e2e) = ends::operator(app_end, identity(1), move |key| {
        (key == &node_public).then_some(()).ok_or_else(|| "not the node".to_string())
    });
    let e2e = tokio::spawn(e2e);
    let layer = tokio::spawn(async move { resume::run(client, cipher, connect, |_| {}, &mut OsEntropy).await });

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
    tokio::time::timeout(2 * LIMIT, r.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(Sha256::digest(&back), Sha256::digest(&sent), "the echo came back whole across the cuts");
    let mut w = writer.await.unwrap();
    w.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(LIMIT, r.read_to_end(&mut rest)).await.unwrap().unwrap();
    assert!(rest.is_empty());

    let reached = tokio::time::timeout(LIMIT, e2e).await.unwrap().unwrap().unwrap();
    assert_eq!(reached, identity(2).public());
    let outcome = tokio::time::timeout(LIMIT, layer).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd | End::Closed(_))),
        "{outcome:?}"
    );
    assert_eq!(opened.load(Ordering::SeqCst), 1, "one connection to the target for the session");
    let lines = lines.lock().unwrap().clone();
    assert_eq!(lines.iter().filter(|l| l.contains("came in")).count(), 1, "one handshake for the session: {lines:?}");
}

/// With no layer (`podssh node --plain`), the relay's session carries the
/// channel as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_channel_runs_with_no_layer_as_the_plain_mode_serves_it() {
    let opened = Arc::new(AtomicUsize::new(0));
    let (node_end, _lines) = node(identity(2), |_| Ok(()));
    let handler = E2e::new(Echo { opened: opened.clone() }, node_end);
    let mut node_side = handler.open(relay_id(1)).await.unwrap();
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let (mut cipher, e2e) = ends::operator(app_end, identity(1), |_| Ok(()));
    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut cipher, &mut node_side).await;
    });
    let e2e = tokio::spawn(e2e);
    let sent: Vec<u8> = (0..MIB).map(|i| (i % 253) as u8).collect();
    assert_eq!(e2e_harness::echo_back(&mut app, &sent).await.unwrap(), sent);
    app.shutdown().await.unwrap();
    assert!(tokio::time::timeout(LIMIT, e2e).await.unwrap().unwrap().is_ok());
    assert_eq!(opened.load(Ordering::SeqCst), 1);
}
