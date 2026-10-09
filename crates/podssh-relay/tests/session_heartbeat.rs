//! The heartbeat of the resumable layer (T-154), on tokio's paused clock:
//! over 200 s of idle time each end sends a record at least each 10 s, so the
//! relay never sees a quiet link; a link that carries nothing from the far
//! end for 30 s is dead, so a resume can replace it; and a peer that did not
//! name `heartbeat.v1` gets no `PING`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::time::Instant;

use podssh_relay::session::client::{self, Outcome};
use podssh_relay::session::pump::{DEAD_AFTER, PING_EVERY};
use podssh_relay::session::{
    far, Acceptance, Ask, Decoder, End, Hello, Nonce, OsEntropy, Record, Role, SessionId, Sessions, Settings,
};

const PIPE: usize = 256 * 1024;

/// The records that passed one way, with the time of each.
type Log = Arc<Mutex<Vec<(Instant, Record)>>>;

/// Copy `from` into `to`, and note each whole record that passes.
async fn tap<R, W>(mut from: R, mut to: W, log: Log)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = Decoder::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        decoder.push(&buf[..n]);
        while let Ok(Some(record)) = decoder.next() {
            log.lock().unwrap().push((Instant::now(), record));
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

/// The largest wait between two records of `log` after `from`, and the
/// count of its `PING`s.
fn gaps(log: &Log, from: Instant, to: Instant) -> (Duration, usize) {
    let log = log.lock().unwrap();
    let times: Vec<Instant> = log.iter().map(|(t, _)| *t).filter(|t| *t >= from).collect();
    let mut widest = Duration::ZERO;
    let mut last = from;
    for t in times.iter().chain(std::iter::once(&to)) {
        widest = widest.max(t.duration_since(last));
        last = *t;
    }
    let pings = log.iter().filter(|(t, r)| *t >= from && matches!(r, Record::Ping { .. })).count();
    (widest, pings)
}

#[tokio::test(start_paused = true)]
async fn an_idle_session_carries_a_record_each_way_each_10_s() {
    let (client_link, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far_link) = tokio::io::duplex(PIPE);
    let (up_log, down_log): (Log, Log) = (Arc::default(), Arc::default());
    let (cr, cw) = tokio::io::split(relay_client);
    let (fr, fw) = tokio::io::split(relay_far);
    tokio::spawn(tap(cr, fw, up_log.clone()));
    tokio::spawn(tap(fr, cw, down_log.clone()));

    let sessions = Arc::new(Mutex::new(Sessions::new()));
    let far_sessions = sessions.clone();
    let (target, _idle_target) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let accepted =
            far::accept(far_link, Role::NODE, Settings::default(), &far_sessions, &mut OsEntropy).await.unwrap();
        accepted.run(target, &far_sessions).await
    });
    let client = client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy).await.unwrap();
    let (_idle_app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(client.run(app_end));

    let start = Instant::now();
    tokio::time::sleep(Duration::from_secs(200)).await;
    let end = Instant::now();
    assert!(!session.is_finished(), "an idle session goes on");
    for (way, log) in [("client to far end", &up_log), ("far end to client", &down_log)] {
        let (widest, pings) = gaps(log, start, end);
        assert!(widest <= PING_EVERY + Duration::from_secs(1), "{way}: {widest:?} with no record");
        assert!(pings >= 18, "{way}: {pings} pings in 200 s");
    }
    // A `PONG` answers each `PING`: the records go both ways.
    let pongs = down_log.lock().unwrap().iter().filter(|(_, r)| matches!(r, Record::Pong { .. })).count();
    assert!(pongs >= 18, "{pongs} pongs");
}

/// A far end that greets with `features`, accepts a new session, and then
/// reads each byte and sends nothing more.
async fn silent_far_end(mut far: DuplexStream, features: &[&str]) {
    let hello = Hello {
        version: 1,
        role: Role::NODE,
        nonce: Nonce([3; 32]),
        features: features.iter().map(|f| f.to_string()).collect(),
    };
    far.write_all(&Record::Greeting(hello).to_bytes().unwrap()).await.unwrap();
    let mut decoder = Decoder::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if let Ok(Some(Record::Open { .. })) = decoder.next() {
            break;
        }
        let n = far.read(&mut buf).await.unwrap();
        decoder.push(&buf[..n]);
    }
    // RFC 7748's public key of Bob: any key that is not of low order.
    let public: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83,
        0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    ];
    let accept = Record::Accept(Acceptance::New { id: SessionId([9; 16]), public });
    far.write_all(&accept.to_bytes().unwrap()).await.unwrap();
    while let Ok(n) = far.read(&mut buf).await {
        if n == 0 {
            return;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_link_that_carries_nothing_for_30_s_is_dead() {
    let (client_link, far) = tokio::io::duplex(PIPE);
    tokio::spawn(silent_far_end(far, &["replay.v1", "heartbeat.v1"]));
    let client = client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy).await.unwrap();
    let (_idle_app, app_end) = tokio::io::duplex(PIPE);
    let start = Instant::now();
    let outcome = client.run(app_end).await;
    let after = start.elapsed();
    let Outcome::Layer(ended) = outcome else { panic!("{outcome:?}") };
    let End::Lost(Some(e)) = &ended.end else { panic!("{ended:?}") };
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
    assert!(e.to_string().contains("nothing came from the far end for 30 s"), "{e}");
    assert!(after >= DEAD_AFTER && after <= DEAD_AFTER + Duration::from_secs(1), "dead after {after:?}");
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_did_not_name_the_heartbeat_gets_no_ping() {
    let (client_link, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    let up_log: Log = Arc::default();
    let (cr, cw) = tokio::io::split(relay_client);
    let (fr, fw) = tokio::io::split(relay_far);
    tokio::spawn(tap(cr, fw, up_log.clone()));
    tokio::spawn(tap(fr, cw, Arc::default()));
    tokio::spawn(silent_far_end(far, &["replay.v1"]));
    let client = client::start(client_link, Ask::New, Settings::default(), &mut OsEntropy).await.unwrap();
    let (_idle_app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(client.run(app_end));
    tokio::time::sleep(Duration::from_secs(200)).await;
    assert!(!session.is_finished(), "with no heartbeat, silence is no loss");
    let pings = up_log.lock().unwrap().iter().filter(|(_, r)| matches!(r, Record::Ping { .. })).count();
    assert_eq!(pings, 0);
}
