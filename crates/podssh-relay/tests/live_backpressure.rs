//! T-062: whether the live relay closes a slow forward client with 1013
//! (`client receive backlog`), through the relay's own loop (the operator's
//! ruling of Q42, 2026-10-31). A pair's node sends a target's bytes fast; the
//! operator's leg of the pair goes to the relay through a CONNECT proxy of
//! this test whose upstream is a forward session to the relay's own host and
//! port 443, read at 16 KiB/s. An outer 1013 means that the forward road's
//! check operates; an inner 1011 `relay backpressure` of the reverse road, or
//! a slow and steady transfer, means that the forward road pushes back
//! through TCP. The bytes that the node took from its target, beside those
//! that the slow client read, say where the rest waited: taken and not read
//! means bytes held at the relay; taken no faster than read means TCP's
//! backpressure from end to end. The control, read at full speed, must carry
//! each byte and end as the target ends. On request only, as it mints tokens
//! and makes a pair:
//!
//! ```sh
//! cargo test -p podssh-relay --features pair --test live_backpressure -- --ignored --nocapture
//! ```
//!
//! No line prints a token: the proxy reads the operator's bytes, which carry
//! its token inside TLS, and never logs them.
#![cfg(feature = "pair")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::open::Request;
use podssh_relay::pair::{self, Pair, PairContext};
use podssh_relay::relay::{self, Relay, DEFAULT_RELAY_HOST};
use podssh_relay::reverse::SessionId;
use podssh_relay::reverse::{operator, run, Exit, Handler, NodeConfig, Opening, OperatorConfig, OperatorLimits};
use podssh_relay::reverse::{Settings, Wire};
use podssh_ws::session::close_code_and_reason;
use podssh_ws::{Proxy, ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::time::Instant;

const MIB: usize = 1024 * 1024;
const LIMIT: Duration = Duration::from_secs(30);
/// The control's size, and the slow run's: far past the 2 MiB of the check.
const CONTROL: usize = 8 * MIB;
const SLOW: usize = 48 * MIB;
/// How fast the slow client reads, and for how long at most: a steady rate
/// over this time is the answer of TCP's backpressure.
const RATE: usize = 16 * 1024;
const SLOW_FOR: Duration = Duration::from_secs(90);
/// More than this host's socket buffers hold (a few MiB each way): bytes
/// that the node took past this wait beyond the host.
const PAST_THIS_HOST: usize = 16 * MIB;

/// A node's target that sends each session its size from the list, in turn,
/// then ends, and counts the bytes that the node took.
struct Source(Mutex<Vec<(usize, Arc<AtomicUsize>)>>);

impl Handler for Source {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        let (size, taken) = self.0.lock().unwrap().pop().unwrap_or_default();
        Box::pin(async move {
            let (node_end, mut source) = tokio::io::duplex(256 * 1024);
            tokio::spawn(async move {
                let chunk = vec![0x5au8; 64 * 1024];
                let mut left = size;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if source.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    taken.fetch_add(n, Ordering::SeqCst);
                    left -= n;
                }
                let _ = source.shutdown().await;
            });
            Ok(node_end)
        })
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

/// The pair as a body of `/v1/pair`, to give the operator its own copy.
fn body_of(pair: &Pair) -> Vec<u8> {
    format!(
        r#"{{"name":"{}","node_token":"{}","connect_token":"{}","stop_token":"{}","expires":{}}}"#,
        pair.name,
        pair.node_token(),
        pair.connect_token(),
        pair.stop_token(),
        pair.expires_ms
    )
    .into_bytes()
}

/// What the outer forward session saw: the bytes read, the relay's Close,
/// and when it ended.
#[derive(Debug)]
struct Seen {
    bytes: usize,
    close: Option<(Option<u16>, String)>,
    elapsed: Duration,
}

/// The bytes the node took from the target, and those the outer client read,
/// so far.
#[derive(Clone, Default)]
struct Counts {
    taken: Arc<AtomicUsize>,
    read: Arc<AtomicUsize>,
}

/// A forward session through the relay to `host`:443: the relay's own loop.
async fn forward_to(host: &str) -> podssh_relay::Opened {
    let relays = relay::select_relays(Some(host), None, &[]).expect("the relay");
    let path = relay::forward_path(host, 443).expect("a path");
    let target = format!("{host}:443");
    let request = Request {
        relays: &relays,
        path: &path,
        trust: &Trust::Default,
        target: &target,
        rounds: 1,
        failover: Default::default(),
    };
    match podssh_relay::open(&request, &mut |note: &str| eprintln!("note: {note}")).await {
        Ok(opened) => opened,
        Err(failure) => panic!("no forward session to the relay itself: {:?}", failure.lines(&target)),
    }
}

/// A CONNECT proxy on the loopback for one connection, whose upstream is a
/// forward session to `host`:443 through the relay, read at `rate` bytes a
/// second, or at full speed with none. The opener's notes are not `Send`, so
/// the caller awaits the proxy in its own task.
async fn loop_proxy(
    host: String,
    rate: Option<usize>,
    read: Arc<AtomicUsize>,
) -> (Proxy, impl std::future::Future<Output = Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = async move {
        let (mut local, _) = tokio::time::timeout(LIMIT, listener.accept()).await.expect("the operator").unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 8192, "a CONNECT head of 8 KiB");
            assert_eq!(local.read(&mut byte).await.unwrap(), 1, "the CONNECT head ended early");
            head.push(byte[0]);
        }
        let asked = String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string();
        assert!(asked.starts_with(&format!("CONNECT {host}:443 ")), "{asked}");
        let session = Arc::new(forward_to(&host).await.session);
        local.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
        let (mut from_local, mut to_local) = local.into_split();
        let up = {
            let session = session.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match from_local.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if session.send_binary(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            })
        };
        let started = Instant::now();
        let (mut bytes, mut close) = (0usize, None);
        loop {
            if rate.is_some() && started.elapsed() > SLOW_FOR {
                break;
            }
            let frame = match tokio::time::timeout(3 * LIMIT, session.read_frame()).await {
                Ok(Ok(frame)) => frame,
                Ok(Err(e)) => {
                    eprintln!("the forward session failed: {e}");
                    break;
                }
                Err(_) => break,
            };
            if frame.opcode == 0x8 {
                close = Some(close_code_and_reason(&frame.payload));
                break;
            }
            bytes += frame.payload.len();
            read.fetch_add(frame.payload.len(), Ordering::SeqCst);
            if to_local.write_all(&frame.payload).await.is_err() {
                break;
            }
            if let Some(rate) = rate {
                tokio::time::sleep(Duration::from_secs_f64(frame.payload.len() as f64 / rate as f64)).await;
            }
        }
        up.abort();
        if close.is_none() {
            let _ = session.send_close(1000, "").await;
        }
        Seen { bytes, close, elapsed: started.elapsed() }
    };
    let proxy = Proxy::parse(&format!("http://127.0.0.1:{port}")).expect("the loop's proxy");
    (proxy, task)
}

/// One operator session through the loop: the bytes that reached the
/// operator, the operator's end, and what the outer session saw. Every 15 s,
/// a line gives the counts so far.
async fn through_the_loop(pair: &Pair, rate: Option<usize>, counts: Counts) -> (usize, String, Seen) {
    let (proxy, outer) = loop_proxy(pair.relay.host.clone(), rate, counts.read.clone()).await;
    let sampler = tokio::spawn(async move {
        let started = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let (taken, read) = (counts.taken.load(Ordering::SeqCst), counts.read.load(Ordering::SeqCst));
            eprintln!("at {:>3} s: the node took {taken} bytes, the client read {read}", started.elapsed().as_secs());
        }
    });
    let (io, mut user) = tokio::io::duplex(4 * MIB);
    let relay = pair.relay.clone();
    let (name, token) = (pair.name.clone(), pair.connect_token().to_string());
    let session = tokio::spawn(async move {
        let proxy = ProxyChoice::Via(proxy);
        let config = OperatorConfig {
            relay: &relay,
            name: &name,
            connect_token: &token,
            trust: &Trust::Default,
            proxy: &proxy,
            timeout: LIMIT,
            limits: OperatorLimits::default(),
            wire: Wire::Tls,
        };
        match operator::run(&config, io).await {
            Ok(outcome) => format!("{outcome:?}"),
            Err(e) => format!("the operator's socket: {e}"),
        }
    });
    let received = Arc::new(AtomicUsize::new(0));
    let reader = {
        let received = received.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = user.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                received.fetch_add(n, Ordering::SeqCst);
            }
        })
    };
    let seen = tokio::time::timeout(SLOW_FOR + 4 * LIMIT, outer).await.expect("the outer session's end");
    let inner = match tokio::time::timeout(LIMIT, session).await {
        Ok(Ok(inner)) => inner,
        _ => "no end of the operator's session in time".to_string(),
    };
    reader.abort();
    sampler.abort();
    (received.load(Ordering::SeqCst), inner, seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "the live relay: run with --ignored"]
async fn a_slow_forward_client_through_the_relay_s_own_loop() {
    let relay = Relay { host: DEFAULT_RELAY_HOST.into(), port: 443 };
    let ctx =
        PairContext { relay: &relay, trust: &Trust::Default, proxy: &ProxyChoice::FromEnvironment, timeout: LIMIT };
    let made = pair::create(&ctx).await.expect("a pair");
    let copy = pair::parse(&relay, &body_of(&made), now_ms()).expect("the same pair");
    // The sizes in turn: the control's, then the slow run's.
    let (control, slow) = (Counts::default(), Counts::default());
    let source = Source(Mutex::new(vec![(SLOW, slow.taken.clone()), (CONTROL, control.taken.clone())]));
    let stop = Arc::new(Notify::new());
    let node = {
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut config = NodeConfig {
                pair: made,
                label: None,
                trust: &Trust::Default,
                proxy: &ProxyChoice::FromEnvironment,
                timeout: LIMIT,
                settings: Settings::default(),
                repair: None,
                wire: Wire::Tls,
                say: None,
            };
            run(&mut config, Arc::new(source), async move { stop.notified().await }).await
        })
    };
    tokio::time::sleep(Duration::from_secs(3)).await;

    let (received, inner, seen) = through_the_loop(&copy, None, control.clone()).await;
    eprintln!("control: {received} bytes at the operator; the operator's end {inner}; outer {seen:?}");
    let taken = slow.taken.clone();
    let slow = through_the_loop(&copy, Some(RATE), slow).await;
    eprintln!("slow: {} bytes at the operator; the operator's end {}; outer {:?}", slow.0, slow.1, slow.2);
    let taken = taken.load(Ordering::SeqCst);
    let waited = taken - taken.min(slow.2.bytes);
    eprintln!("slow: the node took {taken} bytes of {SLOW}; {waited} more than the client read");
    let rate = slow.2.bytes as f64 / slow.2.elapsed.as_secs_f64().max(1.0) / 1024.0;
    let secs = slow.2.elapsed.as_secs_f64();
    let verdict = match &slow.2.close {
        Some((Some(1013), reason)) => format!("the forward road's check operates: 1013 {reason}"),
        _ if slow.1.contains("1011") => "the reverse road closed 1011: the forward road pushed back".into(),
        None if waited > PAST_THIS_HOST => {
            format!(
                "no close in {secs:.0} s at {rate:.1} KiB/s, with {waited} bytes past the node: none closed the client"
            )
        }
        None => format!("no close in {secs:.0} s at {rate:.1} KiB/s, {waited} bytes past the node: TCP's backpressure"),
        Some((code, reason)) => format!("another end: {code:?} {reason}"),
    };
    eprintln!("verdict: {verdict}");

    stop.notify_one();
    let exit: Exit = tokio::time::timeout(LIMIT, node).await.expect("the node's end").unwrap();
    eprintln!("node: {exit:?}");
    let stopped = pair::stop(&ctx, &copy).await;
    eprintln!("pair: {stopped:?}");

    assert_eq!(received, CONTROL, "the control carried each byte through the loop");
    assert!(
        matches!(&seen.close, Some((Some(1000), _))) || seen.close.is_none(),
        "the control ended as the target ended: {seen:?}"
    );
}
