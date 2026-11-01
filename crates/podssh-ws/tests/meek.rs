//! meek_lite (T-385) against a stand-in of meek-server 0.38.0 written here,
//! which reads each request as meek-server does: a `POST` whose
//! `X-Session-Id` has 8 characters at least (else 400), a body of 64 KiB at
//! most, and an answer of 200 with the session's bytes; its "bridge" echoes
//! what each session sent. Plain HTTP, and TLS for a front, the stand-in's
//! root in a file as `--ca-file` gives it, the names pinned to the loopback
//! (no DNS). The control of the stand-in's check: a POST with no id gets 400.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_ws::meek::{self, Args, Ended, MAX_PAYLOAD};
use podssh_ws::pt::Reach;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const LIMIT: Duration = Duration::from_secs(20);

/// What the stand-in saw of one request.
#[derive(Debug, Clone)]
struct Seen {
    at: Instant,
    target: String,
    host: Option<String>,
    session: Option<String>,
    agent: bool,
    body: usize,
    sni: Option<String>,
}

/// The stand-in's state: what it saw, its sessions, and how it answers.
#[derive(Default)]
struct State {
    seen: Vec<Seen>,
    connections: usize,
    sessions: HashMap<String, Vec<u8>>,
    refuse: bool,
}

type Shared = Arc<Mutex<State>>;

fn settings(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn reach(trust: Trust) -> Reach {
    Reach { proxy: ProxyChoice::Direct, trust, wait: Duration::from_secs(5) }
}

/// The names of the fronted tests, on the loopback; the same list in each
/// test, as the pins are the process's.
fn pins() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    podssh_ws::resolve::set_pins(vec![("front.meek.test".into(), lo), ("real.meek.test".into(), lo)]);
}

/// The root of the stand-in's certificate for `name`, in a file.
fn root_file(name: &str, tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-meek-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(name), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

/// A request: its method, its target, its headers (names in lower case)
/// and its body.
type Request = (String, String, Vec<(String, String)>, Vec<u8>);

/// One request's head and body, or `None` at the connection's end.
async fn read_request<S: AsyncRead + Unpin>(s: &mut S, have: &mut Vec<u8>) -> Option<Request> {
    let end = loop {
        if let Some(at) = have.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let mut chunk = [0u8; 8192];
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => have.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&have[..end]).into_owned();
    have.drain(..end);
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let length: usize =
        headers.iter().find(|(n, _)| n == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    while have.len() < length {
        let mut chunk = [0u8; 8192];
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => have.extend_from_slice(&chunk[..n]),
        }
    }
    let body = have.drain(..length).collect();
    Some((method, target, headers, body))
}

/// Serve one connection as meek-server does, its requests one after the
/// other on it.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, sni: Option<String>, state: Shared) {
    let mut have = Vec::new();
    while let Some((method, target, headers, body)) = read_request(&mut s, &mut have).await {
        let get = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
        let session = get("x-session-id");
        let answer = {
            let mut state = state.lock().unwrap();
            state.seen.push(Seen {
                at: Instant::now(),
                target,
                host: get("host"),
                session: session.clone(),
                agent: get("user-agent").is_some(),
                body: body.len(),
                sni: sni.clone(),
            });
            match session {
                _ if method != "POST" || body.len() > MAX_PAYLOAD => Err(400),
                Some(id) if id.len() >= 8 && !state.refuse => {
                    let pending = state.sessions.entry(id).or_default();
                    pending.extend_from_slice(&body);
                    let n = pending.len().min(MAX_PAYLOAD);
                    Ok(pending.drain(..n).collect::<Vec<u8>>())
                }
                Some(_) if state.refuse => Err(500),
                _ => Err(400),
            }
        };
        let written = match answer {
            Ok(bytes) => {
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                    bytes.len()
                );
                s.write_all(&[head.as_bytes(), bytes.as_slice()].concat()).await
            }
            Err(status) => s.write_all(format!("HTTP/1.1 {status} No\r\nContent-Length: 0\r\n\r\n").as_bytes()).await,
        };
        if written.is_err() {
            return;
        }
    }
}

/// A stand-in on the loopback, plain or with TLS for `tls`'s name.
async fn stand_in(tls: Option<&str>, refuse: bool) -> (u16, Shared) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state: Shared = Arc::new(Mutex::new(State { refuse, ..State::default() }));
    let acceptor = tls.map(|name| cert::server_for(name).unwrap().0);
    let shared = state.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            shared.lock().unwrap().connections += 1;
            let (state, acceptor) = (shared.clone(), acceptor.clone());
            tokio::spawn(async move {
                match acceptor {
                    None => serve(tcp, None, state).await,
                    Some(acceptor) => {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            let sni = tls.get_ref().1.server_name().map(str::to_string);
                            serve(tls, sni, state).await;
                        }
                    }
                }
            });
        }
    });
    (port, state)
}

/// `bytes` through a session of `args`, and the bytes that came back.
async fn through(args: &Args, trust: Trust, bytes: &[u8]) -> (Vec<u8>, tokio::task::JoinHandle<Ended>) {
    let session = meek::open(args, &reach(trust)).await.unwrap_or_else(|why| panic!("{why}"));
    let (mut ours, theirs) = tokio::io::duplex(1 << 20);
    let carried = tokio::spawn(session.carry(theirs));
    let mut back = vec![0u8; bytes.len()];
    let echoed = async {
        ours.write_all(bytes).await.unwrap();
        ours.read_exact(&mut back).await.unwrap();
    };
    tokio::time::timeout(LIMIT, echoed).await.expect("the echo within the limit");
    drop(ours);
    (back, carried)
}

/// 200 KB go out in POSTs of 64 KiB at most, joined, on one kept
/// connection, each with the one session's id of 32 hex digits, the URL's
/// host and no agent; they come back whole, and the session ends with its
/// local side.
#[tokio::test]
async fn bytes_go_both_ways_in_posts_of_64_kib_at_most_on_one_connection() {
    let (port, state) = stand_in(None, false).await;
    let url = format!("http://127.0.0.1:{port}/");
    let args = Args::parse(&settings(&[("url", url.as_str())])).unwrap();
    let sent: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (back, carried) = through(&args, Trust::Default, &sent).await;
    assert!(back == sent, "the bytes came back changed");
    let ended = tokio::time::timeout(LIMIT, carried).await.expect("the session ends with its local side").unwrap();
    assert_eq!(ended, Ended::Closed);
    let state = state.lock().unwrap();
    assert_eq!(state.connections, 1, "the connection was not kept");
    let ids: Vec<&Option<String>> = state.seen.iter().map(|s| &s.session).collect();
    let id = ids[0].clone().expect("an id");
    assert!(id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
    assert!(ids.iter().all(|s| s.as_deref() == Some(id.as_str())), "more than one session: {ids:?}");
    for seen in &state.seen {
        assert_eq!((seen.target.as_str(), seen.host.as_deref()), ("/", Some(format!("127.0.0.1:{port}").as_str())));
        assert!(!seen.agent, "a User-Agent went");
    }
    let largest = state.seen.iter().map(|s| s.body).max().unwrap();
    assert_eq!(largest, MAX_PAYLOAD, "no body was joined up to 64 KiB, or one went past it");
}

/// Fronted: TLS goes to the front, with its name, and is checked for it;
/// `Host` names the URL's host, which TLS never sees.
#[tokio::test]
async fn fronting_sends_the_front_to_tls_and_the_url_s_host_to_host() {
    pins();
    let (port, state) = stand_in(Some("front.meek.test"), false).await;
    let root = root_file("front.meek.test", "front");
    let front = format!("front.meek.test:{port}");
    let args = Args::parse(&settings(&[("url", "https://real.meek.test/"), ("front", front.as_str())])).unwrap();
    let (back, _) = through(&args, Trust::File(root.clone()), b"fronted").await;
    assert_eq!(back, b"fronted");
    let state = state.lock().unwrap();
    for seen in &state.seen {
        assert_eq!(seen.sni.as_deref(), Some("front.meek.test"));
        assert_eq!(seen.host.as_deref(), Some("real.meek.test"));
    }
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A front whose certificate is for another name is refused at TLS, before
/// any POST: there is no bypass of the check.
#[tokio::test]
async fn a_front_whose_certificate_names_another_host_is_refused() {
    pins();
    let (port, state) = stand_in(Some("other.meek.test"), false).await;
    let root = root_file("other.meek.test", "other");
    let front = format!("front.meek.test:{port}");
    let args = Args::parse(&settings(&[("url", "https://real.meek.test/"), ("front", front.as_str())])).unwrap();
    let refused = meek::open(&args, &reach(Trust::File(root.clone()))).await.expect_err("a refusal at TLS");
    assert!(refused.contains("TLS with front.meek.test failed"), "{refused}");
    assert!(state.lock().unwrap().seen.is_empty(), "a POST went");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A server that refuses each POST: 10 exchanges, 100 ms apart, then the
/// session ends and says the status.
#[tokio::test]
async fn ten_refusals_end_the_session_and_say_the_status() {
    let (port, state) = stand_in(None, true).await;
    let url = format!("http://127.0.0.1:{port}/");
    let args = Args::parse(&settings(&[("url", url.as_str())])).unwrap();
    let session = meek::open(&args, &reach(Trust::Default)).await.unwrap();
    let (mut ours, theirs) = tokio::io::duplex(1024);
    ours.write_all(b"hello").await.unwrap();
    let started = Instant::now();
    let ended = tokio::time::timeout(LIMIT, session.carry(theirs)).await.expect("the session ends");
    let why = ended.failure().expect("a failure").to_string();
    assert!(why.contains("500") && why.contains("after 10 exchanges"), "{why}");
    assert_eq!(state.lock().unwrap().seen.len(), 10);
    assert!(started.elapsed() >= Duration::from_millis(900), "no pause between refusals");
}

/// With nothing to send, the polls back off: at 0.1, 0.25, 0.475, 0.81 and
/// 1.32 s, each with no body, the gaps growing.
#[tokio::test]
async fn with_nothing_to_send_the_polls_back_off() {
    let (port, state) = stand_in(None, false).await;
    let url = format!("http://127.0.0.1:{port}/");
    let args = Args::parse(&settings(&[("url", url.as_str())])).unwrap();
    let session = meek::open(&args, &reach(Trust::Default)).await.unwrap();
    let (ours, theirs) = tokio::io::duplex(1024);
    let started = Instant::now();
    let carried = tokio::spawn(session.carry(theirs));
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let state = state.lock().unwrap();
    let polls: Vec<Duration> = state.seen.iter().map(|s| s.at - started).collect();
    assert!((3..=7).contains(&polls.len()), "{polls:?}");
    assert!(state.seen.iter().all(|s| s.body == 0), "a poll carried a body");
    let gaps: Vec<Duration> = polls.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(gaps.last() > gaps.first(), "the polls did not back off: {polls:?}");
    drop((ours, carried));
}

/// The control of the stand-in: a POST with no session id gets 400, as from
/// meek-server, so that a client which sent none would fail above.
#[tokio::test]
async fn the_stand_in_refuses_a_post_with_no_session_id() {
    let (port, _) = stand_in(None, false).await;
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
    let mut answer = [0u8; 12];
    tokio::time::timeout(LIMIT, tcp.read_exact(&mut answer)).await.unwrap().unwrap();
    assert_eq!(&answer, b"HTTP/1.1 400");
}
