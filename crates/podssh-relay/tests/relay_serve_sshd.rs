//! An SSH client on podssh's relay role's own port (T-644, GitHub #142), on
//! the loopback. The role takes each connection as `podssh relay serve`
//! takes it (`serve::listener::connection`), with `--sshd` naming a stand-in
//! sshd of the test's, which sends its version line and keeps each byte that
//! it reads: a client's version line, and each byte after it, reach the sshd
//! whole and in order, also a line that comes in parts, and the sshd's line
//! comes back; OpenSSH's sshd, where this host has one, answers through the
//! role. The role's policy is the default one, which dials no loopback
//! target: the sshd is no target of it. Beside the sshd, a request of HTTP
//! still meets the cleartext road and a record of TLS goes to TLS; with the
//! cleartext road off, SSH still reaches the sshd. A start that stops short
//! of `SSH-`, or none at all, is no SSH, and its bytes stay where they were.
//! With no sshd named, an SSH client meets the cleartext road, which answers
//! HTTP once a head ends. An sshd that does not answer gets the client one
//! line that says so, and the owner a line that says why.
//!
//!     cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_sshd
#![cfg(all(feature = "serve", feature = "plain-ws"))]

mod http_road_harness;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::serve::listener::{connection, Door};
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{self, sshd, tokens, Config, Limits, Mint};
use podssh_ws::cleartext::{self, Heard};
use podssh_ws::tls_server::{acceptor_for, Served, HTTP1};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(20);

/// OpenSSH's client's version line, which it sends first.
const CLIENT: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";
/// The stand-in sshd's version line.
const SERVER: &[u8] = b"SSH-2.0-stand-in-sshd-of-the-test\r\n";

/// The role on a free port of the loopback, minting for anyone, its targets
/// public alone, with the cleartext road beside TLS when `cleartext` and
/// SSH to `sshd` when one is named; and what it said. TLS has no
/// certificate here: a record of TLS is only to be told from SSH.
struct Role {
    port: u16,
    events: Arc<Mutex<Vec<String>>>,
}

impl Role {
    async fn start(cleartext: bool, sshd: Option<SocketAddr>) -> Role {
        let bound = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
        let port = bound.local_addr().unwrap().port();
        let events = Arc::new(Mutex::new(Vec::new()));
        let said = events.clone();
        let say: serve::Events = Box::new(move |line: &str| said.lock().unwrap().push(line.to_string()));
        let cfg = Arc::new(Config {
            version: "podssh test".into(),
            mint: Mint::Anyone,
            tokens: tokens::Tokens::new([7; 32]),
            policy: Policy::default(),
            egress: Default::default(),
            limits: Limits::default(),
            pairs: Default::default(),
            resumes: Default::default(),
            answered: Default::default(),
            brake: Default::default(),
            usage: Default::default(),
            events: Some(say),
        });
        let acceptor = acceptor_for(Served::new(None), &[HTTP1]).expect("an acceptor");
        let door = Door { acceptor, cleartext, sshd, published: Default::default() };
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = bound.accept().await {
                tokio::spawn(connection(tcp, peer.ip(), door.clone(), cfg.clone()));
            }
        });
        Role { port, events }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    /// Whether the role said a line that holds `text`.
    fn said(&self, text: &str) -> bool {
        self.events().iter().any(|line| line.contains(text))
    }

    /// Until the role says `text`, `LIMIT` at most.
    async fn until_said(&self, text: &str) {
        let deadline = Instant::now() + LIMIT;
        while !self.said(text) {
            assert!(Instant::now() < deadline, "the role never said {text:?}: {:?}", self.events());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn connect(&self) -> TcpStream {
        TcpStream::connect(("127.0.0.1", self.port)).await.expect("the role's port")
    }
}

/// A stand-in sshd on the loopback: it sends [`SERVER`] to each connection,
/// keeps each byte that it reads, in order, and counts its connections.
struct Stand {
    addr: SocketAddr,
    got: Arc<Mutex<Vec<u8>>>,
    taken: Arc<AtomicUsize>,
}

impl Stand {
    async fn start() -> Stand {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (got, taken) = (Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicUsize::new(0)));
        let (kept, counted) = (got.clone(), taken.clone());
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let kept = kept.clone();
                tokio::spawn(async move {
                    let _ = tcp.write_all(SERVER).await;
                    let mut chunk = vec![0u8; 16 * 1024];
                    loop {
                        match tcp.read(&mut chunk).await {
                            Ok(n) if n > 0 => kept.lock().unwrap().extend_from_slice(&chunk[..n]),
                            _ => break,
                        }
                    }
                });
            }
        });
        Stand { addr, got, taken }
    }

    /// What it read, once `len` bytes came or `LIMIT` passed.
    async fn read(&self, len: usize) -> Vec<u8> {
        let deadline = Instant::now() + LIMIT;
        while self.got.lock().unwrap().len() < len && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.got.lock().unwrap().clone()
    }

    fn connections(&self) -> usize {
        self.taken.load(Ordering::SeqCst)
    }
}

/// `size` bytes that are not all one, as the binary packets after a version
/// line are.
fn payload(size: usize) -> Vec<u8> {
    (0..size as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

/// The first line that `tcp` reads, within `LIMIT`.
async fn line_of(tcp: &mut TcpStream) -> Vec<u8> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\n") {
        match tokio::time::timeout(LIMIT, tcp.read(&mut byte)).await {
            Ok(Ok(1)) => line.push(byte[0]),
            other => panic!("no whole line: {other:?}, after {:?}", String::from_utf8_lossy(&line)),
        }
    }
    line
}

/// Each byte that `tcp` reads to its end, within `LIMIT`.
async fn to_end(tcp: &mut TcpStream) -> Vec<u8> {
    let mut answer = Vec::new();
    let read = tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await;
    assert!(matches!(read, Ok(Ok(_))), "no end in time: {read:?}");
    answer
}

/// The client's version line and 64 KiB after it, as one write: the sshd
/// reads each byte as it was sent, the first four among them, and its own
/// line comes back. The owner's lines name the client and the role's end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_line_and_each_byte_after_it_reach_the_named_sshd_whole() {
    let stand = Stand::start().await;
    let role = Role::start(true, Some(stand.addr)).await;
    let mut sent = CLIENT.to_vec();
    sent.extend_from_slice(&payload(64 * 1024));
    let mut tcp = role.connect().await;
    tcp.write_all(&sent).await.unwrap();
    assert_eq!(line_of(&mut tcp).await, SERVER, "the sshd's version line came back");
    tcp.shutdown().await.unwrap();
    let got = stand.read(sent.len()).await;
    assert_eq!(got.len(), sent.len(), "the sshd read {} bytes of {}", got.len(), sent.len());
    assert!(got == sent, "the sshd read the client's bytes whole: {:?}", String::from_utf8_lossy(&got[..64]));
    assert_eq!(stand.connections(), 1);
    role.until_said("ended after").await;
    let events = role.events();
    let from = events.iter().find(|l| l.starts_with("sshd from 127.0.0.1:")).cloned().unwrap_or_default();
    assert!(from.contains(", at the sshd as 127.0.0.1:"), "the owner's line: {events:?}");
    assert!(!role.said("cleartext"), "no cleartext road: {events:?}");
}

/// A version line that comes in parts, `S`, `SH`, then the rest, is waited
/// for, and reaches the sshd whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_line_in_parts_is_waited_for_and_reaches_the_sshd_whole() {
    let stand = Stand::start().await;
    let role = Role::start(true, Some(stand.addr)).await;
    let mut tcp = role.connect().await;
    for part in [&CLIENT[..1], &CLIENT[1..3], &CLIENT[3..]] {
        tcp.write_all(part).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert_eq!(line_of(&mut tcp).await, SERVER);
    assert_eq!(stand.read(CLIENT.len()).await, CLIENT, "the line, whole");
}

/// OpenSSH's sshd, software that podssh did not write, says its version line
/// to an SSH client on the role's port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openssh_s_sshd_answers_an_ssh_client_on_the_role_s_port() {
    let server = match http_road_harness::sshd("sshd-door") {
        Ok(server) => server,
        Err(why) => return eprintln!("did not run: {why}"),
    };
    let role = Role::start(true, Some(SocketAddr::from(([127, 0, 0, 1], server.port)))).await;
    let mut tcp = role.connect().await;
    tcp.write_all(CLIENT).await.unwrap();
    let line = line_of(&mut tcp).await;
    assert!(line.starts_with(b"SSH-2.0-OpenSSH"), "{:?}", String::from_utf8_lossy(&line));
}

/// Beside the sshd, a request of HTTP gets the cleartext road's answer, and
/// a record of TLS goes to TLS: neither reaches the sshd.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn beside_the_sshd_http_meets_the_cleartext_road_and_tls_goes_to_tls() {
    let stand = Stand::start().await;
    let role = Role::start(true, Some(stand.addr)).await;
    let mut tcp = role.connect().await;
    tcp.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").await.unwrap();
    let answer = String::from_utf8_lossy(&to_end(&mut tcp).await).into_owned();
    assert!(answer.starts_with("HTTP/1.1 200") && answer.contains("tcp-ssh-relay"), "{answer}");
    // A record of TLS's handshake: a ClientHello of no length, which TLS
    // refuses, then the client's end, so that no read waits for more.
    let mut tcp = role.connect().await;
    tcp.write_all(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]).await.unwrap();
    tcp.shutdown().await.unwrap();
    let answer = to_end(&mut tcp).await;
    assert!(!answer.starts_with(b"SSH-") && !answer.starts_with(b"HTTP/"), "{:?}", String::from_utf8_lossy(&answer));
    assert_eq!(stand.connections(), 0, "the sshd was reached: {:?}", role.events());
    assert_eq!(role.events(), ["cleartext GET /health"], "one request of the cleartext road");
}

/// With the cleartext road off, SSH still reaches the sshd, and a request
/// of HTTP meets TLS alone, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_cleartext_road_off_ssh_still_reaches_the_sshd() {
    let stand = Stand::start().await;
    let role = Role::start(false, Some(stand.addr)).await;
    let mut tcp = role.connect().await;
    tcp.write_all(CLIENT).await.unwrap();
    assert_eq!(line_of(&mut tcp).await, SERVER);
    assert_eq!(stand.read(CLIENT.len()).await, CLIENT);
    let heard = cleartext::probe("127.0.0.1", role.port, &ProxyChoice::Direct, LIMIT).await;
    assert!(matches!(heard, Heard::Tls | Heard::Cut(_)), "TLS alone: {heard:?}");
    assert_eq!(stand.connections(), 1, "the probe reached the sshd");
}

/// A pair of sockets on the loopback: the role's end, and the client's.
async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (served, _) = listener.accept().await.unwrap();
    (served, client)
}

/// A start that stops short of `SSH-`, or none, is no SSH once the bound
/// passed; another start is no SSH at once; a start sent in parts is waited
/// for. Each byte stays in the socket for the road that takes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_short_of_ssh_or_none_reaches_no_sshd() {
    let bound = Duration::from_millis(300);
    for (sent, why) in [(&b"SSH"[..], "a start that stops short"), (&b""[..], "no byte at all")] {
        let (mut served, mut client) = pair().await;
        client.write_all(sent).await.unwrap();
        let started = Instant::now();
        assert!(!sshd::opens(&served, tokio::time::Instant::now() + bound).await, "{why}");
        assert!(started.elapsed() >= bound, "{why}: decided before its bound");
        drop(client);
        let mut kept = Vec::new();
        served.read_to_end(&mut kept).await.unwrap();
        assert_eq!(kept, sent, "{why}: its bytes stayed");
    }
    let (served, mut client) = pair().await;
    client.write_all(b"SSX-2.0-x\r\n").await.unwrap();
    let started = Instant::now();
    assert!(!sshd::opens(&served, tokio::time::Instant::now() + LIMIT).await);
    assert!(started.elapsed() < Duration::from_secs(5), "another start is decided at once");
    let (mut served, mut client) = pair().await;
    let writer = tokio::spawn(async move {
        client.write_all(b"SS").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        client.write_all(b"H-2.0-in-parts\r\n").await.unwrap();
        client
    });
    assert!(sshd::opens(&served, tokio::time::Instant::now() + LIMIT).await, "a start in parts");
    drop(writer.await.unwrap());
    let mut kept = Vec::new();
    served.read_to_end(&mut kept).await.unwrap();
    assert_eq!(kept, b"SSH-2.0-in-parts\r\n", "the line stayed whole");
}

/// With no sshd named, an SSH client's version line meets the cleartext
/// road, which waits for an HTTP head and answers it once it ends: no sshd
/// answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_sshd_an_ssh_client_meets_the_cleartext_road() {
    let stand = Stand::start().await;
    let role = Role::start(true, None).await;
    let mut tcp = role.connect().await;
    tcp.write_all(CLIENT).await.unwrap();
    let mut buf = [0u8; 64];
    let early = tokio::time::timeout(Duration::from_millis(1500), tcp.read(&mut buf)).await;
    assert!(early.is_err(), "the role answered a version line: {early:?}");
    // The empty line that ends a head of HTTP, which no SSH client sends.
    tcp.write_all(b"\r\n").await.unwrap();
    let answer = String::from_utf8_lossy(&to_end(&mut tcp).await).into_owned();
    assert!(answer.starts_with("HTTP/1.1 400"), "the cleartext road's answer: {answer}");
    assert_eq!(stand.connections(), 0);
    assert!(!role.said("sshd"), "{:?}", role.events());
}

/// An sshd that does not answer: the client gets one line that says so,
/// before any version line, and names no address; the owner's line names
/// the sshd and why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_sshd_that_does_not_answer_gets_the_client_a_line_and_the_owner_its_cause() {
    // A port that nothing listens on any more.
    let gone = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let role = Role::start(true, Some(gone)).await;
    let mut tcp = role.connect().await;
    tcp.write_all(CLIENT).await.unwrap();
    assert_eq!(to_end(&mut tcp).await, sshd::NO_SSHD, "the client's line");
    role.until_said("did not answer").await;
    let events = role.events();
    let line = events.iter().find(|l| l.contains("did not answer")).cloned().unwrap_or_default();
    assert!(line.starts_with("sshd from 127.0.0.1:") && line.contains(&format!("the sshd at {gone}")), "{events:?}");
}
