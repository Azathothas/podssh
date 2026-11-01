//! WebTunnel (T-385) against a stand-in of the WebTunnel server 0.0.7
//! written here, which reads the request as its `httpupgrade.Server` does:
//! `Connection: upgrade` and `Upgrade: websocket` in any case, else the
//! connection closes; then `101 Switching Protocols` with the two headers,
//! and raw bytes both ways, which it echoes. Its first bytes go in the same
//! write as the 101, so that a client which reads past the answer's head
//! loses them. TLS with the stand-in's root in a file, the names pinned to
//! the loopback; `cert=` is checked after the chain's own check, never in
//! its place. The control: a GET with no upgrade gets no 101.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::pt::Reach;
use podssh_ws::webtunnel::{self, Args};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const LIMIT: Duration = Duration::from_secs(20);
const SWITCHED: &str = "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n";

/// What the stand-in saw of each request: its head, and the SNI.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

fn settings(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn reach(trust: Trust) -> Reach {
    Reach { proxy: ProxyChoice::Direct, trust, wait: Duration::from_secs(5) }
}

fn pins() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    podssh_ws::resolve::set_pins(vec![("bridge.wt.test".into(), lo), ("front.wt.test".into(), lo)]);
}

fn root_file(name: &str, tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-webtunnel-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(name), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

/// Serve one connection: the request's head, its check, `answer`, then an
/// echo after a 101.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, sni: Option<String>, answer: &str, seen: Seen) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    seen.lock().unwrap().push((head.clone(), sni));
    let value = |name: &str| {
        head.split("\r\n")
            .filter_map(|l| l.split_once(':'))
            .find(|(n, _)| n.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_ascii_lowercase())
    };
    if value("connection").as_deref() != Some("upgrade") || value("upgrade").as_deref() != Some("websocket") {
        return;
    }
    if s.write_all(&[answer.as_bytes(), b"early"].concat()).await.is_err() || !answer.contains(" 101 ") {
        return;
    }
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if s.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// A stand-in on the loopback that answers `answer`, plain or with TLS for
/// `tls`'s name.
async fn stand_in(tls: Option<&str>, answer: &'static str) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let acceptor = tls.map(|name| cert::server_for(name).unwrap().0);
    let shared = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (seen, acceptor) = (shared.clone(), acceptor.clone());
            tokio::spawn(async move {
                match acceptor {
                    None => serve(tcp, None, answer, seen).await,
                    Some(acceptor) => {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            let sni = tls.get_ref().1.server_name().map(str::to_string);
                            serve(tls, sni, answer, seen).await;
                        }
                    }
                }
            });
        }
    });
    (port, seen)
}

/// `sent` through a stream of `args`, after the stand-in's early bytes.
async fn echo(args: &Args, trust: Trust, sent: &[u8]) {
    let mut stream = webtunnel::open(args, &reach(trust)).await.unwrap_or_else(|why| panic!("{why}"));
    let mut back = vec![0u8; 5 + sent.len()];
    let echoed = async {
        stream.write_all(sent).await.unwrap();
        stream.read_exact(&mut back).await.unwrap();
    };
    tokio::time::timeout(LIMIT, echoed).await.expect("the echo within the limit");
    assert_eq!(&back[..5], b"early", "the bytes right after the 101 were lost");
    assert!(back[5..] == *sent, "the bytes came back changed");
}

/// The upgrade at the secret path, as lyrebird's: `Host` with no port, Go's
/// agent, the two headers, no key; then raw bytes both ways, none lost
/// after the 101.
#[tokio::test]
async fn bytes_go_both_ways_after_the_upgrade_at_the_secret_path() {
    let (port, seen) = stand_in(None, SWITCHED).await;
    let url = format!("http://127.0.0.1:{port}/s3cret-path?x=1");
    let args = Args::parse(&settings(&[("url", url.as_str())])).unwrap();
    let sent: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
    echo(&args, Trust::Default, &sent).await;
    let seen = seen.lock().unwrap();
    let (head, _) = &seen[0];
    assert!(head.starts_with("GET /s3cret-path HTTP/1.1\r\nHost: 127.0.0.1\r\n"), "{head}");
    assert!(head.contains("\r\nUser-Agent: Go-http-client/1.1\r\n"), "{head}");
    assert!(!head.to_ascii_lowercase().contains("sec-websocket-key"), "{head}");
}

/// Over TLS for `servername=`, checked for that name with the test's root;
/// a `cert=` of the chain that the server sent passes after that check.
#[tokio::test]
async fn tls_for_the_server_name_and_a_pin_of_its_chain_pass() {
    pins();
    let (port, seen) = stand_in(Some("front.wt.test"), SWITCHED).await;
    let root = root_file("front.wt.test", "pinned");
    let leaf = cert::encoding::self_signed_inner("front.wt.test", false).der;
    let pin = base64_of(&webtunnel::chain_hash(&[leaf]));
    let url = format!("https://bridge.wt.test:{port}/p");
    let line = [("url", url.as_str()), ("servername", "front.wt.test"), ("cert", pin.as_str())];
    let args = Args::parse(&settings(&line)).unwrap();
    echo(&args, Trust::File(root.clone()), b"over TLS").await;
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].1.as_deref(), Some("front.wt.test"));
    assert!(seen[0].0.contains("\r\nHost: bridge.wt.test\r\n"), "{}", seen[0].0);
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A pin of another chain is refused, after TLS passed and before the GET.
#[tokio::test]
async fn a_pin_of_another_chain_is_refused_before_the_upgrade() {
    pins();
    let (port, seen) = stand_in(Some("bridge.wt.test"), SWITCHED).await;
    let root = root_file("bridge.wt.test", "other-pin");
    let pin = base64_of(&[7u8; 32]);
    let url = format!("https://bridge.wt.test:{port}/p");
    let args = Args::parse(&settings(&[("url", url.as_str()), ("cert", pin.as_str())])).unwrap();
    let refused = webtunnel::open(&args, &reach(Trust::File(root.clone()))).await.err().expect("a refusal");
    assert!(refused.contains("not the ones that cert= pins"), "{refused}");
    assert!(seen.lock().unwrap().is_empty(), "the GET went");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A certificate that no root here signs is refused even with its own pin:
/// `cert=` never stands in for the chain's check.
#[tokio::test]
async fn a_pin_does_not_take_the_place_of_the_chain_s_check() {
    pins();
    let (port, _) = stand_in(Some("bridge.wt.test"), SWITCHED).await;
    let leaf = cert::encoding::self_signed_inner("bridge.wt.test", false).der;
    let pin = base64_of(&webtunnel::chain_hash(&[leaf]));
    let url = format!("https://bridge.wt.test:{port}/p");
    let args = Args::parse(&settings(&[("url", url.as_str()), ("cert", pin.as_str())])).unwrap();
    // A root of another name: the server's chain reaches none of it.
    let other = root_file("unrelated.wt.test", "unpinned");
    let refused = webtunnel::open(&args, &reach(Trust::File(other.clone()))).await.err().expect("a refusal at TLS");
    assert!(refused.contains("TLS with bridge.wt.test failed"), "{refused}");
    let _ = std::fs::remove_dir_all(other.parent().unwrap());
}

/// An answer other than lyrebird's 101 ends the upgrade, and says it.
#[tokio::test]
async fn an_answer_that_is_not_101_is_refused() {
    let (port, _) = stand_in(None, "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n").await;
    let url = format!("http://127.0.0.1:{port}/p");
    let args = Args::parse(&settings(&[("url", url.as_str())])).unwrap();
    let refused = webtunnel::open(&args, &reach(Trust::Default)).await.err().expect("a refusal");
    assert!(refused.contains("200 OK, not 101"), "{refused}");
    assert!(!refused.contains("/p"), "the secret path was shown: {refused}");
}

/// The control of the stand-in: a GET with no upgrade gets no 101, as the
/// WebTunnel server closes it, so that a client which sent none would
/// fail above.
#[tokio::test]
async fn the_stand_in_answers_no_get_without_the_upgrade() {
    let (port, _) = stand_in(None, SWITCHED).await;
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(b"GET /p HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: upgrade\r\n\r\n").await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await.unwrap().unwrap();
    assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
