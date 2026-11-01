//! A bridge's transport answered in this process (T-385), against Arti's
//! own client of a transport that it does not manage: tor-chanmgr's
//! `ExternalProxyPlugin`, which joins the bridge's arguments into SOCKS5's
//! user and password and dials the transport's address through the
//! runtime's TCP provider, podssh's. Behind the sentinel, meek_lite and
//! WebTunnel reach stand-ins of meek-server and of the WebTunnel server on
//! the loopback, which echo. A provider that dials the sentinel for real
//! (no SOCKS greeting reaches podssh) fails the first two tests.

use std::time::Duration;

use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use podssh_tor::runtime::ProxiedTcp;
use podssh_tor::transport::Kind;
use podssh_ws::dial::ProxyChoice;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tor_chanmgr::transport::{ExternalProxyPlugin, TransportImplHelper as _};
use tor_linkspec::{ChannelMethod, OwnedChanTarget, OwnedChanTargetBuilder, PtTarget, PtTransportName};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_socksproto::SocksVersion;

const LIMIT: Duration = Duration::from_secs(20);

/// A bridge of `kind` with `settings`, at a dummy address, as a bridge line
/// gives it to Arti.
fn bridge(kind: Kind, settings: &[(&str, &str)]) -> OwnedChanTarget {
    let name: PtTransportName = kind.name().parse().unwrap();
    let mut target = PtTarget::new(name, "192.0.2.20:80".parse().unwrap());
    for (k, v) in settings {
        target.push_setting(*k, *v).unwrap();
    }
    OwnedChanTargetBuilder::default()
        .rsa_identity(RsaIdentity::from_bytes(&[7; 20]).unwrap())
        .method(ChannelMethod::Pluggable(target))
        .build()
        .unwrap()
}

/// A stand-in of meek-server: each POST with an id gets back what its body
/// held, at once; a request with no id gets 400.
async fn meek_stand_in() -> (u16, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut targets = Vec::new();
        let mut have = Vec::new();
        loop {
            let end = loop {
                if let Some(at) = have.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
                let mut chunk = [0u8; 8192];
                match s.read(&mut chunk).await {
                    Ok(0) | Err(_) => return targets,
                    Ok(n) => have.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&have[..end]).to_ascii_lowercase();
            have.drain(..end);
            targets.push(head.split(' ').nth(1).unwrap_or_default().to_string());
            let length: usize = head
                .split("\r\n")
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while have.len() < length {
                let mut chunk = [0u8; 8192];
                match s.read(&mut chunk).await {
                    Ok(0) | Err(_) => return targets,
                    Ok(n) => have.extend_from_slice(&chunk[..n]),
                }
            }
            let body: Vec<u8> = have.drain(..length).collect();
            let answer = match head.contains("\r\nx-session-id: ") {
                true => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
                false => b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec(),
            };
            let echoed = if answer.starts_with(b"HTTP/1.1 200") { body } else { Vec::new() };
            if s.write_all(&[answer, echoed].concat()).await.is_err() {
                return targets;
            }
        }
    });
    (port, served)
}

/// A stand-in of the WebTunnel server: the upgrade's two headers, a 101,
/// then an echo; the request's head is kept.
async fn webtunnel_stand_in() -> (u16, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read_exact(&mut byte).await.is_err() {
                return String::new();
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let lower = head.to_ascii_lowercase();
        if !lower.contains("\r\nconnection: upgrade\r\n") || !lower.contains("\r\nupgrade: websocket\r\n") {
            return head;
        }
        let switched = b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n";
        let _ = s.write_all(switched).await;
        let mut buf = [0u8; 4096];
        while let Ok(n) = s.read(&mut buf).await {
            if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        head
    });
    (port, served)
}

/// `ping` through Arti's client of `kind` for `bridge`, and its echo.
async fn ping(kind: Kind, target: &OwnedChanTarget) -> Result<[u8; 4], String> {
    let tcp = ProxiedTcp::new(ProxyChoice::Direct, Duration::from_secs(10));
    let said = tcp.said();
    let plugin = ExternalProxyPlugin::new(tcp, kind.at(), SocksVersion::V5);
    let connected = tokio::time::timeout(LIMIT, plugin.connect(target)).await.map_err(|_| "no channel in time")?;
    let (_, mut stream) = connected.map_err(|e| format!("{e}; podssh: {:?}", said.last()))?;
    stream.write_all(b"ping").await.map_err(|e| e.to_string())?;
    let mut back = [0u8; 4];
    let read = tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await.map_err(|_| "no echo in time")?;
    read.map_err(|e| e.to_string())?;
    Ok(back)
}

/// meek_lite, its URL longer than SOCKS5's user name, so that Arti splits
/// the arguments between the user and the password: the bytes go in a POST
/// to the whole path, and come back.
#[tokio::test]
async fn arti_s_client_reaches_a_meek_lite_bridge_through_its_sentinel() {
    let (port, served) = meek_stand_in().await;
    let path = "a".repeat(300);
    let url = format!("http://127.0.0.1:{port}/{path}");
    let echoed = ping(Kind::Meek, &bridge(Kind::Meek, &[("url", url.as_str())])).await;
    assert_eq!(echoed.unwrap_or_else(|why| panic!("{why}")), *b"ping");
    // Arti's end went with `ping`, and so does the session's connection.
    let targets = tokio::time::timeout(LIMIT, served).await.expect("the session's end").unwrap();
    assert!(!targets.is_empty() && targets.iter().all(|t| *t == format!("/{path}")), "{targets:?}");
}

/// WebTunnel, its path holding a `;`, which Arti escapes in the arguments:
/// the upgrade asks for the path as the line gives it, and bytes pass.
#[tokio::test]
async fn arti_s_client_reaches_a_webtunnel_bridge_through_its_sentinel() {
    let (port, served) = webtunnel_stand_in().await;
    let url = format!("http://127.0.0.1:{port}/s3cret;x");
    let echoed = ping(Kind::WebTunnel, &bridge(Kind::WebTunnel, &[("url", url.as_str()), ("ver", "0.0.7")])).await;
    assert_eq!(echoed.unwrap_or_else(|why| panic!("{why}")), *b"ping");
    let head = tokio::time::timeout(LIMIT, served).await.unwrap().unwrap();
    assert!(head.starts_with("GET /s3cret;x HTTP/1.1\r\n"), "{head}");
}

/// A transport that cannot reach its server is a failure of SOCKS5 for
/// Arti, and the provider keeps why, for the bootstrap's words.
#[tokio::test]
async fn a_transport_that_cannot_open_fails_the_channel_and_says_why() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let url = format!("http://127.0.0.1:{port}/");
    let tcp = ProxiedTcp::new(ProxyChoice::Direct, Duration::from_secs(10));
    let said = tcp.said();
    let plugin = ExternalProxyPlugin::new(tcp, Kind::Meek.at(), SocksVersion::V5);
    let target = bridge(Kind::Meek, &[("url", url.as_str())]);
    let refused = tokio::time::timeout(LIMIT, plugin.connect(&target)).await.unwrap();
    assert!(refused.is_err(), "a channel through a transport that did not open");
    let why = said.last().expect("the provider kept no failure");
    assert!(why.starts_with("meek_lite: ") && why.contains(&format!("127.0.0.1:{port}")), "{why}");
}

/// The control of the meek stand-in: a POST with no id gets 400.
#[tokio::test]
async fn the_meek_stand_in_refuses_a_post_with_no_session_id() {
    let (port, _) = meek_stand_in().await;
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n").await.unwrap();
    let mut answer = [0u8; 12];
    tokio::time::timeout(LIMIT, tcp.read_exact(&mut answer)).await.unwrap().unwrap();
    assert_eq!(&answer, b"HTTP/1.1 400");
}
