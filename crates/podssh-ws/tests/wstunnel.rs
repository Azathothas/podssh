//! wstunnel's protocol (T-441) against stand-ins on the loopback that read
//! a client as wstunnel's server does, from its source at v11.1.0
//! (`erebe/wstunnel:wstunnel/src/tunnel/server/server.rs`,
//! `handle_tunnel_request`, and `utils.rs`): the path prefix of
//! `/PREFIX/events` and its restriction, the JWT after
//! `authorization.bearer.` in `Sec-WebSocket-Protocol`, its claims
//! `{"id","p":{"Tcp":{"proxy_protocol"}},"r","rp"}`, the `Authorization`
//! that a restrictions file matches, the target dialed before the 101 with
//! the subprotocol `v1`, and a 400 "Invalid request" for each refusal. One
//! stand-in checks the token's signature with the old key, as 9.1 to 10.0
//! do; one answers as 9 does, and one as a server that is no wstunnel. Each
//! takes a frame's payload without its mask, as fastwebsockets 0.10 does
//! under wstunnel's default, unless it is told to apply it
//! (`--websocket-mask-frame`). The target sends a version line and echoes.
//! The run against wstunnel's own server is `scripts/interop-wstunnel.sh`.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::wstunnel::{self, Dial, Secret, Server, WstunnelError};
use podssh_ws::{ProxyChoice, Trust};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const NAME: &str = "wst.wstunnel.test";
const LIMIT: Duration = Duration::from_secs(20);
const BANNER: &[u8] = b"SSH-2.0-stand-in\r\n";

/// How a stand-in answers.
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    /// As wstunnel 10 and 11: the tunnel, or 400 "Invalid request".
    Tunnel,
    /// As wstunnel 9: 400 "Invalid upgrade request".
    Refuse9,
    /// A 101 without the subprotocol `v1`: another server.
    NoSubprotocol,
}

/// A stand-in's settings.
#[derive(Clone)]
struct Wst {
    /// `-r PREFIX`.
    restrict: Option<&'static str>,
    /// The `Authorization` that its restrictions match.
    authorization: Option<&'static str>,
    /// The token's signature checked with the old key, as 9.1 to 10.0.
    checks_signature: bool,
    /// Each frame's mask applied, as `--websocket-mask-frame`.
    unmask: bool,
    answer: Answer,
}

/// A server of 11 with its defaults.
const V11: Wst =
    Wst { restrict: None, authorization: None, checks_signature: false, unmask: false, answer: Answer::Tunnel };

/// What a stand-in saw: each request's target, subprotocols and
/// `Authorization`, each target it dialed, and each frame's masking key.
#[derive(Default)]
struct Seen {
    requests: Vec<(String, String, Option<String>)>,
    targets: Vec<(String, u16)>,
    keys: Vec<Option<[u8; 4]>>,
}

/// The target: its version line, then an echo.
async fn target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                if tcp.write_all(BANNER).await.is_ok() {
                    let (mut r, mut w) = tcp.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                }
            });
        }
    });
    port
}

/// A stand-in on the loopback, over TLS for [`NAME`] when `tls`.
async fn stand_in(wst: Wst, tls: bool) -> (u16, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Seen>> = Arc::default();
    let kept = seen.clone();
    let acceptor = tls.then(|| cert::server_for(NAME).unwrap().0);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (wst, seen, acceptor) = (wst.clone(), kept.clone(), acceptor.clone());
            tokio::spawn(async move {
                match acceptor {
                    Some(acceptor) => {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            serve(tls, wst, seen).await;
                        }
                    }
                    None => serve(tcp, wst, seen).await,
                }
            });
        }
    });
    (port, seen)
}

fn refusal(words: &str) -> String {
    format!("HTTP/1.1 400 Bad Request\r\ncontent-length: {}\r\n\r\n{words}", words.len())
}

/// The target of a request, or the refusal, in the order of
/// `handle_tunnel_request`: the path prefix and its restriction, the JWT,
/// then the restrictions' `Authorization`.
fn admit(head: &podssh_ws::http::Request, wst: &Wst) -> Option<(String, u16)> {
    let rest = head.target.strip_prefix('/')?;
    let (prefix, tail) = rest.split_once('/')?;
    if !tail.ends_with("events") || wst.restrict.is_some_and(|r| r != prefix) {
        return None;
    }
    let protocol = head.header("sec-websocket-protocol")?;
    let jwt = protocol.split_once("authorization.bearer.")?.1;
    let parts: Vec<&str> = jwt.split('.').collect();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts.first()?).ok()?).ok()?;
    if parts.len() != 3 || header["alg"] != "HS256" {
        return None;
    }
    if wst.checks_signature {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"champignonfrais").unwrap();
        mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
        mac.verify_slice(&b64.decode(parts[2]).ok()?).ok()?;
    }
    let claims: serde_json::Value = serde_json::from_slice(&b64.decode(parts[1]).ok()?).ok()?;
    claims["id"].as_str()?;
    claims["p"]["Tcp"]["proxy_protocol"].as_bool()?;
    if wst.authorization.is_some_and(|a| head.header("authorization") != Some(a)) {
        return None;
    }
    let host = claims["r"].as_str()?.trim_start_matches('[').trim_end_matches(']').to_string();
    Some((host, u16::try_from(claims["rp"].as_u64()?).ok()?))
}

async fn serve<S>(mut stream: S, wst: Wst, seen: Arc<Mutex<Seen>>)
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok((head, pending)) = podssh_ws::http::read_request(&mut stream, Vec::new()).await else { return };
    let protocol = head.header("sec-websocket-protocol").unwrap_or_default().to_string();
    let auth = head.header("authorization").map(String::from);
    seen.lock().unwrap().requests.push((head.target.clone(), protocol, auth));
    if wst.answer == Answer::Refuse9 {
        let _ = stream.write_all(refusal("Invalid upgrade request").as_bytes()).await;
        return;
    }
    let Some(aim) = admit(&head, &wst) else {
        let _ = stream.write_all(refusal("Invalid request").as_bytes()).await;
        return;
    };
    seen.lock().unwrap().targets.push(aim.clone());
    // The target is dialed before the upgrade is answered, as exec_tunnel.
    let conn = TcpStream::connect((aim.0.as_str(), aim.1)).await;
    let (Ok(conn), Ok(key)) = (conn, podssh_ws::server::check_upgrade(&head)) else {
        let _ = stream.write_all(refusal("Invalid request").as_bytes()).await;
        return;
    };
    let accept = podssh_ws::handshake::accept_key(&key);
    let sub = if wst.answer == Answer::NoSubprotocol { "" } else { "sec-websocket-protocol: v1\r\n" };
    let head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\n\
         sec-websocket-accept: {accept}\r\n{sub}\r\n"
    );
    if stream.write_all(head.as_bytes()).await.is_ok() {
        pump(stream, pending, conn, wst.unmask, seen).await;
    }
}

/// One frame as fastwebsockets 0.10 reads it: its opcode, its masking key,
/// and its payload as it came, the mask applied only when `unmask`.
async fn read_raw(r: &mut (impl AsyncRead + Unpin), unmask: bool) -> Option<(u8, Option<[u8; 4]>, Vec<u8>)> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h).await.ok()?;
    let len = match h[1] & 0x7f {
        126 => usize::from(r.read_u16().await.ok()?),
        127 => usize::try_from(r.read_u64().await.ok()?).ok()?,
        n => usize::from(n),
    };
    let mut key = [0u8; 4];
    let masked = h[1] & 0x80 != 0;
    if masked {
        r.read_exact(&mut key).await.ok()?;
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await.ok()?;
    if masked && unmask {
        frame::apply_mask(&mut payload, key);
    }
    Some((h[0] & 0x0f, masked.then_some(key), payload))
}

async fn send(w: &tokio::sync::Mutex<impl tokio::io::AsyncWrite + Unpin>, opcode: u8, payload: &[u8]) -> bool {
    let bytes = frame::encode(&Frame { fin: true, opcode, payload: payload.to_vec() }, Role::Server, [0; 4]);
    w.lock().await.write_all(&bytes).await.is_ok()
}

/// The copy both ways, as `propagate_local_to_remote` and its reverse: each
/// data frame's payload to the target, a Pong for a Ping, and the target's
/// bytes in binary frames, then a Close at its end.
async fn pump<S>(stream: S, pending: Vec<u8>, target: TcpStream, unmask: bool, seen: Arc<Mutex<Seen>>)
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (rd, wr) = tokio::io::split(stream);
    let mut rd = std::io::Cursor::new(pending).chain(rd);
    let wr = Arc::new(tokio::sync::Mutex::new(wr));
    let (mut trd, mut twr) = target.into_split();
    let w = wr.clone();
    let up = tokio::spawn(async move {
        while let Some((opcode, key, payload)) = read_raw(&mut rd, unmask).await {
            seen.lock().unwrap().keys.push(key);
            match opcode {
                frame::OPCODE_CLOSE => break,
                frame::OPCODE_PING => {
                    send(&*w, frame::OPCODE_PONG, &payload).await;
                }
                frame::OPCODE_PONG => {}
                // wstunnel writes a text frame's payload as a binary one's.
                _ => {
                    if twr.write_all(&payload).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = twr.shutdown().await;
    });
    let mut buf = vec![0u8; 32 * 1024];
    while let Ok(n) = trd.read(&mut buf).await {
        if n == 0 || !send(&*wr, frame::OPCODE_BINARY, &buf[..n]).await {
            break;
        }
    }
    send(&*wr, frame::OPCODE_CLOSE, &1000u16.to_be_bytes()).await;
    let _ = up.await;
}

fn dial() -> Dial<'static> {
    static TRUST: Trust = Trust::Default;
    static PROXY: ProxyChoice = ProxyChoice::Direct;
    Dial { trust: &TRUST, proxy: &PROXY, timeout: LIMIT, close_at_end: true }
}

async fn open(server: &Server, secret: &Secret, aim: u16) -> Result<wstunnel::Carried, WstunnelError> {
    tokio::time::timeout(LIMIT * 2, wstunnel::open(server, secret, "127.0.0.1", aim, &dial()))
        .await
        .expect("an answer within the limit")
}

/// The version line, then 200 KiB echoed, through `carried`.
async fn carries(mut carried: wstunnel::Carried) {
    let sent: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    let mut banner = vec![0u8; BANNER.len()];
    let mut back = vec![0u8; sent.len()];
    let both = async {
        carried.stream.read_exact(&mut banner).await.unwrap();
        carried.stream.write_all(&sent).await.unwrap();
        carried.stream.read_exact(&mut back).await.unwrap();
    };
    tokio::time::timeout(LIMIT, both).await.expect("the bytes within the limit");
    assert_eq!(banner, BANNER);
    assert!(back == sent, "the bytes came back changed");
}

fn plain(port: u16) -> Server {
    Server::parse(&format!("ws://127.0.0.1:{port}")).unwrap()
}

/// A server of 11 (no signature checked) and one of 10.0 (the old key's
/// signature checked) take the token, each frame's payload is read as it
/// came, and the bytes come back as they went; so they do where the server
/// applies the mask. Each frame bears the mask bit with a key of zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_banner_and_the_bytes_come_back_through_each_server_of_9_1_to_11() {
    let aim = target().await;
    for wst in [V11, Wst { checks_signature: true, ..V11 }, Wst { unmask: true, ..V11 }] {
        let (port, seen) = stand_in(wst.clone(), false).await;
        carries(open(&plain(port), &Secret::default(), aim).await.unwrap()).await;
        let seen = seen.lock().unwrap();
        let (path, protocol, auth) = &seen.requests[0];
        assert_eq!((path.as_str(), auth.as_deref()), ("/v1/events", None));
        assert!(protocol.starts_with("v1, authorization.bearer.ey"), "{protocol}");
        assert_eq!(seen.targets, vec![("127.0.0.1".to_string(), aim)]);
        assert!(!seen.keys.is_empty() && seen.keys.iter().all(|k| *k == Some([0; 4])), "{:?}", seen.keys);
    }
}

/// The prefix of the secret file goes in the path and its credentials in
/// `Authorization`; a wrong prefix, or none, is refused by the server, and
/// the refusal says so in the words of its version, with no secret in them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_secret_goes_in_the_path_and_a_wrong_one_is_refused_in_its_words() {
    let aim = target().await;
    let wst = Wst { restrict: Some("s3cr3t"), authorization: Some("Basic YWxpY2U6cHc="), ..V11 };
    let (port, seen) = stand_in(wst, false).await;
    let secret = Secret::parse("path-prefix s3cr3t\ncredentials alice:pw\n").unwrap();
    carries(open(&plain(port), &secret, aim).await.unwrap()).await;
    let (path, _, auth) = seen.lock().unwrap().requests[0].clone();
    assert_eq!((path.as_str(), auth.as_deref()), ("/s3cr3t/events", Some("Basic YWxpY2U6cHc=")));
    for wrong in ["path-prefix other\ncredentials alice:pw", "path-prefix s3cr3t", "v1"] {
        let why = open(&plain(port), &Secret::parse(wrong).unwrap(), aim).await.expect_err("a refusal");
        let line = why.line(&plain(port).shown());
        let words = format!("the wstunnel server ws://127.0.0.1:{port} refused the tunnel: 400 Invalid request; ");
        assert!(line.starts_with(&words) && line.contains("the words of wstunnel 10 and later"), "{line}");
        assert!(!line.contains("s3cr3t") && !line.contains("YWxp") && !format!("{why:?}").contains("s3cr3t"));
    }
}

/// A server of 9 refuses in its own words, which name the versions that
/// cannot read the token; a 101 without `v1` is no wstunnel server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_version_and_another_server_are_said_in_their_words() {
    let aim = target().await;
    let (port, _) = stand_in(Wst { answer: Answer::Refuse9, ..V11 }, false).await;
    match open(&plain(port), &Secret::default(), aim).await.expect_err("a refusal") {
        WstunnelError::Refused { status: 400, words } => {
            assert!(words.starts_with("Invalid upgrade request; the words of wstunnel 9 and before"), "{words}");
            assert!(words.contains("9.0 or before"), "{words}");
        }
        other => panic!("{other:?}"),
    }
    let (port, _) = stand_in(Wst { answer: Answer::NoSubprotocol, ..V11 }, false).await;
    let why = open(&plain(port), &Secret::default(), aim).await.expect_err("a refusal");
    let line = why.line(&plain(port).shown());
    assert!(line.contains("is no wstunnel server that podssh speaks to") && line.contains("9.1 to 11"), "{line}");
}

fn root_file(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-wstunnel-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

/// Over `wss://`, TLS is checked for the server's name with the test's
/// root, and the tunnel carries the session; another name is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wss_checks_the_server_s_name_and_carries_the_session() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    podssh_ws::resolve::set_pins(vec![(NAME.into(), lo), ("other.wstunnel.test".into(), lo)]);
    let (root, aim) = (root_file("tls"), target().await);
    let (port, _) = stand_in(Wst { restrict: Some("p"), ..V11 }, true).await;
    let trust = Trust::File(root.clone());
    let secret = Secret::parse("p").unwrap();
    let dial = Dial { trust: &trust, ..dial() };
    let server = Server::parse(&format!("wss://{NAME}:{port}")).unwrap();
    let opened = tokio::time::timeout(LIMIT * 2, wstunnel::open(&server, &secret, "127.0.0.1", aim, &dial)).await;
    carries(opened.expect("an answer within the limit").unwrap()).await;
    let other = Server::parse(&format!("wss://other.wstunnel.test:{port}")).unwrap();
    let why = wstunnel::open(&other, &secret, "127.0.0.1", aim, &dial).await.expect_err("a refusal");
    assert!(why.line(&other.shown()).starts_with("TLS with the wstunnel server wss://other"), "{why:?}");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}
