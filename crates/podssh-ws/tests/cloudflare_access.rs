//! The road to a service that `cloudflared` publishes (T-264), against a
//! stand-in on 127.0.0.1 for Cloudflare's edge and cloudflared's origin
//! (feature `plain-ws`). The upgrade is checked line by line against the one
//! that `cloudflared access tcp` sends, read in its source at `bf4f502` with
//! gorilla/websocket 1.5.3; a capture of the program itself waits for a
//! service that the operator publishes. Messages up are cut at 16 KiB, as
//! the origin reads them; no Ping goes up; a refusal of Cloudflare Access is
//! told apart and quotes no credential; and a request with a token in its
//! URL fails the check.
#![cfg(feature = "plain-ws")]

use std::time::Duration;

use podssh_ws::client::ConnectError;
use podssh_ws::cloudflare::{self, Access};
use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::plain::connect_loopback;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(5);
const ID: &str = "made-up-client-id.access";
const SECRET: &str = "made-up-client-secret-of-this-test";
const JWT: &str = "made.up-token-of.this-test";

/// The upgrade of `cloudflared access tcp --hostname HOST` with a service
/// token and a token of a user, line by line, as its source writes it.
const CLOUDFLARED: [&str; 10] = [
    // wss://HOST/ (cmd/cloudflared/access/validation.go L48-73,
    // carrier/websocket.go L138-145)
    "GET / HTTP/1.1",
    // carrier/websocket.go L113: the name, with no port
    "Host: HOST",
    // cmd/cloudflared/access/cmd.go L69: cloudflared/VERSION
    "User-Agent: AGENT",
    // cmd/cloudflared/access/carrier.go L23-24 and L83-88
    "Cf-Access-Client-Id: ID",
    "Cf-Access-Client-Secret: SECRET",
    // carrier/carrier.go L23-25 and L155
    "Cf-Access-Token: JWT",
    // gorilla/websocket client.go L209-221; Go writes a header map in the
    // order of its names
    "Connection: Upgrade",
    "Sec-WebSocket-Key: KEY",
    "Sec-WebSocket-Version: 13",
    "Upgrade: websocket",
];

fn access(service: bool, token: bool) -> Access {
    Access {
        client_id: service.then(|| Zeroizing::new(ID.to_string())),
        client_secret: service.then(|| Zeroizing::new(SECRET.to_string())),
        token: token.then(|| Zeroizing::new(JWT.to_string())),
    }
}

/// Whether `head` is cloudflared's upgrade to `host` with the credentials of
/// `service` and `token`: the same lines, in the same order, but for the
/// User-Agent and the key of each run. A credential anywhere but in its
/// own header, as in a URL, fails it.
fn check_head(head: &str, host: &str, service: bool, token: bool) -> Result<(), String> {
    let request_line = head.lines().next().unwrap_or_default();
    for secret in [ID, SECRET, JWT] {
        if request_line.contains(secret) || request_line.to_ascii_lowercase().contains("cf-access") {
            return Err(format!("a credential in the request line: {request_line}"));
        }
    }
    let want: Vec<String> = CLOUDFLARED
        .iter()
        .filter(|line| service || !line.starts_with("Cf-Access-Client-"))
        .filter(|line| token || !line.starts_with("Cf-Access-Token"))
        .map(|line| line.replace("HOST", host).replace("SECRET", SECRET).replace("JWT", JWT).replace("ID", ID))
        .collect();
    let got: Vec<&str> = head.trim_end_matches("\r\n").split("\r\n").collect();
    if got.len() != want.len() {
        return Err(format!("{} lines where cloudflared sends {}: {got:?}", got.len(), want.len()));
    }
    for (got, want) in got.iter().zip(&want) {
        match want.split_once(": ") {
            Some(("User-Agent", _)) if got.starts_with("User-Agent: podssh/") => {}
            Some(("Sec-WebSocket-Key", _)) => {
                use base64::Engine as _;
                let key = got.strip_prefix("Sec-WebSocket-Key: ").ok_or(format!("{got:?}: no key"))?;
                let bytes = base64::engine::general_purpose::STANDARD.decode(key).map_err(|e| e.to_string())?;
                if bytes.len() != 16 {
                    return Err(format!("a key of {} bytes", bytes.len()));
                }
            }
            _ if got == want => {}
            _ => return Err(format!("{got:?} where cloudflared sends {want:?}")),
        }
    }
    Ok(())
}

/// What the stand-in does after it reads the upgrade.
enum Then {
    /// 101, a Ping, then each frame up until `bytes` of data came.
    Carry { bytes: usize },
    /// The answer, as it is, and the end.
    Answer(String),
}

/// What the stand-in saw: the head, and each frame up.
struct Seen {
    head: String,
    frames: Vec<Frame>,
}

/// A stand-in for the edge and the origin, for one connection.
async fn stand_in(then: Then) -> (u16, tokio::task::JoinHandle<Seen>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("an address").port();
    let task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.expect("accept");
        let head = read_head(&mut tcp).await;
        let mut frames = Vec::new();
        match then {
            Then::Answer(answer) => tcp.write_all(answer.as_bytes()).await.unwrap(),
            Then::Carry { bytes } => {
                let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).expect("a key");
                let accept = podssh_ws::handshake::accept_key(key.trim());
                let answer = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                tcp.write_all(answer.as_bytes()).await.unwrap();
                // The origin pings each 54 s; the first at once here.
                let ping = Frame { fin: true, opcode: frame::OPCODE_PING, payload: Vec::new() };
                tcp.write_all(&frame::encode(&ping, Role::Server, [0; 4])).await.unwrap();
                let mut data = 0usize;
                let mut buf = Vec::new();
                let mut chunk = vec![0u8; 64 * 1024];
                loop {
                    while let Some((f, used)) = frame::decode(&buf, Role::Client).expect("a frame of a client") {
                        buf.drain(..used);
                        if f.opcode == frame::OPCODE_BINARY || f.opcode == frame::OPCODE_CONTINUATION {
                            data += f.payload.len();
                        }
                        frames.push(f);
                    }
                    if data >= bytes {
                        break;
                    }
                    let n = tcp.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
        }
        Seen { head, frames }
    });
    (port, task)
}

async fn read_head(tcp: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.expect("a request");
        head.push(byte[0]);
    }
    String::from_utf8(head).expect("text")
}

#[tokio::test]
async fn cloudflare_upgrade_is_the_one_of_cloudflared() {
    for (service, token) in [(false, false), (true, false), (false, true), (true, true)] {
        let (port, edge) = stand_in(Then::Carry { bytes: 1 }).await;
        let session = cloudflare::connect_loopback("127.0.0.1", port, &access(service, token), TIMEOUT, Some(TIMEOUT))
            .await
            .expect("the upgrade");
        session.send_binary(b"x").await.expect("a send");
        let seen = tokio::time::timeout(TIMEOUT, edge).await.expect("in time").unwrap();
        check_head(&seen.head, "127.0.0.1", service, token).unwrap_or_else(|why| panic!("{why}:\n{}", seen.head));
    }
}

/// The check of the head refuses a token in the URL, and a head of another
/// order: it proves something.
#[test]
fn cloudflare_check_refuses_a_token_in_the_url() {
    let good = CLOUDFLARED
        .iter()
        .map(|l| {
            let l = l.replace("HOST", "h.test").replace("SECRET", SECRET).replace("JWT", JWT).replace("ID", ID);
            l.replace("AGENT", "podssh/0").replace("KEY", "AAAAAAAAAAAAAAAAAAAAAA==")
        })
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n\r\n";
    check_head(&good, "h.test", true, true).expect("the head of cloudflared");
    let in_url = good.replacen("GET / HTTP/1.1", &format!("GET /?cf-access-token={JWT} HTTP/1.1"), 1);
    assert!(check_head(&in_url, "h.test", true, true).is_err(), "a token in the URL passed");
    let swapped = good.replacen("Connection: Upgrade\r\nSec-", "Sec-", 1).replacen(
        "\r\n\r\n",
        "\r\nConnection: Upgrade\r\n\r\n",
        1,
    );
    assert!(check_head(&swapped, "h.test", true, true).is_err(), "another order passed");
}

/// 256 KiB up: each message is at most 16 KiB, whole (no fragment), and the
/// bytes arrive in order. A session of the relay's kind sends one message,
/// which the origin would cut: the check sees it.
#[tokio::test]
async fn cloudflare_messages_up_are_cut_at_16_kib() {
    let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let (port, edge) = stand_in(Then::Carry { bytes: data.len() }).await;
    let session = cloudflare::connect_loopback("127.0.0.1", port, &Access::default(), TIMEOUT, Some(TIMEOUT))
        .await
        .expect("the upgrade");
    session.send_binary(&data).await.expect("a send");
    let seen = tokio::time::timeout(TIMEOUT, edge).await.expect("in time").unwrap();
    let up: Vec<&Frame> = seen.frames.iter().filter(|f| f.opcode == frame::OPCODE_BINARY).collect();
    assert!(up.iter().all(|f| f.fin && f.payload.len() <= cloudflare::MAX_MESSAGE), "a message over 16 KiB");
    assert_eq!(up.len(), 16);
    assert_eq!(up.iter().flat_map(|f| f.payload.iter().copied()).collect::<Vec<u8>>(), data);

    let (port, edge) = stand_in(Then::Carry { bytes: data.len() }).await;
    let relay = connect_loopback("127.0.0.1", port, "/", "TESTONLYNOTACREDENTIAL", TIMEOUT, Some(TIMEOUT))
        .await
        .expect("the upgrade");
    relay.send_binary(&data).await.expect("a send");
    let seen = tokio::time::timeout(TIMEOUT, edge).await.expect("in time").unwrap();
    assert!(seen.frames.iter().any(|f| f.payload.len() > cloudflare::MAX_MESSAGE), "the check sees no long message");
}

/// The origin's Ping gets its Pong, and the session sends no Ping of its
/// own: its liveness watch never ends.
#[tokio::test]
async fn cloudflare_sends_no_ping() {
    let (port, edge) = stand_in(Then::Carry { bytes: 1 }).await;
    let session = cloudflare::connect_loopback("127.0.0.1", port, &Access::default(), TIMEOUT, Some(TIMEOUT))
        .await
        .expect("the upgrade");
    let reading = tokio::time::timeout(Duration::from_millis(300), session.read_frame());
    let watching =
        tokio::time::timeout(Duration::from_millis(300), session.watch_liveness(Duration::from_millis(20), 2));
    let (_, watched) = tokio::join!(reading, watching);
    assert!(watched.is_err(), "the liveness watch ended");
    session.send_binary(b"x").await.expect("a send");
    let seen = tokio::time::timeout(TIMEOUT, edge).await.expect("in time").unwrap();
    assert!(seen.frames.iter().any(|f| f.opcode == frame::OPCODE_PONG), "no Pong to the origin's Ping");
    assert!(!seen.frames.iter().any(|f| f.opcode == frame::OPCODE_PING), "a Ping went up");
}

/// A redirect to the login page of Cloudflare Access is told apart, and the
/// query of its Location, which the page fills, is left out.
#[tokio::test]
async fn cloudflare_redirect_to_the_login_of_access() {
    let answer = "HTTP/1.1 302 Found\r\nLocation: https://team.cloudflareaccess.com/cdn-cgi/access/login/h.test?kid=k1\
                  &redirect_url=%2F\r\nContent-Length: 0\r\n\r\n";
    let (port, _edge) = stand_in(Then::Answer(answer.into())).await;
    let refused = cloudflare::connect_loopback("127.0.0.1", port, &Access::default(), TIMEOUT, Some(TIMEOUT)).await;
    let Err(ConnectError::Refused { status, body }) = refused else { panic!("{refused:?}") };
    assert_eq!(status, 302);
    assert!(body.contains(cloudflare::LOGIN_PATH) && !body.contains("kid="), "{body}");
    assert!(cloudflare::refused_by_access(status, &body));
}

/// A refusal that quotes what it was sent shows no credential.
#[tokio::test]
async fn cloudflare_refusal_quotes_no_credential() {
    let body = format!("forbidden: {SECRET} and {JWT} are not good");
    let answer = format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (port, _edge) = stand_in(Then::Answer(answer)).await;
    let refused = cloudflare::connect_loopback("127.0.0.1", port, &access(true, true), TIMEOUT, Some(TIMEOUT)).await;
    let Err(ConnectError::Refused { status, body }) = refused else { panic!("{refused:?}") };
    assert_eq!(status, 403);
    assert!(!body.contains(SECRET) && !body.contains(JWT), "{body}");
    assert!(body.contains("forbidden"), "{body}");
    assert!(cloudflare::refused_by_access(status, &body));
}
