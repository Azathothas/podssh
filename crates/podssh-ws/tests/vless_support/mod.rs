//! Stand-ins of a VLESS server on the loopback, as Xray-core's behave
//! (`proxy/vless/inbound/inbound.go`, `transport/internet/websocket/hub.go`,
//! `transport/internet/splithttp/hub.go`): over a WebSocket at `/ws`, and over
//! XHTTP at `/xh/` on h2's own HTTP/2 server, which podssh did not write. Each
//! reads VLESS's request, ends the session with no answer for another ID (a
//! Close of 1000, or the end of the GET's body), and otherwise dials the target
//! and sends the answer with the target's first bytes. The XHTTP one answers
//! 400 to a padding out of 100 to 1000 and 404 to another path, and puts
//! packet-up's POSTs in order by their numbers. Xray-core itself runs in
//! `scripts/interop-vless.sh`.

#![allow(dead_code)]

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::session::RelaySession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod cert {
    include!("../common/cert_for_test.rs");
}

// The XHTTP stand-in's handler of each request.
mod xhttp;

pub const NAME: &str = "vless.test";
pub const BANNER: &[u8] = b"SSH-2.0-stand-in\r\n";
/// The users' ID of the stand-ins, and its bytes.
pub const ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const ID_BYTES: [u8; 16] = [0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0, 0];

/// What a stand-in saw: each request's method, path, `Host` and padding's
/// length, and each target that a VLESS request named.
#[derive(Default)]
pub struct Seen {
    pub requests: Mutex<Vec<(String, String, String, usize)>>,
    pub targets: Mutex<Vec<String>>,
}

pub fn pins() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    podssh_ws::resolve::set_pins(vec![(NAME.into(), lo)]);
}

pub fn root_file(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-vless-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

/// The target: its version line first when `speaks_first`, then an echo.
pub async fn target(speaks_first: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                if speaks_first && tcp.write_all(BANNER).await.is_err() {
                    return;
                }
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// VLESS's request at the front of `buf`, once whole: its ID, its target
/// and its length.
pub fn parse_request(buf: &[u8]) -> Option<([u8; 16], String, usize)> {
    let addons = usize::from(*buf.get(17)?);
    let at = 18 + addons;
    let command = *buf.get(at)?;
    assert_eq!((buf[0], command), (0, 1), "version 0 and TCP");
    let port = u16::from_be_bytes([*buf.get(at + 1)?, *buf.get(at + 2)?]);
    let (host, end) = match buf.get(at + 3)? {
        1 => (format!("{}", std::net::Ipv4Addr::from(<[u8; 4]>::try_from(buf.get(at + 4..at + 8)?).ok()?)), at + 8),
        2 => {
            let len = usize::from(*buf.get(at + 4)?);
            (String::from_utf8(buf.get(at + 5..at + 5 + len)?.to_vec()).ok()?, at + 5 + len)
        }
        kind => panic!("an address of type {kind}"),
    };
    Some((buf[1..17].try_into().ok()?, format!("{host}:{port}"), end))
}

fn acceptor(alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
    let (acceptor, _) = cert::server_for(NAME).unwrap();
    let mut config = (**acceptor.config()).clone();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// A VLESS server over a WebSocket at `/ws`, over TLS for [`NAME`].
pub async fn ws_server() -> (u16, Arc<Seen>) {
    let (acceptor, listener) = (acceptor(&[]), TcpListener::bind("127.0.0.1:0").await.unwrap());
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Seen> = Arc::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen) = (acceptor.clone(), kept.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                serve_ws(tls, seen).await;
            });
        }
    });
    (port, seen)
}

async fn serve_ws<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(mut tls: S, seen: Arc<Seen>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let path = head.split(' ').nth(1).unwrap_or_default().to_string();
    let field = |name: &str| {
        let mut fields = head.split("\r\n").filter_map(|l| l.split_once(':'));
        fields.find(|(n, _)| n.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string())
    };
    seen.requests.lock().unwrap().push(("GET".into(), path.clone(), field("host").unwrap_or_default(), 0));
    if path != "/ws" {
        let _ = tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        return;
    }
    let accept = podssh_ws::handshake::accept_key(&field("sec-websocket-key").unwrap_or_default());
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \
         {accept}\r\n\r\n"
    );
    if tls.write_all(answer.as_bytes()).await.is_err() {
        return;
    }
    let session = Arc::new(RelaySession::new(tls, Vec::new(), None, Duration::from_secs(30)).as_server());
    let mut got = Vec::new();
    let (id, target, used) = loop {
        let Ok(frame) = session.read_frame().await else { return };
        got.extend_from_slice(&frame.payload);
        if let Some(request) = parse_request(&got) {
            break request;
        }
    };
    let Some(tcp) = dial(id, &target, &seen).await else {
        // As Xray-core's connection closes: a Close of 1000 and no reason.
        let _ = session.send_close(1000, "").await;
        return;
    };
    let (mut rd, mut wr) = tcp.into_split();
    let _ = wr.write_all(&got[used..]).await;
    let up_session = session.clone();
    let up = async move {
        while let Ok(frame) = up_session.read_frame().await {
            if frame.opcode == podssh_ws::frame::OPCODE_CLOSE || wr.write_all(&frame.payload).await.is_err() {
                break;
            }
        }
    };
    let down = async move {
        let (mut buf, mut answer) = (vec![0u8; 16 * 1024], vec![0u8, 0u8]);
        while let Ok(n) = rd.read(&mut buf).await {
            if n == 0 {
                break;
            }
            answer.extend_from_slice(&buf[..n]);
            if session.send_binary(&answer).await.is_err() {
                return;
            }
            answer.clear();
        }
        let _ = session.send_close(1000, "").await;
    };
    tokio::join!(up, down);
}

/// The target of a request whose ID is the stand-in's, else none.
pub(crate) async fn dial(id: [u8; 16], target: &str, seen: &Seen) -> Option<TcpStream> {
    if id != ID_BYTES {
        return None;
    }
    seen.targets.lock().unwrap().push(target.to_string());
    TcpStream::connect(target).await.ok()
}

/// A VLESS server over XHTTP at `/xh/`, over TLS for [`NAME`], offering
/// `alpn`.
pub async fn xhttp_server(alpn: &[&[u8]]) -> (u16, Arc<Seen>) {
    let (acceptor, listener) = (acceptor(alpn), TcpListener::bind("127.0.0.1:0").await.unwrap());
    let port = listener.local_addr().unwrap().port();
    let (seen, sessions): (Arc<Seen>, xhttp::Sessions) = (Arc::default(), Arc::default());
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen, sessions) = (acceptor.clone(), kept.clone(), sessions.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let Ok(mut connection) = h2::server::handshake(tls).await else { return };
                while let Some(Ok((request, respond))) = connection.accept().await {
                    tokio::spawn(xhttp::handle(request, respond, seen.clone(), sessions.clone()));
                }
            });
        }
    });
    (port, seen)
}
