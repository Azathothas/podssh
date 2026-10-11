//! The SOCKS5 road to the relay (T-070), against a stand-in SOCKS5 server
//! on a local socket that records each byte it gets: the greeting, the user
//! and password of RFC 1929, and a CONNECT with the address type 3 and the
//! relay's name; the replies of RFC 1928 as the failover reads them; a bound
//! name read to its end; and a proxy that takes no names, which gets one more
//! try with an address.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::dial::{dial, proxy_from_vars, DialError, Proxy, ProxyChoice, ProxyKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(5);

/// What the stand-in does on one connection.
#[derive(Clone, Copy)]
struct Script {
    /// The method that it chooses.
    method: u8,
    /// Its answer to the user and the password, when it asks for them, and
    /// the version of that answer: 1, or 5 as a few servers give it.
    auth_ok: bool,
    auth_version: u8,
    /// Its reply to CONNECT, and the address type of its bound address.
    reply: u8,
    bound: u8,
}

const PLAIN: Script = Script { method: 0x00, auth_ok: true, auth_version: 1, reply: 0x00, bound: 0x01 };

/// The bytes that the stand-in got on one connection: the greeting, the
/// user and password (empty when not asked), and the CONNECT request.
#[derive(Debug, Default, Clone)]
struct Seen {
    greeting: Vec<u8>,
    auth: Vec<u8>,
    connect: Vec<u8>,
}

/// A stand-in that runs `scripts` on its connections, one each, and
/// records what each got; after a reply of success it echoes 4 bytes.
async fn stand_in(scripts: Vec<Script>) -> (u16, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        for script in scripts {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let got = serve(&mut sock, script).await;
            record.lock().unwrap().push(got);
        }
    });
    (port, seen)
}

async fn serve(sock: &mut TcpStream, script: Script) -> Seen {
    let mut seen = Seen::default();
    let mut head = [0u8; 2];
    if sock.read_exact(&mut head).await.is_err() {
        return seen;
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    let _ = sock.read_exact(&mut methods).await;
    seen.greeting = [head.to_vec(), methods].concat();
    let _ = sock.write_all(&[5, script.method]).await;
    if script.method == 0xff {
        return seen;
    }
    if script.method == 0x02 {
        let mut ulen = [0u8; 2];
        let _ = sock.read_exact(&mut ulen).await;
        let mut user = vec![0u8; usize::from(ulen[1])];
        let _ = sock.read_exact(&mut user).await;
        let mut plen = [0u8; 1];
        let _ = sock.read_exact(&mut plen).await;
        let mut password = vec![0u8; usize::from(plen[0])];
        let _ = sock.read_exact(&mut password).await;
        seen.auth = [ulen.to_vec(), user, plen.to_vec(), password].concat();
        let _ = sock.write_all(&[script.auth_version, if script.auth_ok { 0 } else { 1 }]).await;
        if !script.auth_ok {
            return seen;
        }
    }
    let mut request = [0u8; 4];
    if sock.read_exact(&mut request).await.is_err() {
        return seen;
    }
    let addr_len = match request[3] {
        1 => 4,
        4 => 16,
        _ => {
            let mut len = [0u8; 1];
            let _ = sock.read_exact(&mut len).await;
            seen.connect.push(len[0]);
            usize::from(len[0])
        }
    };
    let mut rest = vec![0u8; addr_len + 2];
    let _ = sock.read_exact(&mut rest).await;
    seen.connect = [request.to_vec(), seen.connect.clone(), rest].concat();
    let reply = if script.reply == 0x08 && request[3] != 3 { 0x00 } else { script.reply };
    let bound: Vec<u8> = match script.bound {
        3 => [vec![3, 13], b"bound.example".to_vec(), vec![0x04, 0x38]].concat(),
        4 => [vec![4], vec![0u8; 16], vec![0x04, 0x38]].concat(),
        _ => vec![1, 192, 0, 2, 7, 0x04, 0x38],
    };
    let _ = sock.write_all(&[vec![5, reply, 0], bound].concat()).await;
    if reply == 0 {
        let mut ping = [0u8; 4];
        if sock.read_exact(&mut ping).await.is_ok() {
            let _ = sock.write_all(&ping).await;
        }
    }
    seen
}

fn proxy(url: String) -> ProxyChoice {
    ProxyChoice::Via(Proxy::parse(&url).expect("a proxy URL"))
}

/// The tunnel carries bytes both ways right after the reply.
async fn echoes(mut stream: TcpStream) {
    stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await.expect("an echo in time").unwrap();
    assert_eq!(&back, b"ping");
}

#[test]
fn socks5_urls_parse_with_their_port_and_their_credentials() {
    let p = Proxy::parse("socks5://proxy.example").unwrap();
    assert_eq!((p.host.as_str(), p.port, p.kind), ("proxy.example", 1080, ProxyKind::Socks5));
    let p = Proxy::parse("SOCKS5H://alice:s%40cret@[::1]:9050").unwrap();
    assert_eq!((p.host.as_str(), p.port, p.kind), ("::1", 9050, ProxyKind::Socks5));
    assert_eq!(p.to_string(), "[::1]:9050", "Display never shows credentials");
    let debug = format!("{p:?}");
    assert!(!debug.contains("alice") && !debug.contains("cret"), "{debug}");
    assert_eq!(p.url(), "socks5h://alice:s%40cret@[::1]:9050");
    // RFC 1929: a user and a password of 1 to 255 bytes each.
    assert!(Proxy::parse("socks5://alice@proxy.example").unwrap_err().contains("RFC 1929"));
    assert!(Proxy::parse(&format!("socks5://{}:pw@proxy.example", "u".repeat(256))).unwrap_err().contains("RFC 1929"));
    let set = |name: &str| (name == "ALL_PROXY").then(|| "socks5h://proxy.example:1080".to_string());
    let chosen = proxy_from_vars("relay.example", set).unwrap().expect("a proxy");
    assert_eq!(chosen.kind, ProxyKind::Socks5);
}

#[tokio::test]
async fn a_tunnel_goes_by_name_and_needs_no_dns() {
    let (port, seen) = stand_in(vec![PLAIN]).await;
    // `relay.invalid` cannot resolve: the name must reach the proxy as text.
    let stream =
        dial("relay.invalid", 443, &proxy(format!("socks5://127.0.0.1:{port}")), LIMIT).await.expect("a tunnel");
    echoes(stream).await;
    let seen = seen.lock().unwrap()[0].clone();
    assert_eq!(seen.greeting, [5, 1, 0], "no authentication alone, with no credentials");
    let mut want = vec![5, 1, 0, 3, 13];
    want.extend_from_slice(b"relay.invalid");
    want.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(seen.connect, want, "CONNECT with the address type 3 and the name");
}

#[tokio::test]
async fn credentials_go_as_the_user_and_password_of_rfc_1929() {
    let (port, seen) = stand_in(vec![Script { method: 0x02, ..PLAIN }]).await;
    let stream = dial("relay.invalid", 443, &proxy(format!("socks5h://alice:s3cret@127.0.0.1:{port}")), LIMIT)
        .await
        .expect("a tunnel");
    echoes(stream).await;
    let seen = seen.lock().unwrap()[0].clone();
    assert_eq!(seen.greeting, [5, 2, 0, 2]);
    assert_eq!(seen.auth, [&[1u8, 5][..], b"alice", &[6], b"s3cret"].concat());
}

#[tokio::test]
async fn a_refused_password_is_a_407_that_does_not_show_it() {
    let (port, _) = stand_in(vec![Script { method: 0x02, auth_ok: false, ..PLAIN }]).await;
    let err =
        dial("relay.invalid", 443, &proxy(format!("socks5://alice:s3cret@127.0.0.1:{port}")), LIMIT).await.unwrap_err();
    assert!(matches!(&err, DialError::ProxyRefused { status: 407, .. }), "{err:?}");
    assert!(err.to_string().contains("refused the user and the password"), "{err}");
    assert!(!err.to_string().contains("s3cret") && !format!("{err:?}").contains("s3cret"), "{err:?}");
}

/// RFC 1929's answer has the version 1; one with SOCKS's 5 is taken too,
/// as curl takes it, and any other version breaks the protocol.
#[tokio::test]
async fn an_answer_to_the_password_with_the_version_5_is_taken() {
    let (port, _) = stand_in(vec![Script { method: 0x02, auth_version: 5, ..PLAIN }]).await;
    let url = format!("socks5://alice:s3cret@127.0.0.1:{port}");
    echoes(dial("relay.invalid", 443, &proxy(url), LIMIT).await.expect("a tunnel")).await;
    let (port, _) = stand_in(vec![Script { method: 0x02, auth_version: 7, ..PLAIN }]).await;
    let url = format!("socks5://alice:s3cret@127.0.0.1:{port}");
    let err = dial("relay.invalid", 443, &proxy(url), LIMIT).await.unwrap_err();
    assert!(matches!(err, DialError::ProxyProtocol { .. }), "{err:?}");
    assert!(!format!("{err:?}").contains("s3cret"), "{err:?}");
}

#[tokio::test]
async fn a_proxy_that_needs_a_password_when_none_is_given_is_a_407() {
    let (port, _) = stand_in(vec![Script { method: 0xff, ..PLAIN }]).await;
    let err = dial("relay.invalid", 443, &proxy(format!("socks5://127.0.0.1:{port}")), LIMIT).await.unwrap_err();
    assert!(matches!(&err, DialError::ProxyRefused { status: 407, .. }), "{err:?}");
    assert!(err.to_string().contains("needs a user and a password"), "{err}");
}

#[tokio::test]
async fn each_reply_maps_to_the_case_of_an_http_proxy() {
    for (reply, status) in [(0x02, 403), (0x01, 502), (0x04, 502), (0x05, 502)] {
        let (port, _) = stand_in(vec![Script { reply, ..PLAIN }]).await;
        let err = dial("relay.invalid", 443, &proxy(format!("socks5://127.0.0.1:{port}")), LIMIT).await.unwrap_err();
        match &err {
            DialError::ProxyRefused { status: got, reason, target, .. } => {
                assert_eq!(*got, status, "reply {reply}");
                assert!(reason.starts_with(&format!("SOCKS5 reply {reply}, ")), "{reason}");
                assert_eq!(target, "relay.invalid:443");
            }
            other => panic!("reply {reply}: {other:?}"),
        }
    }
    let (port, _) = stand_in(vec![Script { reply: 0x07, ..PLAIN }]).await;
    let err = dial("relay.invalid", 443, &proxy(format!("socks5://127.0.0.1:{port}")), LIMIT).await.unwrap_err();
    assert!(matches!(err, DialError::ProxyProtocol { .. }), "a proxy with no CONNECT: {err:?}");
}

#[tokio::test]
async fn a_bound_name_and_an_ipv6_address_are_read_to_their_end() {
    for bound in [3, 4] {
        let (port, _) = stand_in(vec![Script { bound, ..PLAIN }]).await;
        let stream =
            dial("relay.invalid", 443, &proxy(format!("socks5://127.0.0.1:{port}")), LIMIT).await.expect("a tunnel");
        // An extra or a missing byte would break the echo.
        echoes(stream).await;
    }
}

#[tokio::test]
async fn a_proxy_that_takes_no_names_gets_one_more_try_with_an_address() {
    let (port, seen) = stand_in(vec![Script { reply: 0x08, ..PLAIN }, Script { reply: 0x08, ..PLAIN }]).await;
    let stream = dial("localhost", 443, &proxy(format!("socks5://127.0.0.1:{port}")), LIMIT).await.expect("a tunnel");
    echoes(stream).await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].connect[3], 3, "the name first");
    assert!(matches!(seen[1].connect[3], 1 | 4), "then an address: {:?}", seen[1].connect);
}
