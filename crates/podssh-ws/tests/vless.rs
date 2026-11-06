//! VLESS (T-440) against stand-ins on the loopback (`vless_support/`): over
//! a WebSocket, and over XHTTP's three modes on h2's own HTTP/2 server. A
//! session carries the target's version line and an echo; another ID is said
//! as the server's refusal; a refused upgrade names XHTTP as the way past it;
//! a server of HTTP/1.1 alone carries packet-up and stream-up on two
//! connections and refuses stream-one (T-456, Q67); a pipe takes a stream
//! whose target waits for its client; and the host's own proxy carries the
//! TCP. The runs against Xray-core and shoes are `scripts/interop-vless.sh`.

mod vless_support;

use std::path::Path;
use std::time::Duration;

use podssh_ws::vless::{self, Dial, Mode, Opened, Server, Transport, VlessError};
use podssh_ws::{Proxy, ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vless_support::{pins, root_file, target, ws_server, xhttp1_server, xhttp_server, BANNER, CLOSE_AFTER, ID, NAME};

const LIMIT: Duration = Duration::from_secs(20);

fn server(port: u16, query: &str, id: &str) -> Server {
    Server::parse(&format!("vless://{id}@{NAME}:{port}?security=tls&{query}")).unwrap()
}

fn dial<'a>(trust: &'a Trust, proxy: &'a ProxyChoice, pipe: bool) -> Dial<'a> {
    let answer = if pipe { vless::EARLY_WAIT } else { vless::ANSWER_WAIT };
    Dial { trust, proxy, timeout: LIMIT, answer, silence_is_ready: pipe, close_at_end: !pipe }
}

async fn open(server: &Server, port: u16, root: &Path, proxy: ProxyChoice, pipe: bool) -> Result<Opened, VlessError> {
    let trust = Trust::File(root.to_path_buf());
    let dial = dial(&trust, &proxy, pipe);
    tokio::time::timeout(LIMIT * 2, vless::open(server, "127.0.0.1", port, &dial)).await.expect("within the limit")
}

/// The target's version line, then `sent` echoed back.
async fn carries(opened: &mut Opened, sent: &[u8]) {
    let mut banner = vec![0u8; BANNER.len()];
    let mut back = vec![0u8; sent.len()];
    let both = async {
        opened.stream.read_exact(&mut banner).await.unwrap();
        // The echo is read while the bytes go: written whole first, they
        // could fill each buffer on the way and leave both ends waiting.
        let (mut read, mut write) = tokio::io::split(&mut opened.stream);
        let up = async {
            write.write_all(sent).await.unwrap();
            write.flush().await.unwrap();
        };
        tokio::join!(up, async { read.read_exact(&mut back).await.unwrap() });
    };
    tokio::time::timeout(LIMIT * 2, both).await.expect("the bytes within the limit");
    assert_eq!(banner, BANNER);
    assert!(back == sent, "the bytes came back changed");
}

/// Each transport carries the session: the request names the target, the
/// server's answer comes with the version line, and a large echo comes back
/// whole (several POSTs on packet-up, as one waits while the next fills).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_goes_over_a_websocket_and_each_mode_of_xhttp() {
    pins();
    let (root, aim) = (root_file("modes"), target(true).await);
    let (ws, ws_seen) = ws_server().await;
    let link = server(ws, &format!("type=ws&path=%2Fws&host=front.vless.test&sni={NAME}"), ID);
    let mut opened = open(&link, aim, &root, ProxyChoice::Direct, false)
        .await
        .unwrap_or_else(|e| panic!("{}", e.line("ws", "target")));
    assert!(opened.answered && opened.how == "a WebSocket", "{}", opened.how);
    let big = vec![5u8; 200_000];
    carries(&mut opened, &big).await;
    assert_eq!(*ws_seen.targets.lock().unwrap(), vec![format!("127.0.0.1:{aim}")]);
    let (method, path, host, _) = ws_seen.requests.lock().unwrap()[0].clone();
    assert_eq!((method.as_str(), path.as_str(), host.as_str()), ("GET", "/ws", "front.vless.test"));
    let (xh, xh_seen) = xhttp_server(&[b"h2"]).await;
    for (mode, how) in [
        ("stream-one", "XHTTP stream-one over HTTP/2"),
        ("stream-up", "XHTTP stream-up over HTTP/2"),
        ("packet-up", "XHTTP packet-up over HTTP/2"),
        ("auto", "XHTTP packet-up over HTTP/2"),
    ] {
        let link = server(xh, &format!("type=xhttp&path=%2Fxh&mode={mode}"), ID);
        let mut opened = open(&link, aim, &root, ProxyChoice::Direct, false)
            .await
            .unwrap_or_else(|e| panic!("{mode}: {}", e.line("xhttp", "target")));
        assert_eq!(opened.how, how);
        let big = vec![9u8; 2_500_000];
        carries(&mut opened, &big).await;
    }
    let requests = xh_seen.requests.lock().unwrap().clone();
    assert!(requests.iter().all(|(_, _, host, pad)| host == &format!("{NAME}:{xh}") && (100..=1000).contains(pad)));
    let posts = requests.iter().filter(|(m, p, _, _)| m == "POST" && p.matches('/').count() == 3).count();
    assert!(posts >= 6, "packet-up's POSTs, numbered, twice: {posts}");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// Another ID: the WebSocket closes and XHTTP's download ends before
/// VLESS's answer, and the line says that the server refused the ID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_id_is_said_as_the_server_s_refusal() {
    pins();
    let (root, aim) = (root_file("refusal"), target(true).await);
    let (ws, _) = ws_server().await;
    let (xh, _) = xhttp_server(&[b"h2"]).await;
    let other = "00000000-0000-4000-8000-000000000001";
    for link in [server(ws, "type=ws&path=%2Fws", other), server(xh, "type=xhttp&path=%2Fxh&mode=packet-up", other)] {
        let Err(e) = open(&link, aim, &root, ProxyChoice::Direct, false).await else {
            panic!("the wrong ID was taken over {:?}: no refusal said", link.transport);
        };
        assert!(matches!(e, VlessError::Ended), "{}", e.line("x", "y"));
        let line = e.line(&link.shown(), &format!("127.0.0.1:{aim}"));
        assert!(line.contains("before VLESS's answer: it refused the ID"), "{line}");
        assert!(!line.contains(other), "{line}");
    }
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A path that the server does not serve refuses the upgrade, and the line
/// names XHTTP as the way past a refused upgrade; XHTTP's 404 and a server
/// of HTTP/1.1 alone are said too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_upgrade_a_wrong_path_and_http1_are_said() {
    pins();
    let (root, aim) = (root_file("refused"), target(true).await);
    let (ws, _) = ws_server().await;
    let direct = ProxyChoice::Direct;
    let e = open(&server(ws, "type=ws&path=%2Fother", ID), aim, &root, direct.clone(), false).await.err().unwrap();
    assert!(matches!(e, VlessError::Refused { status: 404, .. }), "{}", e.line("x", "y"));
    assert!(e.line("s", "t").contains("type=xhttp passes where the upgrade does not"));
    let (xh, _) = xhttp_server(&[b"h2"]).await;
    let e = open(&server(xh, "type=xhttp&path=%2Fother", ID), aim, &root, direct.clone(), false).await.err();
    assert!(matches!(e, Some(VlessError::Refused { status: 404, .. })), "{:?}", e.map(|e| e.line("x", "y")));
    // stream-one alone stays refused on HTTP/1.1 (Q67): its body never ends.
    let (h1, _) = xhttp1_server(true).await;
    let link = server(h1, "type=xhttp&path=%2Fxh&mode=stream-one", ID);
    let e = open(&link, aim, &root, direct, false).await.err().unwrap();
    let line = e.line("s", "t");
    assert!(matches!(e, VlessError::Http1(_)) && line.contains("stream-one cannot go over HTTP/1.1"), "{line}");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A server of HTTP/1.1 alone (Q67, T-456): packet-up and stream-up carry the
/// session on two connections, the GET's and the upload's, over TLS that
/// chose `http/1.1` and over HTTP/2 with prior knowledge that the server
/// refused, with no TLS; a kept connection that the server closes after
/// [`CLOSE_AFTER`] packets is dialed again. With no second connection (the
/// planted defect: the POSTs on the GET's connection) the GET holds it, and
/// no packet is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_alone_carries_packet_up_and_stream_up_on_two_connections() {
    pins();
    let (root, aim) = (root_file("http1"), target(true).await);
    for tls in [true, false] {
        let (h1, seen) = xhttp1_server(tls).await;
        let security = if tls { "tls" } else { "none" };
        for (mode, how) in [
            ("packet-up", "XHTTP packet-up over HTTP/1.1 on two connections"),
            ("stream-up", "XHTTP stream-up over HTTP/1.1 on two connections"),
            ("auto", "XHTTP packet-up over HTTP/1.1 on two connections"),
        ] {
            let query = format!("type=xhttp&path=%2Fxh&mode={mode}&security={security}");
            let link = Server::parse(&format!("vless://{ID}@{NAME}:{h1}?{query}")).unwrap();
            let mut opened = open(&link, aim, &root, ProxyChoice::Direct, false)
                .await
                .unwrap_or_else(|e| panic!("{mode}, TLS {tls}: {}", e.line("xhttp", "target")));
            assert_eq!(opened.how, how, "TLS {tls}");
            // Large enough for more packets than a kept connection takes.
            let big = vec![7u8; 2_500_000];
            carries(&mut opened, &big).await;
        }
        let requests = seen.requests.lock().unwrap().clone();
        let packets = requests.iter().filter(|(m, p, _, _)| m == "POST" && p.matches('/').count() == 3).count();
        assert!(packets > CLOSE_AFTER, "packet-up's POSTs past a closed connection: {packets}");
        let gets = requests.iter().filter(|(m, ..)| m == "GET").count();
        let connections = seen.connections.load(std::sync::atomic::Ordering::SeqCst);
        assert!(connections > gets, "a connection of its own for the uploads: {connections} for {gets} GETs");
    }
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A pipe's target may wait for its client: the stream is taken after the
/// short wait with no answer, and the answer comes with the echo.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_takes_the_stream_of_a_target_that_waits_for_its_client() {
    pins();
    let (root, aim) = (root_file("pipe"), target(false).await);
    let (xh, _) = xhttp_server(&[b"h2"]).await;
    let link = server(xh, "type=xhttp&path=%2Fxh&mode=stream-one", ID);
    let mut opened = open(&link, aim, &root, ProxyChoice::Direct, true).await.unwrap();
    assert!(!opened.answered, "no answer before the client spoke");
    opened.stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    tokio::time::timeout(LIMIT, opened.stream.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(&back, b"ping");
    let ssh = open(&link, aim, &root, ProxyChoice::Direct, false).await.err().unwrap();
    assert!(matches!(ssh, VlessError::Silent(_)), "{}", ssh.line("x", "y"));
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// The host's own proxy, a plain CONNECT, carries the TCP to the server by
/// its name, and packet-up runs inside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_s_proxy_carries_the_tcp_to_the_server() {
    pins();
    let (root, aim) = (root_file("hop"), target(true).await);
    let (xh, _) = xhttp_server(&[b"h2", b"http/1.1"]).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hop = listener.local_addr().unwrap().port();
    let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let kept = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && tcp.read(&mut byte).await.unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            let line = String::from_utf8_lossy(&head).split(' ').nth(1).unwrap_or_default().to_string();
            kept.lock().unwrap().push(line.clone());
            let port = line.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(0);
            let Ok(mut out) = TcpStream::connect(("127.0.0.1", port)).await else { continue };
            tokio::spawn(async move {
                if tcp.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut out).await;
                }
            });
        }
    });
    let first = ProxyChoice::Via(Proxy::parse(&format!("http://127.0.0.1:{hop}")).unwrap());
    let mut opened = open(&server(xh, "type=xhttp&path=%2Fxh", ID), aim, &root, first, false).await.unwrap();
    carries(&mut opened, b"through the host's proxy").await;
    assert_eq!(*asked.lock().unwrap(), vec![format!("{NAME}:{xh}")]);
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

#[test]
fn doctor_tries_each_mode_of_an_auto_link() {
    let link = server(443, "type=xhttp", ID);
    assert_eq!(vless::modes(link.transport).len(), 3);
    assert_eq!(link.transport, Transport::Xhttp(Mode::Auto));
}
