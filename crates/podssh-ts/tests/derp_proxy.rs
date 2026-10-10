//! The relay's DERP dial over WebSocket goes through the proxy (T-103,
//! patch 0017): the fork's `ws::connect` asks the proxy to `CONNECT` the
//! relay by name, a host on the `no_proxy` list goes direct, and the
//! credentials reach the proxy as they were typed. The proxy and the relay
//! are stand-ins on the loopback, and an `.invalid` name resolves nowhere:
//! only a tunnel reaches it.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use ts_http_util::proxy::{applies, configure, no_proxy_matches, ProxyConfig};

/// The fork's proxy is one for the process: these tests take turns. An
/// async lock, as each test holds it across its awaits; a test that fails
/// while it holds it poisons nothing.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Clears the fork's proxy when a test ends, also when it fails.
struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        configure(None);
    }
}

/// A stand-in proxy: keeps the head of each request, answers `200`, and
/// closes, so a TLS handshake through it fails.
async fn stand_in() -> (u16, Arc<Mutex<Vec<String>>>) {
    stand_in_on(TcpListener::bind("127.0.0.1:0").await.unwrap())
}

/// [`stand_in`] on `listener`.
fn stand_in_on(listener: TcpListener) -> (u16, Arc<Mutex<Vec<String>>>) {
    let port = listener.local_addr().unwrap().port();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let kept = heads.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && stream.read_exact(&mut byte).await.is_ok() {
                head.push(byte[0]);
            }
            kept.lock().unwrap().push(String::from_utf8_lossy(&head).into_owned());
            let _ = stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
        }
    });
    (port, heads)
}

fn first_lines(heads: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    heads.lock().unwrap().iter().map(|h| h.lines().next().unwrap_or("").to_string()).collect()
}

#[tokio::test]
async fn the_relay_dial_goes_through_the_proxy_by_name() {
    let _serial = SERIAL.lock().await;
    let (port, heads) = stand_in().await;
    configure(Some(ProxyConfig::from_url(&format!("http://127.0.0.1:{port}")).unwrap()));
    let _reset = Reset;
    let dialled = ts_derp::ws::connect("relay.invalid", 443).await;
    assert!(dialled.is_err(), "the stand-in speaks no TLS");
    // The name went to the proxy, which resolves it: this host never looked
    // it up.
    assert_eq!(first_lines(&heads), ["CONNECT relay.invalid:443 HTTP/1.1"]);
}

#[tokio::test]
async fn a_host_on_the_no_proxy_list_goes_direct() {
    let _serial = SERIAL.lock().await;
    let (port, heads) = stand_in().await;
    // The relay: a socket that counts who came to it directly.
    let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let came = tokio::spawn(async move { relay.accept().await.is_ok() });
    let config = ProxyConfig::from_url(&format!("http://127.0.0.1:{port}")).unwrap();
    configure(Some(config.with_no_proxy("other.example, 127.0.0.1")));
    let _reset = Reset;
    assert!(!applies("127.0.0.1") && !applies("other.example"));
    assert!(applies("tcp.ts.relay.ajam.dev"));
    let dialled = ts_derp::ws::connect("127.0.0.1", relay_port).await;
    assert!(dialled.is_err(), "the stand-in relay speaks no TLS");
    assert!(came.await.unwrap(), "the relay saw no direct connection");
    assert!(heads.lock().unwrap().is_empty(), "the proxy was asked: {:?}", first_lines(&heads));
}

#[tokio::test]
async fn credentials_reach_the_proxy_as_they_were_typed() {
    let _serial = SERIAL.lock().await;
    let (port, heads) = stand_in().await;
    // `us@er` and `p:s s`, escaped in the URL as podssh-ws escapes them.
    configure(Some(ProxyConfig::from_url(&format!("http://us%40er:p%3As%20s@127.0.0.1:{port}")).unwrap()));
    let _reset = Reset;
    let _ = ts_http_util::proxy::connect("relay.example", 443).await;
    let heads = heads.lock().unwrap();
    assert_eq!(heads.len(), 1);
    assert!(heads[0].contains("Proxy-Authorization: Basic dXNAZXI6cDpzIHM=\r\n"), "{}", heads[0]);
}

/// A proxy at an IPv6 address: the fork dials the address, not the
/// bracketed form of the URL, which no resolver takes.
#[tokio::test]
async fn a_proxy_at_an_ipv6_address_is_reached() {
    let _serial = SERIAL.lock().await;
    let Ok(listener) = TcpListener::bind("[::1]:0").await else {
        eprintln!("skipped: this host has no IPv6 loopback");
        return;
    };
    let (port, heads) = stand_in_on(listener);
    let config = ProxyConfig::from_url(&format!("http://[::1]:{port}")).unwrap();
    // The address the fork dials: Windows resolves `[::1]` with its
    // brackets, musl and glibc do not.
    assert_eq!(config.host, "::1");
    configure(Some(config));
    let _reset = Reset;
    ts_http_util::proxy::connect("relay.example", 443).await.expect("the tunnel opens");
    assert_eq!(first_lines(&heads), ["CONNECT relay.example:443 HTTP/1.1"]);
}

/// The fork's `no_proxy` rules are podssh's, case for case: podssh's checks
/// before the start read the list with podssh-ws, and the node with the
/// fork.
#[test]
fn the_no_proxy_rules_are_podssh_ws_rules() {
    let cases = [
        ("*", "anything.example"),
        ("example.com", "example.com"),
        ("example.com", "a.example.com"),
        ("example.com", "badexample.com"),
        (".example.com", "example.com"),
        ("*.example.com", "b.example.com"),
        ("example.com:443", "example.com"),
        ("EXAMPLE.com", "example.COM."),
        ("[::1]:80", "::1"),
        ("[::1]", "[::1]"),
        ("::1", "::1"),
        ("[::1", "::1"),
        ("[::1]x", "::1"),
        ("host:abc", "host"),
        ("host:", "host"),
        ("a.example, b.example", "b.example"),
        ("a.example b.example", "c.example"),
        ("", "example.com"),
        (".", "example.com"),
        ("10.0.0.1", "10.0.0.1"),
        ("10.0.0.1", "10.0.0.10"),
    ];
    for (list, host) in cases {
        assert_eq!(
            no_proxy_matches(list, host),
            podssh_ws::dial::no_proxy_matches(list, host),
            "{list:?} for {host:?}"
        );
    }
}
