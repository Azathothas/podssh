//! The proxy-aware dialer: proxy settings from the environment, `no_proxy`,
//! and the CONNECT exchange against a stand-in proxy on a local socket.

use std::time::Duration;

use podssh_ws::dial::{dial, no_proxy_matches, proxy_from_vars, DialError, HttpProxy, ProxyChoice};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn vars(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |name| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
}

#[test]
fn proxy_urls_parse_with_and_without_scheme_port_and_credentials() {
    let p = HttpProxy::parse("http://169.254.169.1:45331").unwrap();
    assert_eq!((p.host.as_str(), p.port), ("169.254.169.1", 45331));

    let p = HttpProxy::parse("proxy.example:3128").unwrap();
    assert_eq!((p.host.as_str(), p.port), ("proxy.example", 3128));

    let p = HttpProxy::parse("http://proxy.example/").unwrap();
    assert_eq!(p.port, 80, "an http:// URL with no port means port 80");

    let p = HttpProxy::parse("http://[::1]:8080").unwrap();
    assert_eq!((p.host.as_str(), p.port), ("::1", 8080));

    let p = HttpProxy::parse("http://user:p%40ss@proxy.example:3128").unwrap();
    assert_eq!(p.to_string(), "proxy.example:3128", "Display never shows credentials");
    let debug = format!("{p:?}");
    assert!(!debug.contains("p@ss") && !debug.contains("user"), "Debug leaked credentials: {debug}");
}

/// The URL that a library takes (the iroh road's relay dial): the resolved
/// address, and the credentials escaped again so that they parse back the
/// same.
#[test]
fn a_proxy_as_a_url_at_its_address_keeps_its_credentials() {
    let p = HttpProxy::parse("http://us%40er:p%3Ass word@proxy.example:3128").unwrap();
    let url = p.url_at("192.0.2.7:3128".parse().unwrap());
    assert_eq!(url, "http://us%40er:p%3Ass%20word@192.0.2.7:3128");
    assert_eq!(
        HttpProxy::parse(&url).unwrap(),
        HttpProxy::parse("http://us%40er:p%3Ass%20word@192.0.2.7:3128").unwrap()
    );
    let plain = HttpProxy::parse("http://[::1]:8080").unwrap();
    assert_eq!(plain.url_at("[::1]:8080".parse().unwrap()), "http://[::1]:8080");
}

#[test]
fn unsupported_proxy_schemes_are_refused_by_name() {
    for url in ["https://proxy.example:443", "socks5://proxy.example:1080"] {
        let err = HttpProxy::parse(url).unwrap_err();
        assert!(err.contains("not supported"), "{url}: {err}");
    }
    assert!(HttpProxy::parse("http://:3128").is_err(), "a proxy URL with no host");
    assert!(HttpProxy::parse("http://proxy.example:notaport").is_err());
}

#[test]
fn no_proxy_lists_match_names_suffixes_and_wildcards() {
    assert!(no_proxy_matches("*", "anything.example"));
    assert!(no_proxy_matches("example.com", "example.com"));
    assert!(no_proxy_matches("example.com", "relay.example.com"));
    assert!(no_proxy_matches(".example.com", "example.com"));
    assert!(no_proxy_matches("*.example.com", "a.b.example.com"));
    assert!(no_proxy_matches("EXAMPLE.com:443", "example.COM"));
    assert!(no_proxy_matches("localhost, 10.0.0.1 ,example.com", "10.0.0.1"));
    assert!(!no_proxy_matches("example.com", "notexample.com"));
    assert!(!no_proxy_matches("", "example.com"));
    assert!(!no_proxy_matches("other.org", "example.com"));
}

#[test]
fn environment_precedence_and_exclusions() {
    let lower_wins = vars(&[("https_proxy", "http://a:1"), ("HTTPS_PROXY", "http://b:2")]);
    assert_eq!(proxy_from_vars("relay.example", lower_wins).unwrap().unwrap().host, "a");

    let all_proxy = vars(&[("ALL_PROXY", "http://c:3")]);
    assert_eq!(proxy_from_vars("relay.example", all_proxy).unwrap().unwrap().host, "c");

    let empty_is_unset = vars(&[("https_proxy", "  "), ("HTTPS_PROXY", "http://d:4")]);
    assert_eq!(proxy_from_vars("relay.example", empty_is_unset).unwrap().unwrap().host, "d");

    let excluded = vars(&[("HTTPS_PROXY", "http://e:5"), ("NO_PROXY", ".example")]);
    assert_eq!(proxy_from_vars("relay.example", excluded).unwrap(), None);

    assert_eq!(proxy_from_vars("relay.example", vars(&[])).unwrap(), None);
    assert!(proxy_from_vars("relay.example", vars(&[("HTTPS_PROXY", "ftp://x:1")])).is_err());
}

/// A stand-in proxy: accepts one connection, returns the request head it
/// received, answers with `reply`, and then (on 2xx) echoes bytes back as
/// the tunnelled target would.
async fn stand_in_proxy(reply: &'static str) -> (HttpProxy, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if sock.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        sock.write_all(reply.as_bytes()).await.unwrap();
        if reply.starts_with("HTTP/1.1 2") {
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        }
        String::from_utf8(head).unwrap()
    });
    (HttpProxy::parse(&format!("http://127.0.0.1:{port}")).unwrap(), task)
}

#[tokio::test]
async fn connect_tunnels_by_name_without_resolving_the_target() {
    let (proxy, seen) = stand_in_proxy("HTTP/1.1 200 Connection Established\r\n\r\n").await;
    // `relay.invalid` cannot resolve: the name must reach the proxy as text.
    let mut stream =
        dial("relay.invalid", 443, &ProxyChoice::Via(proxy), Duration::from_secs(5)).await.expect("a tunnel");
    stream.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping", "bytes flow through the tunnel");

    let head = seen.await.unwrap();
    assert!(head.starts_with("CONNECT relay.invalid:443 HTTP/1.1\r\n"), "{head}");
    assert!(head.contains("\r\nHost: relay.invalid:443\r\n"), "{head}");
    assert!(!head.contains("Proxy-Authorization"), "no credentials were given: {head}");
}

#[tokio::test]
async fn credentials_go_in_a_basic_proxy_authorization_header() {
    let (proxy, seen) = stand_in_proxy("HTTP/1.1 200 OK\r\n\r\n").await;
    let with_auth = HttpProxy::parse(&format!("http://user:pass@{proxy}")).unwrap();
    let mut s = dial("relay.invalid", 443, &ProxyChoice::Via(with_auth), Duration::from_secs(5)).await.unwrap();
    s.write_all(b"x").await.unwrap();
    let head = seen.await.unwrap();
    // base64("user:pass")
    assert!(head.contains("\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n"), "{head}");
}

#[tokio::test]
async fn a_refusal_carries_the_status_and_the_proxys_reason() {
    let (proxy, _seen) = stand_in_proxy("HTTP/1.1 403 not on the egress allowlist\r\n\r\n").await;
    let err = dial("example.com", 22, &ProxyChoice::Via(proxy), Duration::from_secs(5)).await.unwrap_err();
    match &err {
        DialError::ProxyRefused { status, reason, target, .. } => {
            assert_eq!(*status, 403);
            assert_eq!(reason, "not on the egress allowlist");
            assert_eq!(target, "example.com:22");
        }
        other => panic!("expected ProxyRefused, got {other:?}"),
    }
    assert!(err.to_string().contains("403 not on the egress allowlist"), "{err}");
}

#[tokio::test]
async fn an_unreachable_proxy_is_named() {
    // Bind and drop a listener to find a port with nothing on it.
    let port = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let proxy = HttpProxy::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let err = dial("relay.invalid", 443, &ProxyChoice::Via(proxy), Duration::from_secs(5)).await.unwrap_err();
    assert!(matches!(err, DialError::ProxyUnreachable { .. }), "{err:?}");
}

#[tokio::test]
async fn a_silent_proxy_times_out_within_the_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _hold = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(sock);
    });
    let proxy = HttpProxy::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let started = std::time::Instant::now();
    let err = dial("relay.invalid", 443, &ProxyChoice::Via(proxy), Duration::from_millis(300)).await.unwrap_err();
    assert!(matches!(err, DialError::Timeout { .. }), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
}

#[tokio::test]
async fn direct_connections_ignore_the_environment() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
    let stream: TcpStream =
        dial("127.0.0.1", port, &ProxyChoice::Direct, Duration::from_secs(5)).await.expect("a direct connection");
    drop(stream);
    accept.await.unwrap().unwrap();
}

#[tokio::test]
async fn names_that_would_break_a_request_are_refused() {
    for bad in ["", "two words", "host\r\nX: y", "a/b", "user@host"] {
        let err = dial(bad, 443, &ProxyChoice::Direct, Duration::from_secs(1)).await.unwrap_err();
        assert!(matches!(err, DialError::InvalidTarget(_)), "{bad:?}: {err:?}");
    }
}

/// A proxy's reason phrase ends up in the refusal message.
#[test]
fn a_proxy_reason_phrase_cannot_carry_terminal_controls() {
    let (status, reason) = podssh_ws::dial::parse_status_line("HTTP/1.1 403 not\x1b[31m allowed\x07\r\n\r\n").unwrap();
    assert_eq!(status, 403);
    assert_eq!(reason, "not[31m allowed");
}

/// A loopback target never goes through the proxy: the proxy's loopback is
/// not this host's (a proxy answered 405 to `CONNECT 127.0.0.1`, measured by
/// podbox). Anything else still does.
#[test]
fn loopback_targets_bypass_the_proxy() {
    let vars = |name: &str| (name == "https_proxy").then(|| "http://proxy.example:3128".to_string());
    for host in ["localhost", "LOCALHOST", "api.localhost", "127.0.0.1", "127.8.9.10", "::1", "[::1]"] {
        assert!(proxy_from_vars(host, vars).unwrap().is_none(), "{host} must not be proxied");
    }
    for host in ["example.org", "10.0.0.1", "localhost.example.org", "128.0.0.1"] {
        assert!(proxy_from_vars(host, vars).unwrap().is_some(), "{host} must be proxied");
    }
}
