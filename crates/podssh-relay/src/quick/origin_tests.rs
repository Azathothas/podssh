//! The heads between the edge and the node's origin (T-428): what a request
//! of the edge becomes, what of the origin's answer goes back, and the
//! routing of a node with an origin and of one with none.

use super::*;

/// An origin of the paths under `/relay/`, which serves no connection.
struct Paths;

impl Origin for Paths {
    fn serves(&self, path: &str) -> bool {
        path.starts_with("/relay/")
    }

    fn connect(&self, _: Option<std::net::IpAddr>) -> DuplexStream {
        tokio::io::duplex(16).0
    }
}

fn asked(websocket: bool, headers: &[(&str, &str)]) -> Asked {
    Asked {
        method: if websocket { "GET" } else { "POST" }.into(),
        target: "/v1/mint?x=1".into(),
        host: "podssh-test.trycloudflare.com".into(),
        headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
        websocket,
    }
}

fn text(head: Result<Vec<u8>, String>) -> String {
    String::from_utf8(head.expect("a head")).unwrap()
}

/// A request's head keeps the visitor's headers, drops the edge's own and
/// those of one hop, and names its body's length, which the role's reader
/// reads as the request that came.
#[test]
fn a_request_s_head_is_the_visitor_s_without_the_edge_s_and_one_hop_s() {
    let fields = [
        ("x-relay-token", "abc"),
        ("cf-cloudflared-proxy-connection-upgrade", "websocket"),
        ("connection", "keep-alive"),
        ("transfer-encoding", "chunked"),
        ("content-length", "99"),
        ("host", "another.example"),
        ("cf-connecting-ip", "203.0.113.7"),
    ];
    let head = text(asked(false, &fields).head(2));
    assert!(head.starts_with("POST /v1/mint?x=1 HTTP/1.1\r\nHost: podssh-test.trycloudflare.com\r\n"), "{head}");
    assert!(head.ends_with("Content-Length: 2\r\n\r\n"), "{head}");
    for gone in ["cf-cloudflared", "keep-alive", "chunked", ": 99", "another.example"] {
        assert!(!head.contains(gone), "{gone}: {head}");
    }
    let read = podssh_ws::http::request::parse_request(head.as_bytes()).expect("the role reads it");
    assert_eq!(read.header("x-relay-token"), Some("abc"));
    assert_eq!(read.header("cf-connecting-ip"), Some("203.0.113.7"));
    assert_eq!(read.header("host"), Some("podssh-test.trycloudflare.com"));
}

/// A WebSocket's head has the three headers of the upgrade, as cloudflared's
/// proxy sets them, whatever the visitor's were, so that the server's check
/// of RFC 6455 takes it; it names no length.
#[test]
fn a_websocket_s_head_has_the_upgrade_as_cloudflared_sets_it() {
    let fields =
        [("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="), ("sec-websocket-version", "8"), ("upgrade", "something")];
    let head = text(asked(true, &fields).head(0));
    let read = podssh_ws::http::request::parse_request(head.as_bytes()).unwrap();
    assert_eq!(podssh_ws::server::check_upgrade(&read), Ok("dGhlIHNhbXBsZSBub25jZQ==".to_string()));
    assert!(!head.to_ascii_lowercase().contains("content-length"), "{head}");
    assert!(!head.contains("something") && !head.contains(": 8\r\n"), "{head}");
}

/// A part that would break the head, or be read two ways, is refused: the
/// edge's metadata over QUIC is any text.
#[test]
fn a_part_that_would_break_the_head_is_refused() {
    let mut bad = asked(false, &[("x", "a\r\nX-Relay-Token: forged")]);
    assert!(bad.head(0).unwrap_err().contains("control byte"));
    bad.headers = vec![("x y".into(), "z".into())];
    assert!(bad.head(0).is_err(), "a name with a space");
    let bad = [("GE T", "/", "h"), ("GET", "v1/mint", "h"), ("GET", "/a b", "h"), ("GET", "/", "")];
    for (method, target, host) in bad {
        let request = Asked { method: method.into(), target: target.into(), host: host.into(), ..asked(false, &[]) };
        assert!(request.head(0).is_err(), "{method} {target} {host}");
    }
}

/// The answer's head as the role writes it, and the bytes after it, which
/// are the body's.
#[tokio::test]
async fn an_answer_s_head_is_read_and_the_bytes_after_it_are_kept() {
    let (mut ours, mut theirs) = tokio::io::duplex(4096);
    let sent = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: podssh-key\r\nContent-Length: 4\r\n\
                Connection: close\r\n\r\nbody";
    tokio::io::AsyncWriteExt::write_all(&mut theirs, sent.as_bytes()).await.unwrap();
    let (answer, rest) = read_answer(&mut ours).await.unwrap();
    assert_eq!((answer.status, rest.as_slice()), (401, &b"body"[..]));
    assert_eq!(answer.length(), Some("4"));
    assert_eq!(answer.passed(), vec![("www-authenticate", "podssh-key"), ("content-length", "4")]);
    drop(theirs);
    assert!(read_answer(&mut ours).await.unwrap_err().contains("closed before"));
}

/// A 101 passes the three headers that the visitor's client needs; another
/// answer passes none of one hop.
#[test]
fn a_101_passes_the_upgrade_s_headers_and_another_answer_none_of_one_hop() {
    let headers = |pairs: &[(&str, &str)]| pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
    let switched = Answer {
        status: 101,
        headers: headers(&[("upgrade", "websocket"), ("connection", "Upgrade"), ("sec-websocket-accept", "s3p=")]),
    };
    assert!(switched.switched());
    assert_eq!(switched.passed().len(), 3);
    let other = Answer { status: 403, headers: headers(&[("connection", "close"), ("content-type", "text/plain")]) };
    assert_eq!(other.passed(), vec![("content-type", "text/plain")]);
}

/// A node with an origin gives it the paths that it serves, the query and
/// the fragment set aside; a node with none, or a closure, gives none.
#[test]
fn the_origin_takes_its_paths_alone() {
    let origin: Option<Arc<dyn Origin>> = Some(Arc::new(Paths));
    assert!(taking(&origin, "/relay/health").is_some());
    assert!(taking(&origin, "/relay/x?token=y#z").is_some());
    assert!(taking(&origin, "/").is_none() && taking(&origin, "/other?/relay/").is_none());
    assert!(taking(&None, "/relay/health").is_none());
    let visit = |_: DuplexStream| async {};
    assert!(Visit::origin(&visit).is_none(), "a closure has no origin");
    let visitors = Visitors { visit, origin };
    assert!(visitors.origin().is_some());
}

/// The visitor that the edge names, one address of any case of the field's
/// name; a field that holds no single address names nobody.
#[test]
fn the_visitor_is_the_one_address_of_cf_connecting_ip() {
    let fields = [("Host", "n.example"), ("CF-Connecting-IP", " 192.0.2.9 ")];
    assert_eq!(visitor_of(fields.into_iter()), Some("192.0.2.9".parse().unwrap()));
    let v6 = [("cf-connecting-ip", "2001:db8::1")];
    assert_eq!(visitor_of(v6.into_iter()), Some("2001:db8::1".parse().unwrap()));
    for bad in ["192.0.2.9, 198.51.100.1", "", "n.example"] {
        assert_eq!(visitor_of([("cf-connecting-ip", bad)].into_iter()), None, "{bad}");
    }
    assert_eq!(visitor_of([("x-forwarded-for", "192.0.2.9")].into_iter()), None);
}
