//! `ws-listen:` with `--raw-upgrade` (T-645, GitHub #143), beside the tests
//! of its upgrade: the request of podssh's own WebTunnel client
//! (`podssh_ws::webtunnel::request`, the request of lyrebird's client), with
//! no key and no version, gets a 101 that the client's own check takes, with
//! no `Sec-WebSocket-Accept`; then bytes of each value cross both ways
//! unmasked and unframed, the ones sent with the request first, and a
//! half-close ends the pipe with 0. With no flag the same request is
//! refused; with it, a client with a key is still framed, a broken key is
//! still 400, and an `Origin` is 403 with and without a key. The flag is for
//! `ws-listen:` alone (64).

use super::*;

/// The request of podssh's WebTunnel client for a bridge at `at`.
fn webtunnel_request(at: &str) -> String {
    let settings = [("url".to_string(), format!("http://{at}/a-secret-path"))];
    podssh_ws::webtunnel::request(&podssh_ws::webtunnel::Args::parse(&settings).unwrap())
}

/// A listener of `ws-listen:` with the echo target as its other side, and
/// `flags` after: the process, its stderr, and its address.
fn listener(flags: &[&str]) -> (Running, Arc<Mutex<Vec<u8>>>, String) {
    let other = format!("tcp:127.0.0.1:{}", echo_target());
    let mut args = vec!["ws-listen:127.0.0.1:0", other.as_str()];
    args.extend_from_slice(flags);
    let mut server = spawn(podssh(&args));
    let err = collect(server.0.stderr.take().unwrap());
    let at = listening_at(&err);
    (server, err, at)
}

#[test]
fn a_keyless_upgrade_gets_a_bare_101_and_raw_bytes_both_ways() {
    let (mut server, err, at) = listener(&["--raw-upgrade"]);
    // Each byte value, then each again backwards: the first 256 go with the
    // request itself, as a client may send them before the answer.
    let bytes: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
    let mut stream = TcpStream::connect(at.as_str()).unwrap();
    stream.set_read_timeout(Some(LIMIT)).unwrap();
    let mut first = webtunnel_request(&at).into_bytes();
    first.extend_from_slice(&bytes[..256]);
    stream.write_all(&first).unwrap();
    let head = read_head(&mut stream);
    podssh_ws::webtunnel::check_answer(&head).unwrap_or_else(|why| panic!("{why}: {head}"));
    assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{head}");
    assert!(!head.to_ascii_lowercase().contains("sec-websocket-accept"), "{head}");
    stream.write_all(&bytes[256..]).unwrap();
    let (mut back, mut chunk) = (Vec::new(), [0u8; 1024]);
    while back.len() < bytes.len() {
        let n = read_some(&mut stream, &mut chunk).expect("the echo within the limit");
        assert!(n > 0, "the connection ended after {} bytes", back.len());
        back.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(back, bytes, "the echo, unmasked and unframed");
    // A half-close goes on to the target, whose end comes back: the pipe
    // ends as tcp-listen:'s does.
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    assert!(rest.is_empty(), "{} bytes after the echo", rest.len());
    assert_eq!(ended(&mut server.0, "the server"), 0, "{}", text(&err));
}

#[test]
fn a_keyless_upgrade_is_refused_without_raw_upgrade() {
    let (_server, _err, at) = listener(&[]);
    let (_, head) = asked(&at, &webtunnel_request(&at));
    assert!(head.starts_with("HTTP/1.1 426 ") && head.contains("Sec-WebSocket-Version: 13\r\n"), "{head}");
}

#[test]
fn with_raw_upgrade_a_key_is_still_framed_and_an_origin_refused_either_way() {
    let (_server, _err, at) = listener(&["--raw-upgrade", "--keep-listening"]);
    let keyless = webtunnel_request(&at);
    let base = keyless.trim_end_matches("\r\n");
    let (_, head) = asked(&at, &format!("{base}\r\nOrigin: https://page.example\r\n\r\n"));
    assert!(head.starts_with("HTTP/1.1 403 "), "a keyless request with an Origin: {head}");
    let (_, head) = asked(&at, &upgrade("Origin: https://page.example\r\n"));
    assert!(head.starts_with("HTTP/1.1 403 "), "a framed one with an Origin: {head}");
    let (_, head) = asked(&at, &upgrade("").replace(KEY, "c2hvcnQ="));
    assert!(head.starts_with("HTTP/1.1 400 "), "a key of 5 bytes is no raw form: {head}");
    let (_, head) = asked(&at, &upgrade("").replace("Version: 13", "Version: 8"));
    assert!(head.starts_with("HTTP/1.1 426 "), "a key takes the version: {head}");
    let (mut stream, head) = asked(&at, &upgrade(""));
    let accept = format!("Sec-WebSocket-Accept: {ACCEPT}\r\n");
    assert!(head.starts_with("HTTP/1.1 101 ") && head.contains(&accept), "{head}");
    let masked = Frame { fin: true, opcode: frame::OPCODE_BINARY, payload: b"still framed".to_vec() };
    stream.write_all(&frame::encode(&masked, Role::Client, [9, 8, 7, 6])).unwrap();
    let (mut buf, mut echoed) = (Vec::new(), Vec::new());
    while echoed.len() < 12 {
        echoed.extend(server_frame(&mut stream, &mut buf).payload);
    }
    assert_eq!(echoed, b"still framed");
}

#[test]
fn raw_upgrade_is_for_ws_listen_alone() {
    let mut child = spawn(podssh(&["tcp-listen:127.0.0.1:0", "tcp:127.0.0.1:9", "--raw-upgrade"]));
    let err = collect(child.0.stderr.take().unwrap());
    assert_eq!(ended(&mut child.0, "podssh"), 64, "{}", text(&err));
    wait_for(&err, "--raw-upgrade is for ws-listen:", "the refusal");
    assert!(!text(&err).contains("listening on"), "nothing listens: {}", text(&err));
}
