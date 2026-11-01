//! `--ts-control-url` and `--ts-relay HOST:PORT` (T-334): the URL that
//! `podssh ts` takes, read before the network; the check of `tcp` against a
//! control server of the test's own CA, which asks for its key and, when it
//! publishes one, for its DERP map; and a whole run whose check goes to that
//! server, never to login.tailscale.com. The servers are stand-ins on the
//! loopback: no test here leaves the machine.
#![cfg(feature = "ts")]

mod cleanup;
mod update_support;

use std::path::PathBuf;
use std::time::Duration;

use podssh_cli::dispatch::{run, Streams};
use podssh_cli::tree::parse;
use podssh_cli::ts::control::{control_url, host_port, names_a_key, reach, test_ca_notice, url_of, Server as Control};
use podssh_ts::chain::Verdict;
use podssh_ts::control::key_path;
use podssh_ts::wait::Deadline;
use podssh_ws::{ProxyChoice, Trust};

/// The answer to `/key`, as headscale and Tailscale's control give it.
const KEY_ANSWER: &[u8] = concat!(
    r#"{"legacyPublicKey":"mkey:0000000000000000000000000000000000000000000000000000000000000000","#,
    r#""publicKey":"mkey:4f3c2b1a00000000000000000000000000000000000000000000000000000000"}"#,
)
.as_bytes();

fn control(host: &str, port: u16) -> Control {
    Control { host: host.to_string(), port }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-ts-control-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

#[test]
fn a_control_url_is_https_with_a_host_and_a_port_at_most() {
    for (text, host, port) in [
        ("https://hs.example", "hs.example", 443),
        ("HTTPS://hs.example:8443/", "hs.example", 8443),
        ("https://127.0.0.1:45380", "127.0.0.1", 45380),
        ("https://[::1]:8443", "::1", 8443),
        ("  https://hs.example  ", "hs.example", 443),
    ] {
        assert_eq!(control_url(text), Ok(control(host, port)), "{text}");
    }
    // A URL with a user and a password, made at run time: a secrets scan
    // takes the literal for a credential.
    let with_password = with_password();
    for bad in [
        "hs.example",
        "http://hs.example",
        "https://",
        with_password.as_str(),
        "https://hs.example/prefix",
        "https://hs.example?x=1",
        "https://hs.example#top",
        "https://hs.example:0",
        "https://hs.example:99999",
        "https://::1",
        "https://[::1",
        "https://[nope]:1",
        "https://hs example",
    ] {
        let why = control_url(bad).expect_err(bad);
        assert!(!why.contains("secret"), "a refusal quoted the password: {why}");
    }
}

/// The fork gets the URL with its port written, an IPv6 address in brackets.
#[test]
fn the_fork_gets_https_host_and_port() {
    assert_eq!(url_of(&control("hs.example", 443)), "https://hs.example:443");
    assert_eq!(url_of(&control("::1", 8443)), "https://[::1]:8443");
}

#[test]
fn the_relay_takes_a_port_and_443_without_one() {
    assert_eq!(host_port("relay.example", 443), Ok(control("relay.example", 443)));
    assert_eq!(host_port("127.0.0.1:45380", 443), Ok(control("127.0.0.1", 45380)));
    assert_eq!(host_port("[::1]:8443", 443), Ok(control("::1", 8443)));
    for bad in ["", ":443", "relay.example:", "relay.example:x", "fd00::1", "[::1]x", "re/lay"] {
        assert!(host_port(bad, 443).is_err(), "{bad}");
    }
}

#[test]
fn an_answer_to_key_names_a_machine_key() {
    assert!(names_a_key(KEY_ANSWER));
    let bodies: [&[u8]; 4] = [b"{}", br#"{"publicKey":"nodekey:00"}"#, br#"{"publicKey":7}"#, b"not JSON"];
    for body in bodies {
        assert!(!names_a_key(body), "{}", String::from_utf8_lossy(body));
    }
}

/// A test's CA beside the node's roots is said; an empty variable is none.
#[test]
fn a_test_ca_is_said_and_an_empty_variable_is_none() {
    assert_eq!(test_ca_notice(|_| None), None);
    assert_eq!(test_ca_notice(|_| Some("  ".to_string())), None);
    let line = test_ca_notice(|name| (name == "PODSSH_TS_TEST_CA_FILE").then(|| "/run/ca.pem".to_string()));
    let line = line.expect("the notice");
    assert!(line.contains("/run/ca.pem") && line.contains("for tests"), "{line}");
}

/// `podssh ts` with a key file, a state file to be, and `extra`; its exit,
/// stderr, and whether the node started (the fork makes the state file).
fn run_with(name: &str, extra: &[&str]) -> (i32, String, bool) {
    let dir = scratch(name);
    let key = dir.join("key");
    std::fs::write(&key, b"tskey-auth-test-not-a-secret").unwrap();
    let state = dir.join("state.json");
    let mut argv: Vec<String> =
        ["ts", "--ts-auth-key-file", key.to_str().unwrap(), "--ts-state"].iter().map(|s| s.to_string()).collect();
    argv.push(state.to_str().unwrap().to_string());
    argv.extend(extra.iter().map(|s| s.to_string()));
    argv.extend(["--timeout".to_string(), "60s".to_string()]);
    let (mut out, mut err): (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
    let rc = run(&parse(argv), &mut Streams { out: &mut out, err: &mut err });
    assert!(out.is_empty(), "stdout carries nothing: {}", String::from_utf8_lossy(&out));
    (rc, String::from_utf8(err).unwrap(), state.exists())
}

/// A bad URL is a usage error before any network: its part is named, and
/// no node starts.
/// A control URL with a made-up user and password, at `hs.example`.
fn with_password() -> String {
    format!("https://{}:{}@hs.example", "user", "secret")
}

#[test]
fn a_bad_control_url_or_relay_is_64_before_the_network() {
    let (rc, err, started) = run_with("http", &["--ts-control-url", "http://hs.example"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("podssh ts: --ts-control-url: the scheme is not https://"), "{err}");
    assert!(!started, "the node started: the state file was made");
    let (rc, err, _) = run_with("password", &["--ts-control-url", &with_password()]);
    assert_eq!(rc, 64, "{err}");
    assert!(!err.contains("secret"), "{err}");
    let (rc, err, _) = run_with("relay", &["--ts-mode", "relay", "--ts-relay", "relay.example:x"]);
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("podssh ts: --ts-relay: "), "{err}");
}

/// With a control URL, the check of `tcp` goes to that server, through the
/// proxy, and never to Tailscale's: the proxy refuses here, so the run ends
/// at 78 with the server named, and no node starts. With the URL ignored,
/// the reason names login.tailscale.com.
#[test]
fn the_check_of_tcp_asks_the_control_server_and_not_tailscale() {
    let extra = ["--ts-mode", "tcp", "--ts-control-url", "https://control.invalid", "--ts-proxy", "http://127.0.0.1:1"];
    let (rc, err, started) = run_with("tcp", &extra);
    assert_eq!(rc, 78, "{err}");
    assert!(err.contains("podssh ts: mode tcp: the control key from control.invalid:443: "), "{err}");
    assert!(!err.contains("login.tailscale.com"), "{err}");
    assert!(!started, "the node started: the state file was made");
}

/// A control server of the test's own CA, which answers `/key` when `key`
/// holds; with it, the place and the trust of its checks.
async fn stand_in(name: &str, key: Option<&[u8]>) -> (update_support::Server, Control, Trust) {
    let stand = update_support::Server::start(&scratch(name)).await;
    if let Some(body) = key {
        stand.body(&key_path(), body.to_vec());
    }
    let place = control("127.0.0.1", stand.addr.port());
    let trust = Trust::File(stand.ca_file.clone());
    (stand, place, trust)
}

fn bound() -> Deadline {
    Deadline::after(Some(Duration::from_secs(20)))
}

/// headscale publishes no DERP map: its `/derpmap/default` is a 404, and
/// the check passes on its key.
#[tokio::test]
async fn a_server_that_publishes_no_map_passes_on_its_key() {
    let (stand, place, trust) = stand_in("nomap", Some(KEY_ANSWER)).await;
    let verdict = reach(&place, &trust, &ProxyChoice::Direct, bound()).await;
    assert_eq!(verdict, Verdict::Ok);
    let asked = stand.asked.lock().unwrap().clone();
    assert_eq!(asked, [key_path(), "/derpmap/default".to_string()], "the requests, in order");
    assert!(key_path().starts_with("/key?v="), "{}", key_path());
}

/// A server that publishes a map: one of its DERP servers must answer.
#[tokio::test]
async fn a_published_map_is_read_and_its_servers_are_tried() {
    let (stand, place, trust) = stand_in("map", Some(KEY_ANSWER)).await;
    let map = |port: u16| {
        let node = format!(r#"{{"Name":"999a","HostName":"127.0.0.1","DERPPort":{port}}}"#);
        format!(r#"{{"Regions":{{"999":{{"RegionID":999,"Nodes":[{node}]}}}}}}"#)
    };
    // The stand-in itself answers TLS for 127.0.0.1.
    stand.body("/derpmap/default", map(stand.addr.port()).into_bytes());
    assert_eq!(reach(&place, &trust, &ProxyChoice::Direct, bound()).await, Verdict::Ok);
    // Port 1 of the loopback: nothing listens.
    stand.body("/derpmap/default", map(1).into_bytes());
    let verdict = reach(&place, &trust, &ProxyChoice::Direct, bound()).await;
    let Verdict::Fail(why) = verdict else { panic!("a map whose server is down passed") };
    assert!(why.starts_with(&format!("no DERP server of {} answered: 127.0.0.1:1: ", place.authority())), "{why}");
}

#[tokio::test]
async fn a_server_with_no_key_is_not_ready() {
    let (stand, place, trust) = stand_in("nokey", None).await;
    let verdict = reach(&place, &trust, &ProxyChoice::Direct, bound()).await;
    assert_eq!(verdict, Verdict::Fail(format!("the control key from {}: HTTP 404", place.authority())));
    assert!(!stand.was_asked("/derpmap/default"), "the map was asked after the key failed");
    let (_stand, place, trust) = stand_in("emptykey", Some(b"{}")).await;
    let verdict = reach(&place, &trust, &ProxyChoice::Direct, bound()).await;
    let expected = format!("the control key from {}: the answer names no publicKey", place.authority());
    assert_eq!(verdict, Verdict::Fail(expected));
}

/// TLS stays checked: with podssh's own roots, which do not hold the
/// stand-in's CA, the handshake fails, and nothing is asked.
#[tokio::test]
async fn the_check_is_tls_checked() {
    let (stand, place, _) = stand_in("trust", Some(KEY_ANSWER)).await;
    let verdict = reach(&place, &Trust::Default, &ProxyChoice::Direct, bound()).await;
    let Verdict::Fail(why) = verdict else { panic!("a server of an unknown CA passed") };
    assert!(why.starts_with(&format!("the control key from {}: ", place.authority())), "{why}");
    assert!(stand.asked.lock().unwrap().is_empty(), "a request went over unchecked TLS");
}
