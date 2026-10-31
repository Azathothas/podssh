//! RFC 8484's wire form against bytes that podssh did not write: the answers
//! that Cloudflare, Google and Quad9 gave on 2026-10-31
//! (`tests/fixtures/doh/`, whose README says how they were taken) decode to
//! their addresses and records, and no cut or change of them panics. And the
//! addresses that carried a session, through the dialer (T-344): asked after
//! the system resolver, handed over when they do not connect, and refused by
//! TLS on the name when they are not the host's. A test binary of its own,
//! as the remembered addresses are the process's.

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_ws::client::open_tls;
use podssh_ws::resolve::{self, wire, Remembered, Source, Srv, NXDOMAIN};
use podssh_ws::{ConnectError, ProxyChoice, Trust};
use tokio::net::TcpListener;
use tokio::time::Instant;

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("common/cert_for_test.rs");
}

const OPERATORS: [&str; 3] = ["cloudflare", "google", "quad9"];
const RELAY: &str = "tcp.ssh.relay.ajam.dev";

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/doh").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn ips(list: &[&str]) -> Vec<IpAddr> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

/// Each operator's A and AAAA answers for the default relay give its two
/// addresses of each family, in the operator's order; the owners are
/// pointers to the question's name.
#[test]
fn each_operator_s_answers_decode_to_the_relay_s_addresses() {
    let (v4, v6) = (["104.21.39.2", "172.67.141.178"], ["2606:4700:3037::6815:2702", "2606:4700:3036::ac43:8db2"]);
    let a = [("cloudflare", v4), ("google", [v4[1], v4[0]]), ("quad9", [v4[1], v4[0]])];
    for (op, want) in a {
        let got = wire::addrs(&fixture(&format!("{op}-a.bin")), RELAY, wire::A);
        assert_eq!(got, Ok(ips(&want)), "{op}");
    }
    let aaaa = [("cloudflare", v6), ("google", v6), ("quad9", [v6[1], v6[0]])];
    for (op, want) in aaaa {
        let got = wire::addrs(&fixture(&format!("{op}-aaaa.bin")), RELAY, wire::AAAA);
        assert_eq!(got, Ok(ips(&want)), "{op}");
    }
}

/// A CNAME before the address is passed over, as the JSON form passes over
/// each `data` of another type.
#[test]
fn a_cname_is_passed_over_to_its_address() {
    let want = [("cloudflare", "140.82.114.3"), ("google", "140.82.112.3"), ("quad9", "140.82.112.3")];
    for (op, ip) in want {
        let got = wire::addrs(&fixture(&format!("{op}-cname.bin")), "www.github.com", wire::A);
        assert_eq!(got, Ok(ips(&[ip])), "{op}");
    }
}

/// The edge's SRV record (T-339) gives its two regions and their port,
/// whose targets each operator wrote out in full.
#[test]
fn each_operator_s_srv_answer_gives_the_edge_s_regions() {
    let region = |n: u16| Srv { priority: n, weight: 1, port: 7844, target: format!("region{n}.v2.argotunnel.com") };
    let name = "_v2-origintunneld._tcp.argotunnel.com";
    let want = [("cloudflare", [region(1), region(2)]), ("google", [region(2), region(1)]), ("quad9", [region(2), region(1)])];
    for (op, records) in want {
        assert_eq!(wire::srv(&fixture(&format!("{op}-srv.bin")), name), Ok(records.to_vec()), "{op}");
    }
}

/// A name that does not exist is NXDOMAIN, as the JSON form says it; an
/// answer read for another question is refused.
#[test]
fn nxdomain_and_another_question_are_named() {
    for op in OPERATORS {
        let answer = fixture(&format!("{op}-nxdomain.bin"));
        assert_eq!(wire::addrs(&answer, "podssh-no-such-name.invalid", wire::A), Err(NXDOMAIN.to_string()), "{op}");
        let a = fixture(&format!("{op}-a.bin"));
        assert!(wire::addrs(&a, RELAY, wire::AAAA).unwrap_err().contains("another question"), "{op}");
        assert!(wire::addrs(&a, "tcp.ssh.relay.example", wire::A).unwrap_err().contains("another question"), "{op}");
    }
}

/// Each answer cut short is refused, and no change of one byte panics: the
/// decoder reads bytes from the network.
#[test]
fn no_cut_and_no_changed_byte_of_an_answer_panics() {
    for op in OPERATORS {
        for (kind, name, code) in [("a", RELAY, wire::A), ("aaaa", RELAY, wire::AAAA), ("cname", "www.github.com", wire::A)] {
            let answer = fixture(&format!("{op}-{kind}.bin"));
            for cut in 0..answer.len() {
                assert!(wire::addrs(&answer[..cut], name, code).is_err(), "{op}-{kind} cut at {cut}");
            }
            for at in 0..answer.len() {
                for value in [0x00, 0x3f, 0xc0, 0xff] {
                    let mut changed = answer.clone();
                    changed[at] = value;
                    let _ = wire::addrs(&changed, name, code);
                    let _ = wire::srv(&changed, name);
                }
            }
        }
    }
}

/// The remembered addresses are the process's: one test at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn remember(host: &str, ip: &str, ago: Duration) -> Remembered {
    Remembered { host: host.into(), ip: ip.parse().unwrap(), at_ms: now_ms() - ago.as_millis() as i64 }
}

/// The system resolver comes first: a name that it resolves never takes the
/// cache's address. This is the test of the order that a cache asked before
/// the system resolver fails.
#[tokio::test]
async fn the_system_resolver_comes_before_the_cache() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    resolve::set_remembered(vec![remember("localhost", "192.0.2.1", Duration::from_secs(60))]);
    let found = resolve::resolve_from("localhost", 443, Instant::now() + Duration::from_secs(10), None).await;
    resolve::set_remembered(Vec::new());
    let found = found.expect("localhost resolves on each system");
    assert_eq!(found.source, Source::System, "{found:?}");
    assert!(found.addrs.iter().all(|a| a.ip().is_loopback()), "{found:?}");
}

/// With the system resolver failing and no answer of DNS over HTTPS (the
/// name, with a `+`, is none to ask a resolver for, so no resolver is asked
/// and the test needs no network), the dialer takes a remembered address: a
/// fresh one first, which does not connect here, then the old one, which
/// does.
#[tokio::test]
async fn the_dialer_hands_a_cached_address_that_does_not_connect_to_the_next_source() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = "cached+relay.invalid";
    let week = resolve::FRESH;
    resolve::set_remembered(vec![
        remember(host, "::1", Duration::from_secs(60)),
        remember(host, "127.0.0.1", week + Duration::from_secs(3600)),
    ]);
    let dialed = podssh_ws::dial::dial(host, port, &ProxyChoice::Direct, Duration::from_secs(20)).await;
    resolve::set_remembered(Vec::new());
    let stream = dialed.expect("the old address connects");
    let peer = stream.peer_addr().unwrap();
    assert_eq!(peer, SocketAddr::from(([127, 0, 0, 1], port)));
    assert_eq!(resolve::dialed(host, peer), Some(Source::OldCache));
}

/// A remembered address that is not the host's: TCP connects, and TLS
/// refuses the certificate for the name, which is the host's and not the
/// address's; the dialer's record says that the cache gave the address.
#[tokio::test]
async fn a_wrong_cached_address_fails_tls_on_the_name() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let (acceptor, roots) = cert::server_for("other.example").expect("a server for another name");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = acceptor.accept(stream).await;
        }
    });
    let config = podssh_ws::tls::client_config(&podssh_ws::tls::TlsRoots {
        count: roots.len(),
        roots,
        source: "the test's own root".into(),
    })
    .unwrap();
    let trust = Trust::caller(config).unwrap();
    let host = "podssh-cached-relay.invalid";
    resolve::set_remembered(vec![remember(host, "127.0.0.1", Duration::from_secs(60))]);
    let opened = open_tls(host, port, host, &trust, &ProxyChoice::Direct, Duration::from_secs(20)).await;
    resolve::set_remembered(Vec::new());
    // A resolver here that answers for the reserved name would leave the
    // stand-in unasked: the wait for it is bounded.
    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    match opened {
        Err(ConnectError::Tls(why)) => {
            assert!(why.contains("NotValidForName") || why.contains("not valid for"), "{why}")
        }
        Err(other) => panic!("TLS must refuse the name, not this: {other}"),
        Ok(_) => panic!("a certificate for another name was taken"),
    }
    let last = resolve::last_dialed(host);
    assert_eq!(last, Some((SocketAddr::from(([127, 0, 0, 1], port)), Source::Cache)), "{last:?}");
}
