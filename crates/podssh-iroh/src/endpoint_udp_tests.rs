//! The probe of UDP against iroh's own relay server on the loopback, with
//! its QUIC address discovery on, or with that port behind a socket of the
//! test that reads and never answers (T-359).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iroh::tls::CaTlsConfig;
use iroh::{RelayUrl, SecretKey};
use podssh_ws::{ProxyChoice, Trust};

use super::{open, open_with, Options, Udp};
use crate::probe::{Answer, REPORT_LIMIT};

/// A bound for each wait of these tests.
const LIMIT: Duration = Duration::from_secs(30);

/// The relay, its QAD port given, no proxy, and the relay's self-signed
/// certificate taken as it is.
fn options(relay: &RelayUrl, qad_port: u16, udp: Udp) -> Options {
    Options {
        relays: vec![relay.clone()],
        proxy: ProxyChoice::Direct,
        trust: Trust::Default,
        udp,
        secret: None,
        accepts: false,
        relay_tls: Some(CaTlsConfig::insecure_skip_verify()),
        qad_port: Some(qad_port),
    }
}

/// A UDP port on the loopback that reads each datagram and never answers,
/// as a network that drops UDP further on; the count of datagrams read.
async fn silent_port() -> (u16, Arc<AtomicUsize>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("a UDP port on the loopback");
    let port = socket.local_addr().expect("its address").port();
    let read = Arc::new(AtomicUsize::new(0));
    let counted = read.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while socket.recv(&mut buf).await.is_ok() {
            counted.fetch_add(1, Ordering::SeqCst);
        }
    });
    (port, read)
}

/// A bind refused, as a sandbox refuses it.
fn refused() -> std::io::Result<SocketAddr> {
    Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "a planted refusal"))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_round_trip_to_the_relays_address_discovery_keeps_udp() {
    let (_, url, server) = iroh::test_utils::run_relay_server_with(true).await.expect("a relay with QAD");
    let port = server.quic_addr().expect("the relay's QAD address").port();
    let opened = tokio::time::timeout(LIMIT, open(&options(&url, port, Udp::Probe)))
        .await
        .expect("the probe within its bound")
        .expect("an endpoint");
    assert!(matches!(opened.udp, Answer::Answered(took) if took < REPORT_LIMIT), "{}", opened.udp);
    assert!(!opened.endpoint.bound_sockets().is_empty(), "the endpoint gave up the UDP that came back");
    opened.endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_round_trip_leaves_the_relay_alone_with_the_same_key() {
    let (_, url, _server) = iroh::test_utils::run_relay_server_with(true).await.expect("a relay with QAD");
    let (port, read) = silent_port().await;
    let secret = SecretKey::generate();
    let mut chosen = options(&url, port, Udp::Probe);
    chosen.secret = Some(secret.clone());
    let opened =
        tokio::time::timeout(LIMIT, open(&chosen)).await.expect("the probe within its bound").expect("an endpoint");
    let waited = match opened.udp {
        Answer::Unknown(waited) => waited,
        other => panic!("a port that never answers gave {other:?}"),
    };
    assert!(waited <= REPORT_LIMIT + Duration::from_secs(1), "{waited:?}");
    assert!(read.load(Ordering::SeqCst) > 0, "the address discovery sent nothing to the port");
    assert!(opened.endpoint.bound_sockets().is_empty(), "the endpoint kept UDP that never came back");
    assert_eq!(opened.endpoint.id(), secret.public(), "the endpoint in its place took another key");
    tokio::time::timeout(LIMIT, opened.endpoint.online()).await.expect("online through the relay alone");
    opened.endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_bind_leaves_the_relay_alone() {
    let (_, url, server) = iroh::test_utils::run_relay_server_with(true).await.expect("a relay with QAD");
    let port = server.quic_addr().expect("the relay's QAD address").port();
    let opened = tokio::time::timeout(LIMIT, open_with(&options(&url, port, Udp::Probe), refused))
        .await
        .expect("the probe within its bound")
        .expect("an endpoint");
    assert!(matches!(opened.udp, Answer::Refused(_)), "{}", opened.udp);
    assert!(opened.endpoint.bound_sockets().is_empty());
    opened.endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn on_takes_udp_after_the_bind_alone_and_off_takes_none() {
    let (_, url, _server) = iroh::test_utils::run_relay_server_with(true).await.expect("a relay with QAD");
    let (port, _) = silent_port().await;
    let started = std::time::Instant::now();
    let on = open(&options(&url, port, Udp::On)).await.expect("an endpoint");
    assert!(matches!(on.udp, Answer::BindOnly(_)), "{}", on.udp);
    assert!(!on.endpoint.bound_sockets().is_empty());
    assert!(started.elapsed() < REPORT_LIMIT, "on waited for a report: {:?}", started.elapsed());
    on.endpoint.close().await;
    let off = open(&options(&url, port, Udp::Off)).await.expect("an endpoint");
    assert!(matches!(off.udp, Answer::Off), "{}", off.udp);
    assert!(off.endpoint.bound_sockets().is_empty());
    off.endpoint.close().await;
}

#[test]
fn the_variable_chooses_off_on_or_the_probe() {
    assert_eq!(Udp::from_value(Some("off")), Udp::Off);
    assert_eq!(Udp::from_value(Some(" OFF ")), Udp::Off);
    assert_eq!(Udp::from_value(Some("on")), Udp::On);
    assert_eq!(Udp::from_value(Some("yes")), Udp::Probe);
    assert_eq!(Udp::from_value(None), Udp::Probe);
}
