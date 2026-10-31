//! The record of pkarr that finds a node whose home relay changed (T-350),
//! offline: two of iroh's relay servers and a server of pkarr on the
//! loopback. The node moves from the first relay to the second and keeps its
//! record at the server; a client with the first ticket asks the record once
//! the ticket's relay does not reach the node, and connects. A client whose
//! ticket's relay does not answer asks it before the first dial. A record
//! that a server forged, signed by another key, is refused, and a planted
//! reader that skips the signature fails that check. iroh's own client of
//! pkarr reads podssh's record, and podssh reads iroh's.

mod cleanup;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh::address_lookup::PkarrRelayClient;
use iroh::endpoint_info::EndpointInfo;
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayUrl, SecretKey};
use podssh_iroh::client::FIND_AFTER;
use podssh_iroh::pkarr::{self, Finder, Read, Record, Server, SignedPacket};
use podssh_iroh::test_pkarr::{self, TestPkarr};
use podssh_iroh::{ticket, Dialer, Failure, Options, Udp};
use podssh_relay::session::client::Outcome;
use podssh_relay::session::Settings;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const LIMIT: Duration = Duration::from_secs(60);
const PIPE: usize = 64 * 1024;

/// A fresh, empty scratch directory unique to one test, removed when it ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-iroh-pkarr-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The stand-in server as podssh names a server, and the trust in its
/// certificate alone.
fn server_of(stand_in: &TestPkarr) -> (Server, Trust) {
    (Server::parse(stand_in.url.as_str()).expect("the stand-in's URL"), Trust::File(stand_in.cert.clone()))
}

/// An endpoint on `relay` alone, with no proxy and no UDP; the relays'
/// self-signed certificates are not checked, as in the other tests.
fn options(relay: &RelayUrl, secret: Option<SecretKey>, accepts: bool) -> Options {
    Options {
        relays: vec![relay.clone()],
        proxy: ProxyChoice::Direct,
        trust: Trust::Default,
        udp: Udp::Off,
        secret,
        accepts,
        relay_tls: Some(CaTlsConfig::insecure_skip_verify()),
        qad_port: None,
    }
}

/// A relay on a port of the loopback where nothing listens.
fn silent_relay() -> RelayUrl {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("https://localhost:{port}").parse().unwrap()
}

/// Serve the sessions of `node` with an echo, to each client: the
/// allowlist is not what these tests check.
fn serve(node: &Endpoint) {
    let open = || async {
        let (target, mut echo) = tokio::io::duplex(PIPE);
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut echo);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        Ok::<DuplexStream, String>(target)
    };
    let each = |_: &PublicKey| true;
    tokio::spawn(podssh_iroh::far::serve(node.clone(), Settings::default(), 16 << 20, open, each));
}

/// `hello` there and back over one session of `dialer`, or why it got none.
async fn hello(dialer: &Dialer) -> Result<Vec<u8>, Failure> {
    let (mut app, app_end) = tokio::io::duplex(PIPE);
    let talk = async move {
        app.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        app.read_exact(&mut back).await.map(|_| back.to_vec())
    };
    let (carried, echoed) = tokio::time::timeout(LIMIT, async {
        tokio::join!(podssh_iroh::carry(dialer, app_end, Settings::default(), |_| {}), talk)
    })
    .await
    .expect("the session within the limit");
    dialer.close().await;
    let _: Outcome = carried?;
    echoed.map_err(|e| Failure::Failed(e.to_string()))
}

/// The record of `key` at `server` once it names `relay`, within the limit.
async fn record_naming(server: &Server, key: &PublicKey, trust: &Trust, relay: &RelayUrl) -> Record {
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Ok(Some(record)) = pkarr::lookup(server, key, trust, &ProxyChoice::Direct, LIMIT).await {
            if record.relays.contains(relay) {
                return record;
            }
        }
        assert!(Instant::now() < deadline, "no record that names {relay} within {} s", LIMIT.as_secs());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// What a finder says, kept for the test.
fn heard() -> (Arc<Mutex<Vec<String>>>, impl Fn(String) + Send + Sync + 'static) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = lines.clone();
    (lines, move |line: String| kept.lock().unwrap().push(line))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_with_the_first_ticket_finds_the_node_on_its_second_relay() {
    let dir = scratch("moved");
    let stand_in = test_pkarr::spawn(&dir).await.expect("a server of pkarr");
    let (server, trust) = server_of(&stand_in);
    let (_, first, _first) = iroh::test_utils::run_relay_server_with(false).await.expect("the first relay");
    let (_, second, _second) = iroh::test_utils::run_relay_server_with(false).await.expect("the second relay");
    let secret = SecretKey::from_bytes(&[0x35; 32]);

    // The node on its first relay: its ticket names that relay.
    let before = podssh_iroh::bind(&options(&first, Some(secret.clone()), true)).await.expect("the node");
    tokio::time::timeout(LIMIT, before.online()).await.expect("the node's first home relay");
    let old = ticket::of(&before, &first);
    before.close().await;

    // The node again, with the same key, on the second relay, as after a
    // start at which the first did not answer; its record says so.
    let node = podssh_iroh::bind(&options(&second, Some(secret.clone()), true)).await.expect("the node again");
    tokio::time::timeout(LIMIT, node.online()).await.expect("the node's second home relay");
    let (node_said, say) = heard();
    let keeping = tokio::spawn(pkarr::keep(node.clone(), server.clone(), trust.clone(), ProxyChoice::Direct, say));
    let record = record_naming(&server, &secret.public(), &trust, &second).await;
    assert_eq!(record.relays, vec![second.clone()], "the record names the home relay alone");
    serve(&node);

    // A client on the first relay, with the first ticket: the first relay
    // does not reach the node, and the record names the second.
    let client = podssh_iroh::bind(&options(&first, None, false)).await.expect("the client");
    let (client_said, say) = heard();
    let finder = Finder::new(server.clone(), trust.clone(), ProxyChoice::Direct).saying(say);
    let dialer = Dialer::new(client.clone(), ticket::parse(&old).expect("the first ticket")).finding(finder);
    let got = hello(&dialer).await;
    let said = client_said.lock().unwrap().clone();
    assert_eq!(got, Ok(b"hello".to_vec()), "{said:?}");
    assert!(said.iter().any(|l| l.contains(&format!("names the home relay {second}"))), "{said:?}");
    // The ticket to give next time names the second relay.
    let now = EndpointAddr::new(secret.public()).with_relay_url(second.clone());
    assert_eq!(dialer.moved(), Some(ticket::format(&now)));
    let node_said = node_said.lock().unwrap().clone();
    assert!(node_said.iter().any(|l| l.contains(&format!("names the home relay {second}"))), "{node_said:?}");

    // Another client, whose ticket's relay does not answer: the record is
    // asked before the first dial, so no wait for that relay comes first.
    let other = podssh_iroh::bind(&options(&first, None, false)).await.expect("another client");
    let gone = EndpointAddr::new(secret.public()).with_relay_url(silent_relay());
    let finder = Finder::new(server, trust, ProxyChoice::Direct).first(true);
    let dialer = Dialer::new(other.clone(), gone).finding(finder);
    let started = Instant::now();
    assert_eq!(hello(&dialer).await, Ok(b"hello".to_vec()));
    assert!(started.elapsed() < FIND_AFTER, "the record was asked late: {:?}", started.elapsed());

    keeping.abort();
    other.close().await;
    client.close().await;
    node.close().await;
}

/// The record of `node` that names `relay`, signed by `signer`: the bytes of
/// the node's own record (its names in the node's zone, which anyone can
/// write), with `signer`'s signature over them in place of the node's.
fn signed_by(node: &SecretKey, signer: &SecretKey, relay: &RelayUrl) -> Vec<u8> {
    let own = EndpointInfo::new(node.public())
        .with_relay_url(relay.clone())
        .to_pkarr_signed_packet(node, pkarr::TTL)
        .expect("the node's record");
    let (dns, time) = (own.encoded_packet(), own.timestamp().as_micros());
    // What pkarr signs: BEP 44's form of the sequence number and the value.
    let mut signed = format!("3:seqi{time}e1:v{}:", dns.len()).into_bytes();
    signed.extend_from_slice(dns);
    let mut payload = signer.sign(&signed).to_bytes().to_vec();
    payload.extend_from_slice(&time.to_be_bytes());
    payload.extend_from_slice(dns);
    payload
}

/// Whether a client with the reading `read` refuses a record of the node
/// that another key signed, as a server that forged it serves it; the same
/// bytes signed by the node are taken first, so only the signature differs.
async fn refuses_a_forged_record(name: &str, read: Read) -> bool {
    let dir = scratch(name);
    let stand_in = test_pkarr::spawn(&dir).await.expect("a server of pkarr");
    let (server, trust) = server_of(&stand_in);
    let node = SecretKey::from_bytes(&[0x51; 32]);
    let forger = SecretKey::from_bytes(&[0x52; 32]);
    let relay: RelayUrl = "https://relay.forged.test".parse().unwrap();
    let finder = Finder::new(server, trust, ProxyChoice::Direct).reading(read);
    stand_in.plant(&node.public(), signed_by(&node, &node, &relay));
    let own = finder.find(&node.public()).await.map(|found| found.map(|record| record.relays));
    assert_eq!(own, Ok(Some(vec![relay.clone()])), "the node's own record");
    stand_in.plant(&node.public(), signed_by(&node, &forger, &relay));
    match finder.find(&node.public()).await {
        Err(why) => why.contains("not signed by the node's key"),
        Ok(_) => false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_that_another_key_signed_is_refused() {
    assert!(refuses_a_forged_record("forged", pkarr::read).await, "a record that another key signed was taken");
}

/// A planted reading that skips the check of the signature.
fn unchecked(key: &PublicKey, payload: &[u8]) -> Result<Record, String> {
    let mut bytes = key.as_bytes().to_vec();
    bytes.extend_from_slice(payload);
    let packet = SignedPacket::from_bytes_unchecked(&bytes).map_err(|e| e.to_string())?;
    Record::of(&packet)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_planted_reader_that_skips_the_signature_fails_the_check() {
    let caught = refuses_a_forged_record("planted", unchecked).await;
    assert!(!caught, "the check cannot tell a reader that skips the signature");
}

/// rustls's configuration that trusts the stand-in's certificate alone, for
/// iroh's own client.
fn trusting(der: &[u8]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(der.to_vec())).expect("the stand-in's certificate");
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the provider's versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// iroh's own client of pkarr (iroh 1.4.1's `PkarrRelayClient`, software
/// that podssh did not write) against the same server: each reads what the
/// other put.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iroh_s_own_client_reads_podssh_s_record_and_podssh_reads_iroh_s() {
    let dir = scratch("iroh");
    let stand_in = test_pkarr::spawn(&dir).await.expect("a server of pkarr");
    let (server, trust) = server_of(&stand_in);
    let resolver = iroh::dns::DnsResolver::custom(podssh_iroh::resolve::Podssh);
    let theirs = PkarrRelayClient::new(stand_in.url.clone(), trusting(&stand_in.der), resolver);

    let ours = SecretKey::from_bytes(&[0x61; 32]);
    let relay: RelayUrl = "https://relay-a.podssh.test".parse().unwrap();
    pkarr::publish(&server, &ours, &relay, &trust, &ProxyChoice::Direct, LIMIT).await.expect("podssh puts its record");
    let packet = theirs.resolve(ours.public()).await.expect("iroh's client reads podssh's record");
    let info = EndpointInfo::from_pkarr_signed_packet(&packet).expect("iroh's record of a node");
    assert_eq!(info.relay_urls().cloned().collect::<Vec<_>>(), vec![relay]);

    let iroh_key = SecretKey::from_bytes(&[0x62; 32]);
    let other: RelayUrl = "https://relay-b.podssh.test:8443".parse().unwrap();
    let packet = EndpointInfo::new(iroh_key.public())
        .with_relay_url(other.clone())
        .to_pkarr_signed_packet(&iroh_key, 30)
        .expect("iroh's record");
    theirs.publish(&packet).await.expect("iroh's client puts its record");
    let found = pkarr::lookup(&server, &iroh_key.public(), &trust, &ProxyChoice::Direct, LIMIT).await;
    let record = found.expect("an answer").expect("a record");
    assert_eq!(record.relays, vec![other]);
    assert_eq!(stand_in.payload(&iroh_key.public()), Some(packet.to_relay_payload()), "iroh put its own bytes");
}
