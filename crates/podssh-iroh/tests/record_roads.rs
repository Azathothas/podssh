//! A node's record names each of its roads (T-445), offline: a server of
//! pkarr on the loopback, which reads each `PUT` with iroh-dns's own check,
//! and podssh-relay's stand-in DERP server in memory. A record with the iroh
//! home relay, the DERP home and the quick tunnel is put and read back
//! whole, by podssh and, for its iroh part, by iroh's own client of pkarr. A
//! node keeps its record as its DERP road comes online, and a client with
//! the node's key alone, and no ticket, finds the record, races each road
//! that it names, and reaches the node over DERP where the iroh road is
//! refused. A planted record with no DERP home fails that test.

mod cleanup;
#[path = "../../podssh-relay/tests/derp_stand_in/mod.rs"]
mod derp_stand_in;

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use derp_stand_in::StandIn;
use iroh::address_lookup::PkarrRelayClient;
use iroh::endpoint_info::EndpointInfo;
use iroh::tls::CaTlsConfig;
use iroh::{EndpointAddr, RelayUrl, SecretKey};
use podssh_iroh::pkarr::{self, record, Finder, Record, Roads, Server};
use podssh_iroh::test_pkarr::{self, TestPkarr};
use podssh_iroh::{Dialer, Options, Udp};
use podssh_relay::derp::{self as derp_road, far, Key, Secret, Ticket};
use podssh_relay::identity::Identity;
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::race::{in_turn, Start, HEAD_START};
use podssh_relay::session::{Ask, OsEntropy, Settings};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::watch;

const LIMIT: Duration = Duration::from_secs(60);
const PIPE: usize = 64 * 1024;
/// The replay buffers that the node keeps, at most.
const BUDGET: usize = 16 << 20;
const QUICK: &str = "four-words-of-a.trycloudflare.com";

/// A fresh, empty scratch directory unique to one test, removed when it ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-iroh-roads-{name}-{}", std::process::id()));
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

/// A relay on a port of the loopback where nothing listens: the iroh road,
/// refused on the way.
fn silent_relay() -> RelayUrl {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("https://localhost:{port}").parse().unwrap()
}

fn say(who: &'static str) -> derp_road::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_with_each_road_is_put_and_read_back_whole() {
    let dir = scratch("whole");
    let stand_in = test_pkarr::spawn(&dir).await.expect("a server of pkarr");
    let (server, trust) = server_of(&stand_in);
    let node = SecretKey::from_bytes(&[0x71; 32]);
    let relay: RelayUrl = "https://relay-a.podssh.test".parse().unwrap();
    let ticket = Ticket {
        node: podssh_relay::identity::PublicKey(*node.public().as_bytes()),
        derp: Key([9; 32]),
        server: derp_road::Server::new("tc301a.ipn.dev", 443).unwrap(),
    };
    let roads = Roads { relay: Some(relay.clone()), derp: Some(ticket.clone()), quick: Some(QUICK.into()) };
    // The stand-in reads the PUT with iroh-dns's own check of the signature.
    pkarr::publish(&server, &node, &roads, &trust, &ProxyChoice::Direct, LIMIT).await.expect("the record is put");
    let found = pkarr::lookup(&server, &node.public(), &trust, &ProxyChoice::Direct, LIMIT).await;
    let record: Record = found.expect("an answer").expect("a record");
    assert_eq!(record.relays, vec![relay.clone()]);
    assert_eq!(record.derp, Some(ticket));
    assert_eq!(record.quick.as_deref(), Some(QUICK));
    // iroh's own client of pkarr reads the same bytes as a record of a node:
    // its relay, with podssh's names passed by.
    let resolver = iroh::dns::DnsResolver::custom(podssh_iroh::resolve::Podssh);
    let theirs = PkarrRelayClient::new(stand_in.url.clone(), trusting(&stand_in.der), resolver);
    let packet = theirs.resolve(node.public()).await.expect("iroh's client reads podssh's record");
    let info = EndpointInfo::from_pkarr_signed_packet(&packet).expect("iroh's record of a node");
    assert_eq!(info.relay_urls().cloned().collect::<Vec<_>>(), vec![relay]);
    assert_eq!(packet.txt_records(record::PODSSH_TXT_NAME).len(), 2, "the DERP home and the quick tunnel");
}

/// A link of the client's race, on either road.
enum Link {
    Iroh(podssh_iroh::Stream),
    Derp(derp_road::Link),
}

impl AsyncRead for Link {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Link::Iroh(link) => Pin::new(link).poll_read(cx, buf),
            Link::Derp(link) => Pin::new(link).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Link {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Link::Iroh(link) => Pin::new(link).poll_write(cx, buf),
            Link::Derp(link) => Pin::new(link).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Link::Iroh(link) => Pin::new(link).poll_flush(cx),
            Link::Derp(link) => Pin::new(link).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Link::Iroh(link) => Pin::new(link).poll_shutdown(cx),
            Link::Derp(link) => Pin::new(link).poll_shutdown(cx),
        }
    }
}

type Going<'a> = Pin<Box<dyn Future<Output = Result<Link, String>> + 'a>>;

/// An echo of each byte, as the node's target.
async fn echo() -> Result<DuplexStream, String> {
    let (ours, theirs) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(theirs);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    Ok(ours)
}

/// The record of `key` at `server` once it names a DERP home, within the
/// limit: the node's keeper puts it again when its DERP road comes online.
async fn record_with_derp(finder: &Finder, key: &iroh::PublicKey) -> Record {
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Ok(Some(record)) = finder.find(key).await {
            if record.derp.is_some() {
                return record;
            }
        }
        assert!(Instant::now() < deadline, "no record that names its DERP home within {} s", LIMIT.as_secs());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_with_the_node_s_key_alone_reaches_it_over_derp_when_iroh_is_refused() {
    let dir = scratch("alone");
    let pkarr_stand_in = test_pkarr::spawn(&dir).await.expect("a server of pkarr");
    let (server, trust) = server_of(&pkarr_stand_in);
    // One key for each road, as a node has (T-087): its identity, and the
    // same seed as iroh's key, which signs the record.
    let seed = [0x72; 32];
    let identity = Identity::from_seed(&seed);
    let secret = SecretKey::from_bytes(&seed);
    assert_eq!(identity.public().0, *secret.public().as_bytes());

    // The node's record first names its iroh home alone, a relay that the
    // way refuses.
    let refused = silent_relay();
    let (told, roads) = watch::channel(Roads { relay: Some(refused.clone()), ..Roads::default() });
    let said = |line: String| eprintln!("node: {line}");
    let (at, kept_trust) = (server.clone(), trust.clone());
    let keeping = tokio::spawn(pkarr::keep_roads(secret.clone(), at, kept_trust, ProxyChoice::Direct, roads, said));
    // Its DERP road comes online at the stand-in, under the key that its
    // identity gives, and the record names it then.
    let derp = StandIn::new(0);
    let settings = Settings { features: derp_road::FEATURES, ..Settings::default() };
    let node = far::Node {
        secret: Arc::new(Secret::of_node(&identity)),
        server: StandIn::server(),
        dial: derp.dial(),
        say: say("node"),
    };
    let first = far::connect(&node).await.expect("the node's connection to its DERP home");
    let ticket = Ticket { node: identity.public(), derp: first.key(), server: StandIn::server() };
    let keeper = Arc::new(Keeper::new(settings.resume_deadline));
    let serving = tokio::spawn(far::serve_from(node, Some(first), settings, BUDGET, echo, keeper));
    told.send_modify(|roads| roads.derp = Some(ticket.clone()));

    // The client has the node's key alone: no ticket of either road.
    let finder = Finder::new(server, trust, ProxyChoice::Direct);
    let found = record_with_derp(&finder, &secret.public()).await;
    assert_eq!(found.derp.as_ref(), Some(&ticket), "the DERP home that the node put");
    assert_eq!(found.relays, vec![refused.clone()]);

    // The iroh road of the record, then its DERP road 250 ms later.
    let options = Options {
        relays: found.relays.clone(),
        proxy: ProxyChoice::Direct,
        trust: Trust::Default,
        udp: Udp::Off,
        secret: None,
        accepts: false,
        relay_tls: Some(CaTlsConfig::insecure_skip_verify()),
        qad_port: None,
        quic: None,
    };
    let client = podssh_iroh::bind(&options).await.expect("the client's endpoint");
    let addr = found.relays.iter().cloned().fold(EndpointAddr::new(secret.public()), EndpointAddr::with_relay_url);
    let iroh = Dialer::new(client.clone(), addr);
    let over_derp = derp_road::Dialer::new(found.derp.as_ref().unwrap(), derp.dial(), say("client")).unwrap();
    let roads: Vec<(Start, Going<'_>)> = vec![
        (Start::After(HEAD_START), Box::pin(async { iroh.link().await.map(Link::Iroh).map_err(|e| e.to_string()) })),
        (Start::After(HEAD_START), Box::pin(async { over_derp.link().await.map(Link::Derp) })),
    ];
    let (won, _) = tokio::time::timeout(LIMIT, in_turn(roads)).await.expect("in time").expect("a road answers");
    assert_eq!(won.at, 1, "the DERP road carries the session");

    // A session of the layer on the winner's link: hello, and its echo.
    let session = won.link.start(Ask::New, settings, &mut OsEntropy).await.expect("the layer's handshake");
    let (app, mut user) = tokio::io::duplex(PIPE);
    let talk = async move {
        user.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        user.read_exact(&mut back).await.map(|_| back.to_vec())
    };
    let both = async { tokio::join!(session.run(app), talk) };
    let (_, echoed) = tokio::time::timeout(LIMIT, both).await.expect("in time");
    assert_eq!(echoed.expect("the echo"), b"hello".to_vec());

    over_derp.close().await;
    iroh.close().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), client.close()).await;
    serving.abort();
    keeping.abort();
}
