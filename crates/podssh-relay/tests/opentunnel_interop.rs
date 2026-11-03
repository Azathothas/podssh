//! The OpenTunnel road (T-530) against OpenTunnel's own server,
//! `anomalyco/opentunnel:crates/opentunnel-server` at v0.6.1, which
//! `.github/workflows/opentunnel-interop.yml` builds from its source and runs
//! with MySQL 8 and its local test CA (`ISSUER=local`), through a plain squid
//! as the host's proxy: software that podssh did not write. A node makes a
//! tunnel and attaches; a client reaches it by TLS by name and a session of
//! the layer echoes 1 MiB; a node started again keeps its tunnel and binds no
//! new CSR; a wrong token is named. Each dial goes to the server's address
//! through squid, with the name in TLS alone, so that no resolver needs the
//! test's domain. With no server named, the test says so and passes, unless
//! `PODSSH_OPENTUNNEL_TEST_REQUIRED` is set; `PODSSH_OPENTUNNEL_TEST_PLANT=
//! no-wildcard` makes the node's CSR name the tunnel alone, which the server
//! refuses, so that the workflow sees the check fail.
#![cfg(feature = "opentunnel")]

mod cleanup;
mod opentunnel_stand_in;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use opentunnel_stand_in::keys::{NoWildcard, TestCredentials};
use podssh_relay::opentunnel::api::Api;
use podssh_relay::opentunnel::bridge::{self, Failed};
use podssh_relay::opentunnel::dial::{BoxIo, Dial, Dialing, Visit};
use podssh_relay::opentunnel::{self, far, Credentials, Dialer, Name, Service, Store};
use podssh_relay::session::Settings;
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const LIMIT: Duration = Duration::from_secs(300);
const BUDGET: usize = 64 << 20;
const MIB: usize = 1 << 20;

/// The server of the run, from the workflow's variables.
#[derive(Clone)]
struct Server {
    host: String,
    port: u16,
    domain: String,
    ca: PathBuf,
    proxy: ProxyChoice,
}

fn server() -> Option<Server> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    let Some(addr) = var("PODSSH_OPENTUNNEL_TEST_SERVER") else {
        assert!(var("PODSSH_OPENTUNNEL_TEST_REQUIRED").is_none(), "PODSSH_OPENTUNNEL_TEST_SERVER is required");
        eprintln!("no OpenTunnel server named (PODSSH_OPENTUNNEL_TEST_SERVER): skipped");
        return None;
    };
    let (host, port) = addr.rsplit_once(':').expect("HOST:PORT");
    let proxy = match var("PODSSH_OPENTUNNEL_TEST_PROXY") {
        Some(url) => ProxyChoice::Via(podssh_ws::proxy::Proxy::parse(&url).expect("a proxy's URL")),
        None => ProxyChoice::Direct,
    };
    Some(Server {
        host: host.to_string(),
        port: port.parse().expect("a port"),
        domain: var("PODSSH_OPENTUNNEL_TEST_DOMAIN").unwrap_or_else(|| "opentunnel.test".into()),
        ca: PathBuf::from(var("PODSSH_OPENTUNNEL_TEST_CA").expect("PODSSH_OPENTUNNEL_TEST_CA, the server's local CA")),
        proxy,
    })
}

/// TLS to the server's address through the proxy, by the domain's name.
fn api_dial(server: &Server) -> Dial {
    let server = server.clone();
    Arc::new(move |_: &Service| -> Dialing {
        let server = server.clone();
        Box::pin(async move {
            let tcp = podssh_ws::dial::dial(&server.host, server.port, &server.proxy, LIMIT)
                .await
                .map_err(|e| e.to_string())?;
            let tls = podssh_ws::tls_over(tcp, &server.domain, &Trust::File(server.ca.clone()), LIMIT)
                .await
                .map_err(|e| e.to_string())?;
            Ok(Box::new(tls) as BoxIo)
        })
    })
}

/// TCP to the server's address through the proxy, before a client's TLS.
fn visit(server: &Server) -> Visit {
    let server = server.clone();
    Arc::new(move |_: &str| -> Dialing {
        let server = server.clone();
        Box::pin(async move {
            let tcp = podssh_ws::dial::dial(&server.host, server.port, &server.proxy, LIMIT)
                .await
                .map_err(|e| e.to_string())?;
            Ok(Box::new(tcp) as BoxIo)
        })
    })
}

fn say(who: &'static str) -> opentunnel::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-opentunnel-interop-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

async fn echo() -> Result<DuplexStream, String> {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(theirs);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
        let _ = writer.shutdown().await;
    });
    Ok(ours)
}

/// 1 MiB to the node's echo and back, in a session of the layer.
async fn echo_mib(dialer: &Dialer) {
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out: Vec<u8> = (0..MIB).map(|i| (i * 7 % 251) as u8).collect();
    let carrying = Box::pin(opentunnel::carry(dialer, app, Settings::default(), |_| {}));
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let writing = async { writer.write_all(&out).await.expect("the layer takes the bytes") };
        let reading = async {
            let mut back = vec![0u8; out.len()];
            reader.read_exact(&mut back).await.expect("the echo");
            back
        };
        let ((), back) = tokio::join!(writing, reading);
        drop((reader, writer));
        back
    };
    let (carried, back) = tokio::time::timeout(LIMIT, async { tokio::join!(carrying, using) }).await.expect("in time");
    carried.expect("the session");
    assert_eq!(Sha256::digest(&back), Sha256::digest(&out), "each byte came back once, in order");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn against_opentunnel_s_own_server_a_node_keeps_its_tunnel_and_a_client_echoes_one_mib() {
    let Some(server) = server() else { return };
    let service = Service { host: server.domain.clone(), port: 443 };
    let dir = scratch("own");
    let store = || Store::in_dirs(vec![dir.clone()], vec![dir.clone()], &service, "lab");
    let api = || Api::new(service.clone(), api_dial(&server));
    let planted = std::env::var("PODSSH_OPENTUNNEL_TEST_PLANT").is_ok_and(|v| v == "no-wildcard");
    let credentials: &dyn Credentials = if planted { &NoWildcard } else { &TestCredentials };
    let (node, made) = far::online(api(), store(), credentials, say("node")).await.expect("the node's tunnel");
    assert!(made.made && made.new_csr && made.record.ready());
    let name = Name::parse(&node.name()).expect("the node's name");
    let serving = tokio::spawn(far::serve(node, Settings::default(), BUDGET, echo));
    let trust = Trust::File(server.ca.clone());
    let dialer = Dialer::new(name.clone(), visit(&server), trust, say("client"));
    // The bridge attaches in the first seconds; a link before it is closed.
    let mut tries = 0;
    loop {
        match dialer.link().await {
            Ok(_) => break,
            Err(why) if tries < 30 => {
                tries += 1;
                eprintln!("not yet: {why}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(why) => panic!("the node is not reached: {why}"),
        }
    }
    echo_mib(&dialer).await;
    serving.abort();
    // Started again: the same tunnel, no new CSR.
    let (again, kept) = far::online(api(), store(), credentials, say("node")).await.expect("the tunnel kept");
    assert!(!kept.made && !kept.new_csr, "a second start made or bound nothing new");
    assert_eq!(again.name(), name.to_string());
    let routes = vec![kept.record.route.clone()];
    let failed = bridge::attach(&api(), &kept.record.id, "not-the-token", &routes).await.expect_err("a wrong token");
    assert!(matches!(&failed, Failed::Fatal(why) if why.contains("bad_token")), "{failed}");
}
