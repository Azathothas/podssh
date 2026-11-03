//! The OpenTunnel road (T-530, T-531) through OpenTunnel's own service,
//! `https://opentunnel.xyz`, or the one of `PODSSH_OPENTUNNEL`, as the
//! operator's ruling Q76 allows: short runs, from GitHub Actions
//! (`opentunnel-live.yml`) and a session's own host. A node makes a tunnel
//! with a throwaway key, attaches its route, and a client reaches it by TLS
//! by name through the host's proxy, if any, and echoes 256 KiB in a session
//! of the layer; a node started again keeps its tunnel and binds no new CSR;
//! then the tunnel is deleted. `PODSSH_OPENTUNNEL_TEST_PLANT=other-route`
//! makes the client dial a route that no bridge holds, which must fail.
#![cfg(feature = "opentunnel")]

mod cleanup;
mod opentunnel_stand_in;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use opentunnel_stand_in::keys::TestCredentials;
use podssh_relay::opentunnel::api::Api;
use podssh_relay::opentunnel::{self, dial, far, Dialer, Name, Service, Setting, Store};
use podssh_relay::session::Settings;
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const LIMIT: Duration = Duration::from_secs(180);
const BUDGET: usize = 64 << 20;
const SIZE: usize = 256 * 1024;

fn say(who: &'static str) -> opentunnel::Say {
    Arc::new(move |line: String| eprintln!("{who}: {line}"))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-opentunnel-live-{name}-{}", std::process::id()));
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

/// A link once the node's bridge attached, within 30 s; then `SIZE` bytes
/// to the echo and back in a session of the layer: why it failed, if it did.
async fn echo_through(dialer: &Dialer) -> Result<(), String> {
    let mut tries = 0;
    loop {
        match dialer.link().await {
            Ok(_) => break,
            Err(why) if tries < 30 => {
                tries += 1;
                eprintln!("not yet: {why}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(why) => return Err(format!("the node is not reached: {why}")),
        }
    }
    let (app, user) = tokio::io::duplex(256 * 1024);
    let out: Vec<u8> = (0..SIZE).map(|i| (i * 13 % 251) as u8).collect();
    let carrying = Box::pin(opentunnel::carry(dialer, app, Settings::default(), |_| {}));
    let using = async {
        let (mut reader, mut writer) = tokio::io::split(user);
        let writing = async { writer.write_all(&out).await.map_err(|e| e.to_string()) };
        let reading = async {
            let mut back = vec![0u8; out.len()];
            reader.read_exact(&mut back).await.map(|_| back).map_err(|e| e.to_string())
        };
        let (wrote, back) = tokio::join!(writing, reading);
        drop((reader, writer));
        wrote.and(back)
    };
    let (carried, back) = tokio::time::timeout(LIMIT, async { tokio::join!(carrying, using) })
        .await
        .map_err(|_| "not in time".to_string())?;
    carried?;
    let back = back?;
    (Sha256::digest(&back) == Sha256::digest(&out)).then_some(()).ok_or_else(|| "the echo differs".to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: OpenTunnel's service (Q76), a short run: opentunnel-live.yml"]
async fn through_opentunnel_a_node_keeps_its_tunnel_and_a_client_echoes_through_it() {
    let service = match opentunnel::setting(std::env::var(opentunnel::ENV).ok().as_deref()).expect("the variable") {
        Setting::On(service) => service,
        Setting::Off => Service::hosted(),
    };
    let dir = scratch("own");
    let store = || Store::in_dirs(vec![dir.clone()], vec![dir.clone()], &service, "live");
    let api = Api::new(service.clone(), dial::tls(Trust::Default, ProxyChoice::FromEnvironment));
    let (node, made) = far::online(api.clone(), store(), &TestCredentials, say("node")).await.expect("a tunnel");
    let (id, token) = (made.record.id.clone(), made.record.token.clone());
    let mut name = Name::parse(&node.name()).expect("the node's name");
    if std::env::var("PODSSH_OPENTUNNEL_TEST_PLANT").is_ok_and(|v| v == "other-route") {
        name.route = "other".into();
    }
    let serving = tokio::spawn(far::serve(node, Settings::default(), BUDGET, echo));
    let dialer = Dialer::new(name, dial::tcp(ProxyChoice::FromEnvironment), Trust::Default, say("client"));
    let echoed = echo_through(&dialer).await;
    serving.abort();
    let again = far::online(api.clone(), store(), &TestCredentials, say("node")).await;
    // The throwaway tunnel goes, whatever the run found.
    let removed = api.remove(&token, &id).await;
    echoed.expect("the session through OpenTunnel");
    let (_, kept) = again.expect("the tunnel kept");
    assert!(!kept.made && !kept.new_csr && kept.record.id == id, "a second start made or bound nothing new");
    removed.expect("the tunnel deleted");
}
