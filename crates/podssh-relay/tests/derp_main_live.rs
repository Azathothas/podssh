//! Whether Tailscale's main DERP fleet lets podssh in (T-534, Q74), live and
//! short: for the first server of each region of the map that
//! `PODSSH_DERP_MAP_FILE` names (Tailscale's default map, read on the test's
//! day from the service `tailscale-derp-map` of pod-services), DERP's
//! handshake with a random key and podssh's name, then a node and a client
//! of one process exchange 64 KiB each way through that server alone, as
//! `derp_live` does for tailcat's fleet. A server lets podssh in when it
//! relays; each result is a line, for the record. Ignored, and run by hand:
//!
//! ```sh
//! curl -fsS https://login.tailscale.com/derpmap/default > map.json
//! PODSSH_DERP_MAP_FILE=map.json cargo test -p podssh-relay --features derp \
//!   --test derp_main_live -- --ignored --nocapture
//! ```

#![cfg(feature = "derp")]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::derp::conn::Setup;
use podssh_relay::derp::servers::Server;
use podssh_relay::derp::{dial, Conn, Dialer, Secret, Ticket};
use podssh_relay::identity::PublicKey;
use podssh_relay::session::OsEntropy;
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SIZE: usize = 64 * 1024;
/// The bound of each server's whole run: a short test (Q74).
const LIMIT: Duration = Duration::from_secs(30);

/// The first server of each region of a DERP map, in the order of the
/// regions' ids: its region's code and its host.
fn first_of_each_region(map: &serde_json::Value) -> Vec<(String, String)> {
    let Some(regions) = map.get("Regions").and_then(|r| r.as_object()) else { return Vec::new() };
    let mut ids: Vec<(u64, &serde_json::Value)> =
        regions.iter().filter_map(|(id, region)| Some((id.parse().ok()?, region))).collect();
    ids.sort_by_key(|(id, _)| *id);
    ids.into_iter()
        .filter_map(|(_, region)| {
            let code = region.get("RegionCode")?.as_str()?.to_string();
            let host = region.get("Nodes")?.as_array()?.first()?.get("HostName")?.as_str()?.to_string();
            Some((code, host))
        })
        .collect()
}

/// One server: `Ok` with the round trip when it relayed 64 KiB each way,
/// else where it stopped.
async fn relays(server: Server) -> Result<String, String> {
    let (trust, proxy) = (Trust::Default, ProxyChoice::FromEnvironment);
    let dial = dial::tls(trust, proxy);
    let say: podssh_relay::derp::Say = Arc::new(|_: String| {});
    let secret = Arc::new(Secret::random(&mut OsEntropy).map_err(|e| format!("{e:?}"))?);
    let io = (dial)(&server).await.map_err(|e| format!("TLS: {e}"))?;
    let setup = Setup { secret, serves: true, say: say.clone() };
    let node = Conn::start(server.clone(), io, setup).await.map_err(|e| format!("the handshake: {e}"))?;
    let ticket = Ticket { node: PublicKey([0; 32]), derp: node.key(), server: server.clone() };
    // This server alone: no fallback to tailcat's, which would measure another.
    let dialer = Dialer::with_servers(&ticket, vec![server], dial, say).map_err(|e| format!("{e:?}"))?;
    let (client, served) = tokio::join!(dialer.link(), node.accept());
    let (client, served) = match (client, served) {
        (Ok(client), Some(served)) => (client, served),
        (client, served) => {
            node.close();
            return Err(format!("no link: client {:?}, node {:?}", client.err(), served.map(|_| "a link")));
        }
    };
    let up: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    let down: Vec<u8> = (0..SIZE).map(|i| (i % 241) as u8).collect();
    let (mut got_up, mut got_down) = (vec![0u8; SIZE], vec![0u8; SIZE]);
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut served_r, mut served_w) = tokio::io::split(served);
    let (a, b, c, d) = tokio::join!(
        client_w.write_all(&up),
        served_w.write_all(&down),
        served_r.read_exact(&mut got_up),
        client_r.read_exact(&mut got_down),
    );
    let link = client_r.unsplit(client_w);
    let rtt = link.round_trip();
    dialer.close().await;
    node.close();
    a.and(b).map_err(|e| format!("a write: {e}"))?;
    c.and(d).map_err(|e| format!("a read: {e}"))?;
    if Sha256::digest(&got_up) != Sha256::digest(&up) || Sha256::digest(&got_down) != Sha256::digest(&down) {
        return Err("the bytes came back changed".into());
    }
    Ok(format!("relayed 64 KiB each way, round trip {rtt:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live: Tailscale's main DERP fleet, a short run of each region's first server (Q74)"]
async fn each_region_s_first_server_of_the_main_fleet_is_tried_with_podssh_s_key() {
    let Ok(path) = std::env::var("PODSSH_DERP_MAP_FILE") else {
        eprintln!("did not run: PODSSH_DERP_MAP_FILE names no map");
        return;
    };
    let map: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).expect("a DERP map");
    let firsts = first_of_each_region(&map);
    assert!(!firsts.is_empty(), "the map has no region");
    let mut relayed = 0;
    for (code, host) in &firsts {
        let Ok(server) = Server::new(host, 443) else { continue };
        let result = tokio::time::timeout(LIMIT, relays(server)).await.unwrap_or_else(|_| Err("no end in 30 s".into()));
        match &result {
            Ok(how) => {
                relayed += 1;
                eprintln!("result {code} {host}: {how}");
            }
            Err(why) => eprintln!("result {code} {host}: refused or failed: {why}"),
        }
    }
    eprintln!("result: {relayed} of {} regions' first servers relayed podssh", firsts.len());
}

#[test]
fn the_first_server_of_each_region_is_read_in_the_order_of_the_ids() {
    let map = serde_json::json!({"Regions": {
        "10": {"RegionCode": "sea", "Nodes": [{"HostName": "derp10.example"}, {"HostName": "derp10b.example"}]},
        "2": {"RegionCode": "sfo", "Nodes": [{"HostName": "derp2.example"}]},
        "3": {"RegionCode": "none", "Nodes": []}
    }});
    let got = first_of_each_region(&map);
    assert_eq!(got, vec![("sfo".into(), "derp2.example".into()), ("sea".into(), "derp10.example".into())]);
}
