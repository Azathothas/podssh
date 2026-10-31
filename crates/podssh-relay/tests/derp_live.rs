//! The DERP road against Tailscale's servers for tailcat (T-349), live and
//! short, run by hand: a node and a client in this process, at the first
//! server of the fleet whose probe answers through the proxy of the
//! environment, 64 KiB each way over one link with equal digests. The
//! operator's ruling Q50 lets the road use the fleet unasked. No throughput
//! is measured here: through a shared relay that measures its rate limit,
//! and tailcat refuses its own test of throughput through Tailscale's.
//!
//!     cargo test -p podssh-relay --features derp --test derp_live -- --ignored

#![cfg(feature = "derp")]

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::derp::conn::Setup;
use podssh_relay::derp::{dial, servers, Conn, Dialer, Secret, Ticket};
use podssh_relay::identity::PublicKey;
use podssh_relay::session::OsEntropy;
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SIZE: usize = 64 * 1024;
const LIMIT: Duration = Duration::from_secs(90);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live: Tailscale's servers for tailcat, through the proxy of the environment"]
async fn a_link_through_tailcat_s_fleet_carries_64_kib_each_way() {
    let (trust, proxy) = (Trust::Default, ProxyChoice::FromEnvironment);
    let (home, missed) = servers::home(&servers::fleet(), &trust, &proxy).await;
    let home = home.unwrap_or_else(|| panic!("no server of the fleet answered its probe: {missed:?}"));
    eprintln!("home: {home} (missed: {missed:?})");
    let dial = dial::tls(trust, proxy);
    let say: podssh_relay::derp::Say = Arc::new(|line: String| eprintln!("{line}"));
    let secret = Arc::new(Secret::random(&mut OsEntropy).unwrap());
    let io = (dial)(&home).await.expect("TLS to the server");
    let node = Conn::start(home.clone(), io, Setup { secret, serves: true, say: say.clone() }).await;
    let node = node.expect("DERP's handshake with the node's key");
    let ticket = Ticket { node: PublicKey([0; 32]), derp: node.key(), server: home };
    eprintln!("ticket: {ticket}");
    let dialer = Dialer::new(&ticket, dial, say).unwrap();
    let run = async {
        let (client, served) = tokio::join!(dialer.link(), node.accept());
        let (client, served) = (client.expect("the node answers"), served.expect("a link"));
        let up: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        let down: Vec<u8> = (0..SIZE).map(|i| (i % 241) as u8).collect();
        let (mut got_up, mut got_down) = (vec![0u8; SIZE], vec![0u8; SIZE]);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let (mut served_r, mut served_w) = tokio::io::split(served);
        tokio::join!(
            async { client_w.write_all(&up).await.expect("the client writes") },
            async { served_w.write_all(&down).await.expect("the node writes") },
            async { served_r.read_exact(&mut got_up).await.map(|_| ()).expect("the node reads") },
            async { client_r.read_exact(&mut got_down).await.map(|_| ()).expect("the client reads") },
        );
        assert_eq!(Sha256::digest(&got_up), Sha256::digest(&up));
        assert_eq!(Sha256::digest(&got_down), Sha256::digest(&down));
        eprintln!("round trip: {:?}", client_r.unsplit(client_w).round_trip());
    };
    tokio::time::timeout(LIMIT, run).await.expect("in time");
    dialer.close().await;
    node.close();
}
