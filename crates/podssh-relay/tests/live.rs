//! Against the live relay. Ignored by default: it needs the network and mints
//! a relay token (self-service, cached per machine).
//!
//! ```sh
//! cargo test -p podssh-relay --test live -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::open::Request;
use podssh_relay::relay;
use podssh_ws::Trust;

async fn open_github() -> podssh_relay::Opened {
    let pool = podssh_relay::pool::alternates(relay::DEFAULT_RELAY_HOST);
    let relays = relay::select_relays(None, std::env::var(relay::RELAY_ENV).ok(), &pool).unwrap();
    let path = relay::forward_path("github.com", 22).unwrap();
    let request = Request { relays: &relays, path: &path, trust: &Trust::Default, target: "github.com:22", rounds: 1 };
    match podssh_relay::open(&request, &mut |note: &str| eprintln!("note: {note}")).await {
        Ok(opened) => opened,
        Err(failure) => panic!("no session: {:?}", failure.lines("github.com:22")),
    }
}

/// Whether the relay answers WebSocket pings decides whether
/// `watch_liveness` can find a dead link in seconds (it never declares a link
/// dead before a first pong, so a relay that does not answer is safe, only
/// slower).
#[tokio::test(flavor = "current_thread")]
#[ignore = "network: the live relay"]
async fn the_relay_answers_websocket_pings() {
    let opened = open_github().await;
    eprintln!("session from {}", opened.relay.host);
    let session = Arc::new(opened.session);
    let reader = {
        let session = session.clone();
        tokio::spawn(async move {
            // Pongs are counted inside read_frame, so it must keep running.
            while session.read_frame().await.is_ok() {}
        })
    };
    for n in 1u64..=3 {
        session.send_ping(&n.to_be_bytes()).await.expect("ping sent");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let pongs = session.pongs_received();
    eprintln!("pongs received for 3 pings: {pongs}");
    reader.abort();
    assert!(pongs >= 1, "the relay answered no ping");
}
