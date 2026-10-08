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

/// How the relay takes an IPv6 address (GitHub #2): podssh sends the bare
/// literal, and the upgrade must succeed. Whether bytes then reach the
/// target depends on the relay's egress, so it is printed, not asserted:
/// on 2026-10-08 the session closed at once with 1011 "target closed before
/// sending anything", while IPv4 to the same host worked.
#[tokio::test(flavor = "current_thread")]
#[ignore = "network: the live relay"]
async fn ipv6_the_relay_takes_the_bare_literal() {
    let pool = podssh_relay::pool::alternates(relay::DEFAULT_RELAY_HOST);
    let relays = relay::select_relays(None, std::env::var(relay::RELAY_ENV).ok(), &pool).unwrap();
    // Google's DNS over TLS: a public IPv6 address, on a port that is not a
    // web port (the relay's direct road refuses those).
    let target = "[2001:4860:4860::8888]:853";
    let path = relay::forward_path("2001:4860:4860::8888", 853).unwrap();
    assert_eq!(path, "/connect/2001:4860:4860::8888/853");
    let request = Request { relays: &relays, path: &path, trust: &Trust::Default, target, rounds: 1 };
    let opened = match podssh_relay::open(&request, &mut |note: &str| eprintln!("note: {note}")).await {
        Ok(opened) => opened,
        Err(failure) => panic!("the relay refused the literal: {:?}", failure.lines(target)),
    };
    eprintln!("the relay host {} took /connect/2001:4860:4860::8888/853", opened.relay.host);
    // A TLS record header with no body: a TLS server answers or closes.
    opened.session.send_binary(&[0x16, 0x03, 0x01, 0x00, 0x00]).await.expect("sent");
    match tokio::time::timeout(Duration::from_secs(15), opened.session.read_frame()).await {
        Ok(Ok(f)) if f.opcode == podssh_ws::frame::OPCODE_CLOSE => {
            let (code, reason) = podssh_ws::session::close_code_and_reason(&f.payload);
            eprintln!("the relay closed the session ({code:?} {reason}): its egress did not reach the IPv6 host");
        }
        Ok(Ok(f)) => eprintln!("{} bytes came back from the IPv6 host", f.payload.len()),
        Ok(Err(e)) => eprintln!("the session ended: {e}"),
        Err(_) => eprintln!("nothing came back within 15 s"),
    }
}
