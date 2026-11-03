//! The quiet probe at the default relay (T-325), which serves none of the
//! probes: a socket of its reverse road, for a pair made for the check and
//! stopped after it, which that relay ends for no idleness and sends no
//! keepalive on (`docs/relay.md`, the reverse path), held quiet after the
//! relay's hello. An end before the hold is the path's, or the relay's own
//! drop of a node's socket, which was seen with no Close before; the line
//! names both. The pair's tokens are never shown.

use std::time::Duration;

use podssh_relay::pair::{self, Pair, PairContext};
use podssh_relay::relay::Relay;
use podssh_ws::client::{next_event, open_tls, upgrade, Event};
use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::frame::OPCODE_CLOSE;
use podssh_ws::Trust;
use tokio::io::AsyncReadExt;
use tokio::time::Instant;

use super::super::Report;
use super::http::CONNECT_WAIT;
use super::judge::{self, SocketEnd};

/// The probe's line at `relay`: a pair, its node's socket held quiet for
/// `hold`, then the pair stopped, whatever the socket did.
pub(super) async fn socket(report: &mut Report<'_>, relay: &Relay, trust: &Trust, hold: Duration) {
    let at = dial::authority(&relay.host, relay.port);
    let proxy = ProxyChoice::FromEnvironment;
    let ctx = PairContext { relay, trust, proxy: &proxy, timeout: CONNECT_WAIT };
    let pair = match pair::create(&ctx).await {
        Ok(pair) => pair,
        Err(e) => {
            let why = format!("a socket of the reverse road at {at}: no pair for the check: {e}");
            return report.unknown("quiet stream", why);
        }
    };
    let ended = held(relay, &pair, trust, hold).await;
    // The pair is the check's alone: it goes now, or at its expiry.
    let left = match pair::stop(&ctx, &pair).await {
        Ok(_) => String::new(),
        Err(e) => format!("; the pair made for the check could not be stopped ({e}), and ends at its expiry"),
    };
    let verdict = match judge::socket(&at, hold, &ended) {
        podssh_ws::Verdict::Ok { detail } => podssh_ws::Verdict::Ok { detail: format!("{detail}{left}") },
        other => other,
    };
    super::measured(report, "quiet stream", verdict, judge::socket_numbers(hold, &ended));
}

/// The node's socket of `pair`, upgraded, then read until it ends or `hold`
/// is over: `None` when it held, else when it ended and how.
async fn held(relay: &Relay, pair: &Pair, trust: &Trust, hold: Duration) -> SocketEnd {
    let proxy = ProxyChoice::FromEnvironment;
    let tls =
        open_tls(&relay.host, relay.port, &relay.host, trust, &proxy, CONNECT_WAIT).await.map_err(|e| e.to_string())?;
    let host = dial::authority(&relay.host, relay.port);
    let path = format!("/v1/node/{}", pair.name);
    let upgraded = tokio::time::timeout(CONNECT_WAIT, upgrade(tls, &host, &path, pair.node_token())).await;
    let (mut tls, mut pending) = match upgraded {
        Ok(Ok(upgraded)) => upgraded,
        Ok(Err(e)) => return Err(format!("the socket's upgrade: {e}")),
        Err(_) => return Err(format!("no answer to the socket's upgrade within {} s", CONNECT_WAIT.as_secs())),
    };
    let started = Instant::now();
    let mut chunk = vec![0u8; 4096];
    loop {
        // The relay's frames, its hello among them; a Ping is not answered,
        // as the relay sends none on this road.
        while let Ok(Some(event)) = next_event(&mut pending) {
            if let Event::Frame(frame) = event {
                if frame.opcode == OPCODE_CLOSE {
                    let code = frame.payload.get(..2).map(|c| u16::from_be_bytes([c[0], c[1]]));
                    let reason = String::from_utf8_lossy(frame.payload.get(2..).unwrap_or_default());
                    let why = match code {
                        Some(code) => format!("the relay's Close {code} {}", podssh_ws::text::one_line(&reason)),
                        None => "the relay's Close with no code".to_string(),
                    };
                    return Ok(Some((started.elapsed(), why)));
                }
            }
        }
        match tokio::time::timeout_at(started + hold, tls.read(&mut chunk)).await {
            Err(_) => return Ok(None),
            Ok(Ok(0)) => return Ok(Some((started.elapsed(), "an end with no Close".into()))),
            Ok(Err(e)) => return Ok(Some((started.elapsed(), super::http::cut_words(&e)))),
            Ok(Ok(n)) => pending.extend_from_slice(&chunk[..n]),
        }
    }
}
