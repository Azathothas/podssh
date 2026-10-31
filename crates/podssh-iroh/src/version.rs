//! Whether a relay takes this binary's iroh (T-348). n0's public relays
//! serve the newest iroh only, and a binary in the field is not updated on
//! its own, so a day may come when n0's relay refuses its handshake. iroh's
//! relay client keeps only the status of that refusal, and the relay's
//! answer names both sides' versions: podssh asks the relay itself, once its
//! connection to the relay has failed, never before, in one request: the
//! upgrade that iroh sends, with its versions, whose answer is read and the
//! connection closed.

use std::time::Duration;

use iroh::{Endpoint, RelayUrl, Watcher};
use iroh_relay::http::{ProtocolVersion, RELAY_PATH};
use podssh_ws::client::ConnectError;
use podssh_ws::{dial, ProxyChoice, Trust};

/// The iroh of this build, which the notice names; a test holds it to the
/// version that the lock builds.
pub const IROH: &str = "1.4.1";

/// The bound on the question, the connection included.
pub const LIMIT: Duration = Duration::from_secs(5);

/// A relay's answer to iroh's upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// `101`: it takes one of the versions.
    Takes,
    /// It refuses the versions, in its words.
    Refuses(String),
    /// Anything else: the question did not tell.
    Unknown(String),
}

/// Whether a refusal's words say that the version is what it refused, as
/// iroh's relay server words it ("unsupported relay version: we support
/// ... but you only provide ...").
fn names_the_version(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    body.contains("unsupported relay version") || body.contains("relay protocol version")
}

/// iroh's upgrade to `relay`, offering `versions`, through `proxy`, with
/// `relay`'s certificate checked against `trust`, within `limit`.
pub async fn ask_with(relay: &RelayUrl, versions: &str, trust: &Trust, proxy: &ProxyChoice, limit: Duration) -> Answer {
    let Some(host) = relay.host_str() else { return Answer::Unknown(format!("{relay}: no host")) };
    let host = host.trim_end_matches('.');
    let port = relay.port_or_known_default().unwrap_or(443);
    let key = match podssh_ws::handshake::generate_key() {
        Ok(key) => key,
        Err(e) => return Answer::Unknown(e.to_string()),
    };
    let host_header = if port == 443 { host.to_string() } else { dial::authority(host, port) };
    let request = format!(
        "GET {RELAY_PATH} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: podssh/{}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {versions}\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    let asked = async {
        let tls = podssh_ws::client::open_tls(host, port, host, trust, proxy, limit).await?;
        // The session is dropped at once: the relay waits for a handshake
        // that never comes, and closes its end.
        podssh_ws::client::upgrade_with(tls, request.as_bytes(), &key).await.map(drop)
    };
    match tokio::time::timeout(limit, asked).await {
        Err(_) => Answer::Unknown(format!("{host}: no answer within {} s", limit.as_secs())),
        Ok(Ok(())) => Answer::Takes,
        Ok(Err(ConnectError::Refused { body, .. })) if names_the_version(&body) => {
            Answer::Refuses(podssh_ws::text::one_line(&body))
        }
        Ok(Err(e)) => Answer::Unknown(format!("{host}: {e}")),
    }
}

/// [`ask_with`] with this build's versions.
pub async fn ask(relay: &RelayUrl, trust: &Trust, proxy: &ProxyChoice, limit: Duration) -> Answer {
    ask_with(relay, &ProtocolVersion::all_joined(), trust, proxy, limit).await
}

/// What a client or a node says when `relay` refused this build's iroh,
/// with the relay's `words`.
pub fn notice(relay: &RelayUrl, words: &str) -> String {
    let host = relay.host_str().unwrap_or_default().trim_end_matches('.');
    format!(
        "{host} refuses the iroh of this binary (iroh {IROH}, the relay protocol {}): \"{words}\". n0's public \
         relays serve the newest iroh only: podssh update brings a newer podssh, or --iroh-relay URL names a relay \
         that serves this one",
        ProtocolVersion::all_joined()
    )
}

/// The notice for the first of `relays` that refuses this build's iroh,
/// each asked in turn; none when each takes it or does not tell.
pub async fn refusal(relays: &[RelayUrl], trust: &Trust, proxy: &ProxyChoice) -> Option<String> {
    for relay in relays {
        if let Answer::Refuses(words) = ask(relay, trust, proxy, LIMIT).await {
            return Some(notice(relay, &words));
        }
    }
    None
}

/// Whether `endpoint` holds a connection to a home relay now.
pub fn is_online(endpoint: &Endpoint) -> bool {
    endpoint.home_relay_status().get().iter().any(|status| status.is_connected())
}

/// Why an endpoint did not come online.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offline {
    /// A home relay refused this build's iroh: the notice.
    Refused(String),
    /// No home relay within the limit.
    TimedOut,
}

/// Until `endpoint` is online, within `limit`. When the connection to a
/// home relay fails first, that relay is asked whether it takes this
/// build's iroh, once, and a refusal ends the wait at once, with its notice:
/// iroh would retry a refused version until the limit.
pub async fn online(endpoint: &Endpoint, limit: Duration, trust: &Trust, proxy: &ProxyChoice) -> Result<(), Offline> {
    let wait = async {
        let mut watcher = endpoint.home_relay_status();
        let mut asked: Vec<RelayUrl> = Vec::new();
        let mut now = watcher.get();
        loop {
            if now.iter().any(|status| status.is_connected()) {
                return Ok(());
            }
            let failed: Vec<RelayUrl> = now
                .iter()
                .filter(|status| status.last_error().is_some() && !asked.contains(status.url()))
                .map(|status| status.url().clone())
                .collect();
            for relay in failed {
                asked.push(relay.clone());
                if let Answer::Refuses(words) = ask(&relay, trust, proxy, LIMIT).await {
                    return Err(Offline::Refused(notice(&relay, &words)));
                }
            }
            now = match watcher.updated().await {
                Ok(now) => now,
                // The endpoint is gone: it comes online no more.
                Err(_) => return Err(Offline::TimedOut),
            };
        }
    };
    tokio::time::timeout(limit, wait).await.unwrap_or(Err(Offline::TimedOut))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_notice_names_the_relay_this_iroh_and_the_two_ways_out() {
        let relay: RelayUrl = "https://use1-1.relay.n0.iroh.link.".parse().unwrap();
        let said =
            notice(&relay, "unsupported relay version: we support iroh-relay-v3 but you only provide iroh-relay-v2");
        for part in [
            "use1-1.relay.n0.iroh.link refuses",
            &format!("iroh {IROH}"),
            "iroh-relay-v2",
            "we support iroh-relay-v3",
            "podssh update",
            "--iroh-relay URL",
        ] {
            assert!(said.contains(part), "{part}: {said}");
        }
    }

    #[test]
    fn only_a_refusal_of_the_version_is_one() {
        assert!(names_the_version(
            "invalid header value for sec-websocket-protocol: unsupported relay version: we support iroh-relay-v2 \
             but you only provide iroh-relay-v0"
        ));
        for other in ["missing header: upgrade", "Bad Request", "unsupported websocket version, only supporting 13"] {
            assert!(!names_the_version(other), "{other}");
        }
    }

    /// The version that the notice names is the one that the lock builds.
    #[test]
    fn the_named_iroh_is_the_locked_one() {
        let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")).unwrap();
        let locked = lock
            .split("[[package]]")
            .find(|p| p.contains("\nname = \"iroh\"\n"))
            .and_then(|p| p.lines().find_map(|l| l.strip_prefix("version = \"")))
            .and_then(|v| v.strip_suffix('"'))
            .expect("iroh in the lock");
        assert_eq!(IROH, locked, "the notice would name another iroh than the one built");
    }
}
