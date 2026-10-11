//! `GET /health` on one relay host (T-058), over the same proxy-aware,
//! verified path as a session: the relay's version, the edge that answered,
//! and how the connection went. `podssh doctor` and `podssh relay status`
//! read a host the same way, and so can podbox.

use std::time::{Duration, Instant};

use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::{http, Trust};

use crate::relay::Relay;

/// The service name that the relay gives in `/health`: with a certificate
/// verified for the host, this is how the relay is identified.
pub const SERVICE: &str = "tcp-ssh-relay";
/// The largest `/health` body read.
const MAX_BODY: usize = 64 * 1024;

/// What one host's `/health` said, and how it was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    /// The relay's version, in one line.
    pub version: Option<String>,
    /// The Cloudflare edge that answered.
    pub edge: Option<String>,
    /// The relay says that it is paused.
    pub paused: bool,
    /// Whether the reverse road is on, when the relay says.
    pub reverse: Option<bool>,
    /// The time of the whole request, the connection included.
    pub took: Duration,
    /// The TLS version, as `TLS 1.3`.
    pub tls: String,
    /// `TCP ADDRESS`, or `CONNECT HOST:PORT through PROXY`: a reader can
    /// then tell a proxy's answer from the relay's.
    pub opened: String,
    /// The relay's `Date` header, for a check of this host's clock.
    pub date: Option<String>,
}

impl Health {
    /// `HOST: tcp-ssh-relay VERSION at edge COLO, N ms; TLS 1.3, certificate
    /// verified for HOST; opened ...`, with the pause and a reverse road
    /// that is off when the relay says so.
    pub fn line(&self, host: &str) -> String {
        let version = self.version.as_deref().unwrap_or("(no version)");
        let edge = self.edge.as_deref().map(|c| format!(" at edge {c}")).unwrap_or_default();
        let mut line = format!(
            "{host}: {SERVICE} {version}{edge}, {} ms; {}, certificate verified for {host}; opened {}",
            self.took.as_millis(),
            self.tls,
            self.opened
        );
        if self.paused {
            line.push_str("; the relay says that it is paused");
        }
        if self.reverse == Some(false) {
            line.push_str("; its reverse road is off");
        }
        line
    }
}

/// Why a host's `/health` gave no [`Health`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthError {
    /// TCP, the proxy or TLS failed: the error's text.
    Connect(String),
    /// The connection was made (`opened`), and then the answer did not come
    /// in time, broke, had another status, held no JSON, or named another
    /// service.
    Answer { opened: String, why: String },
}

impl std::fmt::Display for HealthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthError::Connect(text) => f.write_str(text),
            HealthError::Answer { opened, why } => write!(f, "{why} (opened {opened})"),
        }
    }
}

/// `GET /health` on `relay`, each wait within `timeout`.
pub async fn fetch(
    relay: &Relay,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<Health, HealthError> {
    let host = &relay.host;
    let started = Instant::now();
    let mut tls = podssh_ws::client::open_tls(host, relay.port, host, trust, proxy, timeout)
        .await
        .map_err(|e| HealthError::Connect(e.to_string()))?;
    let (tcp, connection) = tls.get_ref();
    let peer = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_else(|e| format!("an address it cannot name ({e})"));
    let tls_version = connection
        .protocol_version()
        .map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1."))
        .unwrap_or_else(|| "TLS".into());
    let through = match proxy {
        ProxyChoice::FromEnvironment => dial::proxy_from_env(host).ok().flatten(),
        ProxyChoice::Via(proxy) => Some(proxy.clone()),
        ProxyChoice::Direct => None,
    };
    let opened = match through {
        Some(proxy) => {
            let request = proxy.kind.request();
            format!("{request} {} through {}", dial::authority(host, relay.port), proxy_reached(&proxy, &peer))
        }
        None => format!("TCP {peer}"),
    };
    let answer = |why: String| HealthError::Answer { opened: opened.clone(), why };
    let host_header = if relay.port == 443 { host.clone() } else { dial::authority(host, relay.port) };
    let exchange =
        http::exchange(&mut tls, "GET", &host_header, "/health", &[("Accept", "application/json")], b"", MAX_BODY);
    let response = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| answer(format!("/health did not answer within {} s", timeout.as_secs())))?
        .map_err(|e| answer(format!("/health: {e}")))?;
    if response.status != 200 {
        return Err(answer(format!("/health answered HTTP {} {}", response.status, response.body_text(120))));
    }
    let doc: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| answer("/health did not answer with JSON".into()))?;
    let text = |v: &serde_json::Value| v.as_str().map(podssh_ws::text::one_line);
    let service = text(&doc["service"]).unwrap_or_default();
    if service != SERVICE {
        return Err(answer(format!(
            "/health names the service {service:?}, not {SERVICE:?}, so this is not the relay"
        )));
    }
    Ok(Health {
        version: text(&doc["version"]),
        edge: text(&doc["relay"]["edge_colo"]),
        paused: doc["paused"].as_bool().unwrap_or(false),
        reverse: doc["reverse"]["enabled"].as_bool(),
        took: started.elapsed(),
        tls: tls_version,
        opened,
        date: response.header("date").map(str::to_string),
    })
}

/// The proxy as named, and the address reached when it differs.
fn proxy_reached(proxy: &dial::HttpProxy, peer: &str) -> String {
    let named = proxy.to_string();
    if named == peer {
        named
    } else {
        format!("{named} ({peer})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health() -> Health {
        Health {
            version: Some("2026-10-03-r2".into()),
            edge: Some("KTM".into()),
            paused: false,
            reverse: Some(true),
            took: Duration::from_millis(55),
            tls: "TLS 1.3".into(),
            opened: "TCP 192.0.2.1:443".into(),
            date: None,
        }
    }

    #[test]
    fn a_line_names_the_version_the_edge_and_the_path() {
        assert_eq!(
            health().line("relay.example"),
            "relay.example: tcp-ssh-relay 2026-10-03-r2 at edge KTM, 55 ms; TLS 1.3, certificate verified for \
             relay.example; opened TCP 192.0.2.1:443"
        );
    }

    #[test]
    fn a_line_says_when_the_relay_is_paused_or_its_reverse_road_is_off() {
        let quiet = Health { paused: true, reverse: Some(false), version: None, edge: None, ..health() };
        let line = quiet.line("relay.example");
        assert!(line.starts_with("relay.example: tcp-ssh-relay (no version), 55 ms;"), "{line}");
        assert!(line.ends_with("; the relay says that it is paused; its reverse road is off"), "{line}");
    }
}
