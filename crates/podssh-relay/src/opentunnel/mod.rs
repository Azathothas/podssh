//! The OpenTunnel road (T-530): a carrier of the reverse road through
//! OpenTunnel, `opentunnel.xyz`, a blind TLS tunnel with no account (the
//! operator's ruling Q76 lets podssh try it unasked; its terms and limits
//! are in docs/carriers.md). A node makes a tunnel once, `<id>.opentunnel.xyz`
//! and a bearer token ([`api`]), with a P-256 key and a CSR that the binary
//! makes ([`record::Credentials`]), so that the service gets the certificate
//! and never the key; it keeps the tunnel in a private file before the bind
//! ([`record`], [`provision`]), so that each start keeps it and binds no new
//! CSR. The node keeps a bridge, one WebSocket with the subprotocol
//! `opentunnel` through `HTTPS_PROXY` ([`bridge`], [`wire`]); the service
//! sends each visitor's connection over it, still encrypted, from its
//! ClientHello on ([`conn`]), and the node ends TLS with its own key
//! ([`far`]). A client's leg is TLS by name to `ROUTE.<id>.opentunnel.xyz`
//! on port 443, with no upgrade, checked against the public roots as each
//! name is ([`client`]): it passes a proxy that refuses the WebSocket upgrade.
//!
//! Each session over a visitor's connection runs the resumable layer and,
//! above the layer, the end-to-end channel (`crate::e2e`), so the service
//! is trusted for availability only: it reads the SNI, the times and the
//! sizes, never the plaintext. A tunnel's name is in the logs of Certificate
//! Transparency, so the node's route is a random label of its own, which
//! the wildcard keeps out of them; the channel's allowlist is still the
//! door. Pure Rust, as this crate must be: TLS is podssh-ws's, with its own
//! provider, on both sides.

pub mod api;
pub mod bridge;
pub mod client;
pub mod conn;
pub mod dial;
pub mod far;
pub mod provision;
pub mod record;
pub mod retry;
pub mod wire;

use std::sync::Arc;

pub use client::{carry, Dialer, Name};
pub use far::Node;
pub use record::{Credentials, Record, Store};

/// The hosted service, whose API and bridges are at its own name and whose
/// tunnels are names under it: the endpoint `api` of `opentunnel`
/// (`pod-services`).
fn hosted_api() -> &'static pod_services::Endpoint {
    let service = pod_services::get("opentunnel").expect("pod-services holds the service opentunnel");
    service.endpoint("api").expect("opentunnel of pod-services has the endpoint api")
}

/// The URL of the hosted service's API.
pub fn default_api() -> String {
    hosted_api().url()
}
/// `no` turns the road off; an `https://` URL names another service.
pub const ENV: &str = "PODSSH_OPENTUNNEL";
/// The port of the API and of each tunnel's name, where a URL names none.
pub const PORT: u16 = 443;

/// Where the lines of the road go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// An OpenTunnel service: the host and the port of its API, whose tunnels
/// the API names under a domain of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub port: u16,
}

impl Service {
    /// `https://HOST[:PORT][/]`, no path, no query, no user: a URL that holds
    /// more is refused, and the refusal does not echo it, as a query may
    /// hold a secret.
    pub fn parse(text: &str) -> Result<Service, String> {
        let text = text.trim();
        let rest = match text.get(..8) {
            Some(scheme) if scheme.eq_ignore_ascii_case("https://") => &text[8..],
            _ => return Err("an OpenTunnel service is an https:// URL".into()),
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty() || rest.contains(['/', '?', '#', '@']) || rest.chars().any(|c| c.is_whitespace()) {
            return Err("an OpenTunnel service is https://HOST[:PORT], with no path, query or user".into());
        }
        let port_of = |text: &str| -> Result<u16, String> {
            let port = text.parse::<u16>().ok().filter(|p| *p != 0);
            port.ok_or_else(|| "the service's port is not a number from 1 to 65535".to_string())
        };
        // An IPv6 address in brackets, whose colons are not the port's.
        let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
            let (host, after) = inner.split_once(']').ok_or("an IPv6 address of the service has no closing ]")?;
            match after.strip_prefix(':') {
                Some(port) => (host, port_of(port)?),
                None if after.is_empty() => (host, PORT),
                None => return Err("the service's address is not [IPv6]:PORT".into()),
            }
        } else {
            match rest.rsplit_once(':') {
                Some((host, port)) => (host, port_of(port)?),
                None => (rest, PORT),
            }
        };
        if host.is_empty() {
            return Err("an OpenTunnel service names no host".into());
        }
        Ok(Service { host: host.to_ascii_lowercase(), port })
    }

    /// OpenTunnel's own service, at `opentunnel.xyz`.
    pub fn hosted() -> Service {
        Service { host: hosted_api().host().to_string(), port: hosted_api().port() }
    }

    /// The value of a request's `Host`: the host alone on port 443.
    pub fn authority(&self) -> String {
        if self.port == PORT {
            self.host.clone()
        } else {
            podssh_ws::dial::authority(&self.host, self.port)
        }
    }

    /// The service as a line names it.
    pub fn shown(&self) -> String {
        format!("https://{}", self.authority())
    }
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.shown())
    }
}

/// What [`ENV`] asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No OpenTunnel road.
    Off,
    /// The road, through this service.
    On(Service),
}

/// [`ENV`]'s value: unset, empty or yes, OpenTunnel's own service; no, none;
/// an `https://` URL, that service. Another word is refused, without its
/// text.
pub fn setting(value: Option<&str>) -> Result<Setting, String> {
    let value = value.map(str::trim).unwrap_or_default();
    match value.to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Ok(Setting::On(Service::hosted())),
        "no" | "off" | "false" | "0" => Ok(Setting::Off),
        _ => Service::parse(value).map(Setting::On).map_err(|why| format!("{ENV}: yes, no, or a service's URL: {why}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variable_turns_the_road_off_names_a_service_or_is_refused_without_its_text() {
        for on in [None, Some(""), Some(" yes "), Some("On"), Some("1")] {
            assert_eq!(setting(on), Ok(Setting::On(Service::hosted())), "{on:?}");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting(Some(off)), Ok(Setting::Off), "{off}");
        }
        let own = setting(Some("https://Tunnels.Example.test:8443/")).unwrap();
        assert_eq!(own, Setting::On(Service { host: "tunnels.example.test".into(), port: 8443 }));
        for refused in
            ["maybe?key=SECRET", "http://opentunnel.xyz", "https://opentunnel.xyz/api?SECRET", "https://u:SECRET@h"]
        {
            let why = setting(Some(refused)).unwrap_err();
            assert!(why.starts_with("PODSSH_OPENTUNNEL: ") && !why.contains("SECRET"), "{why}");
        }
    }

    #[test]
    fn the_host_header_names_a_port_only_off_443() {
        assert_eq!(Service::hosted().authority(), "opentunnel.xyz");
        assert_eq!(Service::hosted().shown(), "https://opentunnel.xyz");
        let own = Service::parse("https://127.0.0.1:8443").unwrap();
        assert_eq!(own.authority(), "127.0.0.1:8443");
        assert!(Service::parse("https://h:0").is_err() && Service::parse("https://:8443").is_err());
    }
}
