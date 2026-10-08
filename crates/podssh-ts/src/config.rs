//! `TsConfig`: everything `TsNode` needs, and the mapping to fork selections.
//!
//! ⛔ This module never names fork types. `podssh-ts` owns `RuntimeSelection`
//! and `node.rs` converts it at the boundary in 4b, so no fork-version
//! coupling leaks into these signatures.

use std::path::PathBuf;

/// Which tailnet route this node uses. 4a carries `Tcp` and `Relay`; `Tun`
/// and `Socks` (an existing daemon's kernel route / localhost proxy) arrive
/// with the chain selection in 4b.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TsMode {
    /// In-process netstack on the stock tailnet: TCP dial, no pin, UDP kept.
    Tcp,
    /// In-process DERP over WebSocket to the pinned relay, UDP gated off.
    Relay {
        /// Relay hostname; default `tcp.ts.relay.ajam.dev`.
        host: String,
        /// Relay port; default 443.
        port: u16,
    },
}

impl TsMode {
    /// The default relay: the sibling worker over WebSocket/443.
    pub fn default_relay() -> Self {
        TsMode::Relay { host: "tcp.ts.relay.ajam.dev".to_string(), port: 443 }
    }

    /// The fork runtime selection this mode implies. `Tcp` keeps UDP and the
    /// netmap's DERP map; `Relay` gates UDP off, selects WS, and pins the relay.
    pub fn runtime_selection(&self, proxy_url: Option<&str>) -> RuntimeSelection {
        match self {
            TsMode::Tcp => RuntimeSelection {
                no_udp: false,
                derp_ws: false,
                derp_host: None,
                derp_port: None,
                proxy_url: proxy_url.map(str::to_string),
            },
            TsMode::Relay { host, port } => RuntimeSelection {
                no_udp: true,
                derp_ws: true,
                derp_host: Some(host.clone()),
                derp_port: Some(*port),
                proxy_url: proxy_url.map(str::to_string),
            },
        }
    }
}

/// The fork runtime selection, field for field, without naming fork types:
/// `podssh-ts` owns this struct and `node.rs` converts it at the boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSelection {
    /// Gate the UDP actors off (DirectActor, Stunner, netmon).
    pub no_udp: bool,
    /// Dial DERP over WebSocket instead of TCP + `Upgrade: DERP`.
    pub derp_ws: bool,
    /// Pin the DERP transport to this host, or `None` for the netmap's map.
    pub derp_host: Option<String>,
    /// Pin port; meaningful only with `derp_host`.
    pub derp_port: Option<u16>,
    /// CONNECT proxy URL for every outbound TCP path, or `None` for direct.
    pub proxy_url: Option<String>,
}

/// Everything `TsNode` needs: state path, control plane, identity, mode.
#[derive(Clone, Debug)]
pub struct TsConfig {
    /// Node key-state file. No default: podssh picks one (E23), and the file
    /// must persist or the node key — and its allowlist entry — rotates.
    pub state_file: PathBuf,
    /// Control plane URL, or `None` for the fork's compiled default.
    pub control_url: Option<String>,
    /// Hostname to request, or `None` for the fork's default.
    pub hostname: Option<String>,
    /// Register an ephemeral node instead of a remembered one.
    pub ephemeral: bool,
    /// The tailnet route.
    pub mode: TsMode,
    /// CONNECT proxy URL, or `None` for direct.
    pub proxy_url: Option<String>,
}

/// Why a `TsConfig` cannot become a fork `Config`.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The proxy URL does not parse as an `http://` URL with a host.
    BadProxyUrl(String),
    /// The control URL does not parse as a URL.
    BadControlUrl(String),
}

/// Check a CONNECT proxy URL the way the fork's dialer needs it:
/// `http://host[:port]`, default port 8080, credentials allowed.
/// Anything else is a named `BadProxyUrl`, before anything dials.
pub fn parse_proxy_url(url: &str) -> Result<String, ConfigError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| ConfigError::BadProxyUrl(url.to_string()))?;
    let (authority, _) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (&authority[..i], &authority[i + 1..]),
        None => ("", authority),
    };
    if hostport.is_empty() || hostport.starts_with(':') {
        return Err(ConfigError::BadProxyUrl(url.to_string()));
    }
    let (host, port) = match hostport.rfind(':') {
        Some(i) if !hostport[..i].is_empty() && hostport[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
            let port: u16 =
                hostport[i + 1..].parse().map_err(|_| ConfigError::BadProxyUrl(url.to_string()))?;
            (&hostport[..i], port)
        }
        _ => (hostport, 8080),
    };
    if host.is_empty() {
        return Err(ConfigError::BadProxyUrl(url.to_string()));
    }
    if userinfo.is_empty() {
        Ok(format!("http://{host}:{port}"))
    } else {
        Ok(format!("http://{userinfo}@{host}:{port}"))
    }
}
