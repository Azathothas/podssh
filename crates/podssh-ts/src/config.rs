//! `TsConfig`: everything `TsNode` needs, and the mapping to fork selections.
//!
//! This module never names fork types. `podssh-ts` owns `RuntimeSelection`
//! and `node.rs` converts it at the boundary, so no fork-version
//! coupling leaks into these signatures.

use std::path::PathBuf;

/// Which tailnet route this node uses: `Tcp` or `Relay`. `Tun` and `Socks`
/// (an existing daemon's kernel route / localhost proxy) would come with a
/// selection of the chain, which is not built.
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
                no_proxy: None,
                retry_refused: false,
            },
            TsMode::Relay { host, port } => RuntimeSelection {
                no_udp: true,
                derp_ws: true,
                derp_host: Some(host.clone()),
                derp_port: Some(*port),
                proxy_url: proxy_url.map(str::to_string),
                no_proxy: None,
                retry_refused: false,
            },
        }
    }
}

/// The fork runtime selection, field for field, without naming fork types:
/// `podssh-ts` owns this struct and `node.rs` converts it at the boundary.
/// Its `Debug` shows no proxy credentials.
#[derive(Clone, PartialEq, Eq)]
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
    /// The hosts that bypass that proxy, as a `no_proxy` list.
    pub no_proxy: Option<String>,
    /// Dial DERP again after the relay refused this node's key (T-104): the node waits for its
    /// key's admission.
    pub retry_refused: bool,
}

impl std::fmt::Debug for RuntimeSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeSelection")
            .field("no_udp", &self.no_udp)
            .field("derp_ws", &self.derp_ws)
            .field("derp_host", &self.derp_host)
            .field("derp_port", &self.derp_port)
            .field("proxy_url", &self.proxy_url.as_deref().map(redacted))
            .field("no_proxy", &self.no_proxy)
            .field("retry_refused", &self.retry_refused)
            .finish()
    }
}

/// Everything `TsNode` needs: state path, control plane, identity, mode.
/// Its `Debug` shows no proxy credentials.
#[derive(Clone)]
pub struct TsConfig {
    /// Node key-state file. No default: the caller names one, and the file
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
    /// The hosts that bypass that proxy, as a `no_proxy` list.
    pub no_proxy: Option<String>,
    /// Dial again after a refusal of the node key, as while waiting for its admission
    /// (`--ts-wait-allowlist`, T-104).
    pub retry_refused: bool,
    /// Where the changes of the node's links go from its start on (T-104), or `None`.
    pub link_events: Option<tokio::sync::broadcast::Sender<crate::node::LinkEvent>>,
}

impl std::fmt::Debug for TsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsConfig")
            .field("state_file", &self.state_file)
            .field("control_url", &self.control_url)
            .field("hostname", &self.hostname)
            .field("ephemeral", &self.ephemeral)
            .field("mode", &self.mode)
            .field("proxy_url", &self.proxy_url.as_deref().map(redacted))
            .field("no_proxy", &self.no_proxy)
            .field("retry_refused", &self.retry_refused)
            .field("link_events", &self.link_events.is_some())
            .finish()
    }
}

/// A proxy URL with its credentials, if any, replaced.
fn redacted(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), url),
    };
    let authority = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority].rfind('@') {
        Some(at) => format!("{scheme}<redacted>@{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

/// Why a `TsConfig` cannot become a fork `Config`.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The proxy URL was refused: what named it, and why. Never the URL,
    /// which may hold a password.
    BadProxyUrl(String),
    /// The control URL does not parse as a URL.
    BadControlUrl(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::BadProxyUrl(why) => write!(f, "{why}"),
            ConfigError::BadControlUrl(url) => write!(f, "the control URL {url:?} does not parse"),
        }
    }
}

/// The proxy that each connection of the node goes through, as
/// [`choose_proxy`] found it. Its `Debug` and its `Display` show no
/// credentials (podssh-ws's `HttpProxy`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsProxy {
    /// The proxy, as each podssh command reads it.
    pub proxy: podssh_ws::HttpProxy,
    /// The `no_proxy` list, for a proxy that the environment named: a flag
    /// names one proxy for each host.
    pub no_proxy: Option<String>,
    /// What named the proxy: `--ts-proxy`, or the variable.
    pub source: &'static str,
}

impl TsProxy {
    /// The URL for the fork: `http://[USER:PASSWORD@]HOST:PORT`, the port
    /// always written, as podssh reads a URL with none (80, where the fork
    /// would read 8080), and the credentials escaped. Never for a message.
    pub fn url(&self) -> String {
        self.proxy.url()
    }
}

/// What names the proxy when `--ts-proxy` does.
pub const PROXY_FLAG: &str = "--ts-proxy";

/// The proxy of the node: `--ts-proxy` (`flag`), else the first of the
/// variables that each podssh command reads, in its order, that is set and
/// not empty, with the `no_proxy` list; `None` for direct. `var` reads a
/// variable, so a test gives its own.
pub fn choose_proxy(flag: Option<&str>, var: impl Fn(&str) -> Option<String>) -> Result<Option<TsProxy>, ConfigError> {
    let set = |name: &str| var(name).filter(|value| !value.trim().is_empty());
    let (raw, source) = match flag {
        Some(url) => (url.to_string(), PROXY_FLAG),
        None => match podssh_ws::dial::PROXY_VARS.iter().find_map(|name| set(name).map(|value| (value, *name))) {
            Some(found) => found,
            None => return Ok(None),
        },
    };
    // podssh-ws's reading, as for each other command: a bare `host:port`,
    // the port 80 for an `http://` URL with none, the credentials decoded.
    let proxy =
        podssh_ws::HttpProxy::parse(&raw).map_err(|why| ConfigError::BadProxyUrl(format!("{source}: {why}")))?;
    let no_proxy = match flag {
        Some(_) => None,
        None => podssh_ws::dial::NO_PROXY_VARS.iter().find_map(|name| set(name)),
    };
    Ok(Some(TsProxy { proxy, no_proxy, source }))
}
