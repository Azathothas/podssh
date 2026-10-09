//! `TsNode`: the fork `Device` behind podssh's config, secret, and errors.
//!
//! The boundary rule: `TsConfig`/`RuntimeSelection` in, fork types out, and
//! the conversion is pure (`selection_to_options`, plant-fired in
//! `tests/convert.rs`). `start` itself needs the control plane and, for
//! `Relay` mode, the relay's allowlist — so it is live-tested (M5), not
//! unit-tested.

use std::net::SocketAddr;
use std::time::Duration;

use crate::config::{ConfigError, TsConfig};
use crate::status::StatusFacts;

/// Convert the owned selection to fork types at the boundary. The proxy URL
/// parses via the fork's own `ProxyConfig::from_url`, so the dialer and this
/// validator never disagree on what a URL means.
pub fn selection_to_options(
    sel: &crate::config::RuntimeSelection,
) -> Result<ts_runtime::options::RuntimeOptions, ConfigError> {
    Ok(ts_runtime::options::RuntimeOptions {
        no_udp: sel.no_udp,
        derp: ts_runtime::options::DerpOptions {
            ws: sel.derp_ws,
            override_host: sel.derp_host.clone(),
            override_port: sel.derp_port,
        },
        proxy: match &sel.proxy_url {
            None => None,
            Some(u) => {
                Some(ts_http_util::proxy::ProxyConfig::from_url(u).map_err(|_| ConfigError::BadProxyUrl(u.clone()))?)
            }
        },
    })
}

/// A tailnet node: fork `Device` plus the state file it persists to.
///
/// `dead_code` on `state_file`: it is retained for reconnect/identity
/// proof and has no reader yet; the field is the reason the struct can grow
/// one without changing construction.
#[allow(dead_code)]
pub struct TsNode {
    device: tailscale::Device,
    state_file: std::path::PathBuf,
}

impl TsNode {
    /// Read (or create) the key state at `cfg.state_file`, build the fork
    /// `Config` with the mode's runtime options, and register. Needs the
    /// control plane and, for `Relay` mode, the relay's allowlist — M5 is
    /// the proof, not a unit test.
    pub async fn start(cfg: &TsConfig, key: &crate::secret::AuthKey) -> Result<Self, NodeError> {
        let raw = key.expose().map_err(|_| NodeError::KeyExpired)?;
        let auth = String::from_utf8(raw.to_vec()).map_err(|_| NodeError::KeyNotUtf8)?;
        let mut fork_cfg = tailscale::Config::default_with_key_file(&cfg.state_file)
            .await
            .map_err(|e| NodeError::Fork(e.to_string()))?;
        if let Some(url) = &cfg.control_url {
            fork_cfg.control_server_url =
                url.parse().map_err(|_| NodeError::Config(ConfigError::BadControlUrl(url.clone())))?;
        }
        fork_cfg.requested_hostname = cfg.hostname.clone();
        fork_cfg.ephemeral = cfg.ephemeral;
        fork_cfg.options =
            selection_to_options(&cfg.mode.runtime_selection(cfg.proxy_url.as_deref())).map_err(NodeError::Config)?;
        let device = tailscale::Device::new(&fork_cfg, Some(auth)).await.map_err(|e| NodeError::Fork(e.to_string()))?;
        Ok(Self { device, state_file: cfg.state_file.clone() })
    }

    /// One machine-readable status: node-key prefix, tailnet IP, home region.
    /// The home region comes from the netmap (`derp_region`); until the
    /// netmap arrives there is no region to report and this returns
    /// `NetmapPending` — the caller retries under `--ts-wait-allowlist` or
    /// fails fast. A region is never invented.
    pub async fn status(&self) -> Result<StatusFacts, NodeError> {
        let node = self.device.self_node().await.map_err(|e| NodeError::Fork(e.to_string()))?;
        let ip = self.device.ipv4_addr().await.map_err(|e| NodeError::Fork(e.to_string()))?;
        let region = node.derp_region.map(|r| r.0.get() as u16).ok_or(NodeError::NetmapPending)?;
        let shown = node.node_key.to_string();
        let hex: String = shown.strip_prefix("nodekey:").unwrap_or(&shown).chars().take(8).collect();
        Ok(StatusFacts { nodekey_prefix: hex, tailnet_ip: ip.to_string(), home_region: region })
    }

    /// Open a TCP stream to a tailnet peer through the in-process netstack.
    pub async fn tcp_connect(&self, remote: SocketAddr) -> Result<tailscale::netstack::TcpStream, NodeError> {
        self.device.tcp_connect(remote).await.map_err(|e| NodeError::Fork(e.to_string()))
    }

    /// Resolve a peer name to its tailnet IPv4 via the netmap. `None` means
    /// the netmap has no such peer — a route error for the caller, never a
    /// dial attempt and never a hang.
    pub async fn peer_ip(&self, name: &str) -> Result<Option<std::net::IpAddr>, NodeError> {
        let peer = self.device.peer_by_name(name).await.map_err(|e| NodeError::Fork(e.to_string()))?;
        Ok(peer.map(|p| std::net::IpAddr::V4(p.tailnet_address.ipv4.addr())))
    }

    /// Shut the node down, waiting up to `timeout` for a clean stop.
    pub async fn shutdown(self, timeout: Option<Duration>) -> bool {
        self.device.shutdown(timeout).await
    }
}

/// Why a node failed to come up. Wire strings (`1008` reasons) classify in
/// `classify.rs`, not here.
#[derive(Debug)]
pub enum NodeError {
    /// The config cannot become a fork `Config`.
    Config(ConfigError),
    /// The fork refused the operation.
    Fork(String),
    /// The auth key was expired before use.
    KeyExpired,
    /// The auth key bytes are not UTF-8.
    KeyNotUtf8,
    /// The netmap has not arrived yet: no home region to report. The caller
    /// retries under `--ts-wait-allowlist` or fails fast — never invents one.
    NetmapPending,
    /// 4a scaffold remnant, kept until M5 proves `start` live: no caller
    /// constructs it, and removing it is part of the M5 landing.
    NotYet(&'static str),
}
