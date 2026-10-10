//! Runtime options: DERP-only gating, transport selection, proxy, pin.
//!
//! ⛔ **Everything here defaults to stock behavior.** A device that names no
//! options runs UDP actors, dials TCP, configures no proxy and pins nothing —
//! exactly as before this module existed. Each deviation is selected, never
//! assumed, and [`RuntimeOptions::default`] pins that (see
//! `tests/options.rs`).
//!
//! The options travel on [`crate::env::Env`] so every actor branches on the
//! same value: `Runtime::on_start` builds the `Env` once from `Config`, and
//! `Uniderp` reads the mode and the pin from it. No second copy, no global
//! except the proxy dialer's own (which `apply_proxy` feeds explicitly).

use ts_derp::ConnectMode;

/// Which actors may spawn and how the transports dial.
#[derive(Debug, Clone, Default)]
pub struct RuntimeOptions {
    /// Skip UDP entirely: no `DirectActor`, no `Stunner`, no netmon. The
    /// sandbox has no UDP and no `/dev/net/tun`; on it these actors are a
    /// bind Gua partial failure at best and a panic at worst.
    pub no_udp: bool,
    /// DERP transport selection and the lab pin.
    pub derp: DerpOptions,
    /// CONNECT proxy for every outbound TCP path, or `None` for direct.
    /// Applied to the proxy dialer by [`RuntimeOptions::apply_proxy`].
    pub proxy: Option<ts_http_util::proxy::ProxyConfig>,
    /// When each link is dialled again after a drop (podssh's patch 0019).
    pub reconnect: crate::reconnect::Reconnect,
}

/// DERP transport selection and the lab pin.
#[derive(Debug, Clone, Default)]
pub struct DerpOptions {
    /// Dial DERP over WebSocket instead of TCP + `Upgrade: DERP`. The only
    /// mode that crosses an HTTP/443-only egress.
    pub ws: bool,
    /// Pin the DERP transport to this host (the lab relay), ignoring the
    /// region's servers for the socket. Region identity stays the netmap's.
    /// A pin implies the WebSocket transport: the pinned relay speaks WS.
    pub override_host: Option<String>,
    /// Pin port, defaulting to 443 when the host is pinned without one.
    pub override_port: Option<u16>,
}

impl RuntimeOptions {
    /// The DERP dial mode this configuration selects.
    pub fn derp_mode(&self) -> ConnectMode {
        if self.derp.ws {
            ConnectMode::WebSocket
        } else {
            ConnectMode::TcpUpgrade
        }
    }

    /// The pinned transport `(host, port)`, or `None` when unpinned.
    pub fn derp_pin(&self) -> Option<(String, u16)> {
        let host = self.derp.override_host.clone()?;
        let port = self.derp.override_port.unwrap_or(443);
        Some((host, port))
    }

    /// Feed the proxy selection to the shared CONNECT dialer. Called once at
    /// startup; `None` leaves direct dialing in place.
    pub fn apply_proxy(&self) {
        ts_http_util::proxy::configure(self.proxy.clone());
    }
}
