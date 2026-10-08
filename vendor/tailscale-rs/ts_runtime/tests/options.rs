//! Increment 3 (E39): DERP-only runtime options, off by default.
//!
//! `RuntimeOptions::default()` is stock behavior — UDP actors spawn, TCP
//! dial, no proxy, no pin — so a device that names no options runs exactly
//! as before. Every deviation is selected, never assumed, and the pure
//! selections below are pinned here so the actor wiring cannot drift from
//! them unwitnessed.

use ts_runtime::options::{DerpOptions, RuntimeOptions};

/// ⛔ **The default is the old behavior.** Anything else would turn every
/// existing device DERP-only by upgrade.
#[test]
fn defaults_are_stock_behavior() {
    let options = RuntimeOptions::default();
    assert!(!options.no_udp);
    assert!(!options.derp.ws);
    assert_eq!(options.derp.override_host, None);
    assert_eq!(options.derp.override_port, None);
    assert_eq!(options.proxy, None);
}

/// `ws` selects the WebSocket DERP transport; unset selects TCP.
#[test]
fn ws_selects_the_websocket_mode() {
    use ts_derp::ConnectMode;
    assert_eq!(RuntimeOptions::default().derp_mode(), ConnectMode::TcpUpgrade);
    let ws = RuntimeOptions {
        derp: DerpOptions { ws: true, ..Default::default() },
        ..Default::default()
    };
    assert_eq!(ws.derp_mode(), ConnectMode::WebSocket);
}

/// The pin splits host and port, defaulting the port to 443.
#[test]
fn the_pin_splits_host_and_port() {
    let options = RuntimeOptions::default();
    assert_eq!(options.derp_pin(), None);

    let pinned = RuntimeOptions {
        derp: DerpOptions {
            override_host: Some("tcp.ts.relay.ajam.dev".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(pinned.derp_pin(), Some(("tcp.ts.relay.ajam.dev".to_string(), 443)));

    let pinned_port = RuntimeOptions {
        derp: DerpOptions {
            override_host: Some("relay.example".to_string()),
            override_port: Some(8443),
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(pinned_port.derp_pin(), Some(("relay.example".to_string(), 8443)));
}

/// The environment carries the options to every actor that branches on them.
#[tokio::test]
async fn the_env_carries_the_options() {
    let keys = ts_keys::NodeState::generate();
    let options = RuntimeOptions {
        no_udp: true,
        ..Default::default()
    };
    let env = ts_runtime::env::Env::new(keys, options);
    assert!(env.options.no_udp);
    assert!(!env.options.derp.ws);
}

/// Applying the options feeds the proxy dialer: configured while set,
// cleared afterwards, so no test leaks a proxy into its neighbour.
#[test]
fn applying_options_feeds_the_proxy_dialer() {
    use ts_http_util::proxy::{configure, is_configured, ProxyConfig};
    let options = RuntimeOptions {
        proxy: Some(
            ProxyConfig::from_url("http://127.0.0.1:3128").unwrap(),
        ),
        ..Default::default()
    };
    options.apply_proxy();
    assert!(is_configured());
    configure(None);
    assert!(!is_configured());
}
