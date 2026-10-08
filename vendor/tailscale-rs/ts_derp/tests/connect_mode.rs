//! Increment 1 (E39): the DERP dial mode is explicit, and TCP by default.
//!
//! `ConnectMode` selects how `DefaultClient::connect` reaches the region:
//! TCP + `Upgrade: DERP` (upstream behavior) or DERP over WebSocket (the only
//! mode that crosses an HTTP/443-only egress). The default is TCP, so a
//! runtime that names no mode dials exactly as before — this test pins that,
//! and the server-selection tests pin which server the WebSocket arm may take:
//! hostname-addressed, not stun-only, no self-signed cert (unsupported, the
//! same rule as the TCP path in `dial.rs`).

use ts_derp::{ConnectMode, ServerConnInfo, TlsValidationConfig};

fn server(host: &str) -> ServerConnInfo {
    ServerConnInfo::default_from_url(
        &url::Url::parse(&format!("https://{host}")).unwrap(),
    )
    .unwrap()
}

/// ⛔ **The default is the old behavior.** A runtime that names no mode must
/// dial TCP + `Upgrade: DERP`, exactly as before this increment.
#[test]
fn the_default_mode_is_tcp() {
    assert_eq!(ConnectMode::default(), ConnectMode::TcpUpgrade);
}

/// The WebSocket arm dials the first server that can carry it.
#[test]
fn ws_target_is_the_first_dialable_server() {
    let servers = vec![server("derp1.example"), server("derp2.example")];
    let target = ts_derp::ws_target(&servers).unwrap();
    assert_eq!(target.hostname, "derp1.example");
    assert_eq!(target.https_port, 443);
}

/// `stun_only` servers carry no DERP traffic and are skipped.
#[test]
fn ws_target_skips_stun_only_servers() {
    let stun = ServerConnInfo { stun_only: true, ..server("stun.example") };
    let servers = vec![stun, server("derp.example")];
    let target = ts_derp::ws_target(&servers).unwrap();
    assert_eq!(target.hostname, "derp.example");
}

/// Self-signed certs are unsupported (same rule as the TCP path): skipped,
// and `None` when nothing is dialable.
#[test]
fn ws_target_skips_self_signed_and_reports_nothing_dialable() {
    let signed = ServerConnInfo {
        tls_validation_config: TlsValidationConfig::SelfSigned { sha256: [0u8; 64] },
        ..server("selfsigned.example")
    };
    let stun = ServerConnInfo { stun_only: true, ..server("stun.example") };
    assert!(ts_derp::ws_target(&[signed, stun]).is_none());
    assert!(ts_derp::ws_target(&[]).is_none());
}
