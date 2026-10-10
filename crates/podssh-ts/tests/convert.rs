//! Conversion tests: the owned selection becomes fork options field-for-field.
//!
//! The proxy URL parses via the fork's own `ProxyConfig::from_url`, so the
//! dialer and this validator never disagree on what a URL means — and the
//! bad-URL test below pins that by feeding the fork's own refusals back.

use podssh_ts::config::{ConfigError, RuntimeSelection, TsMode};
use podssh_ts::node::selection_to_options;

fn relay() -> RuntimeSelection {
    TsMode::Relay { host: "tcp.ts.relay.ajam.dev".to_string(), port: 443 }.runtime_selection(None)
}

#[test]
fn relay_selection_converts_field_for_field() {
    let opts = selection_to_options(&relay()).unwrap();
    assert!(opts.no_udp);
    assert!(opts.derp.ws);
    assert_eq!(opts.derp.override_host.as_deref(), Some("tcp.ts.relay.ajam.dev"));
    assert_eq!(opts.derp.override_port, Some(443));
    assert!(opts.proxy.is_none());
}

#[test]
fn tcp_selection_converts_to_all_stock() {
    let opts = selection_to_options(&TsMode::Tcp.runtime_selection(None)).unwrap();
    assert!(!opts.no_udp);
    assert!(!opts.derp.ws);
    assert_eq!(opts.derp.override_host, None);
    assert_eq!(opts.derp.override_port, None);
    assert!(opts.proxy.is_none());
}

#[test]
fn a_proxy_url_rides_along_when_present() {
    let sel = TsMode::Tcp.runtime_selection(Some("http://127.0.0.1:3128"));
    let opts = selection_to_options(&sel).unwrap();
    assert!(opts.proxy.is_some());
}

#[test]
fn a_bad_proxy_url_is_named_not_swallowed() {
    let sel = RuntimeSelection {
        no_udp: true,
        derp_ws: true,
        derp_host: Some("tcp.ts.relay.ajam.dev".to_string()),
        derp_port: Some(443),
        proxy_url: Some("socks5://user:secret@proxy.example:1080".to_string()),
        no_proxy: None,
        retry_refused: false,
    };
    let Err(ConfigError::BadProxyUrl(why)) = selection_to_options(&sel) else { panic!("accepted") };
    // The fork's refusal says why, and quotes no URL (patch 0017).
    assert!(why.contains("socks5"), "{why}");
    assert!(!why.contains("secret"), "the password is quoted: {why}");
}

#[test]
fn the_no_proxy_list_rides_into_the_forks_proxy() {
    let mut sel = TsMode::default_relay().runtime_selection(Some("http://127.0.0.1:3128"));
    sel.no_proxy = Some("internal.example, .corp.example".to_string());
    let proxy = selection_to_options(&sel).unwrap().proxy.expect("a proxy");
    assert!(proxy.bypasses("internal.example") && proxy.bypasses("a.corp.example"));
    assert!(!proxy.bypasses("tcp.ts.relay.ajam.dev"));
    // Its Debug shows no credentials (patch 0017).
    let sel = TsMode::Tcp.runtime_selection(Some("http://user:secret@127.0.0.1:3128"));
    let shown = format!("{:?} {sel:?}", selection_to_options(&sel).unwrap().proxy);
    assert!(!shown.contains("secret") && !shown.contains("dXNlcjpzZWNyZXQ"), "{shown}");
}
