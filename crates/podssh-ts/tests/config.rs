//! `podssh-ts` config tests: the mode mapping and URL parsing.

use podssh_ts::config::{ConfigError, TsMode, parse_proxy_url};

#[test]
fn tcp_keeps_udp_and_the_netmap() {
    let sel = TsMode::Tcp.runtime_selection(None);
    assert!(!sel.no_udp);
    assert!(!sel.derp_ws);
    assert_eq!(sel.derp_host, None);
    assert_eq!(sel.derp_port, None);
    assert_eq!(sel.proxy_url, None);
}

#[test]
fn relay_gates_udp_selects_ws_and_pins() {
    let sel = TsMode::Relay { host: "tcp.ts.relay.ajam.dev".to_string(), port: 443 }
        .runtime_selection(None);
    assert!(sel.no_udp);
    assert!(sel.derp_ws);
    assert_eq!(sel.derp_host.as_deref(), Some("tcp.ts.relay.ajam.dev"));
    assert_eq!(sel.derp_port, Some(443));
    assert_eq!(sel.proxy_url, None);
}

#[test]
fn proxy_url_rides_both_modes() {
    let tcp = TsMode::Tcp.runtime_selection(Some("http://127.0.0.1:3128"));
    assert_eq!(tcp.proxy_url.as_deref(), Some("http://127.0.0.1:3128"));
    assert!(!tcp.no_udp);
    let relay = TsMode::default_relay().runtime_selection(Some("http://127.0.0.1:3128"));
    assert!(relay.no_udp);
    assert_eq!(relay.proxy_url.as_deref(), Some("http://127.0.0.1:3128"));
}

#[test]
fn default_relay_is_the_sibling_worker() {
    assert_eq!(
        TsMode::default_relay(),
        TsMode::Relay { host: "tcp.ts.relay.ajam.dev".to_string(), port: 443 }
    );
}

#[test]
fn proxy_urls_parse_and_bad_ones_are_named() {
    assert_eq!(
        parse_proxy_url("http://127.0.0.1:3128"),
        Ok("http://127.0.0.1:3128".to_string())
    );
    assert_eq!(
        parse_proxy_url("http://proxy.example"),
        Ok("http://proxy.example:8080".to_string())
    );
    assert_eq!(
        parse_proxy_url("http://user:pass@proxy.example:3128"),
        Ok("http://user:pass@proxy.example:3128".to_string())
    );
    assert!(matches!(
        parse_proxy_url("socks5://proxy.example:1080"),
        Err(ConfigError::BadProxyUrl(_))
    ));
    assert!(matches!(
        parse_proxy_url("not a url"),
        Err(ConfigError::BadProxyUrl(_))
    ));
    assert!(matches!(
        parse_proxy_url("http://:3128"),
        Err(ConfigError::BadProxyUrl(_))
    ));
}
