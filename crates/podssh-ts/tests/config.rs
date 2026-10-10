//! `podssh-ts` config tests: the mode mapping, and the proxy of the node:
//! the flag, else the variables that each podssh command reads (T-103).

use podssh_ts::config::{choose_proxy, ConfigError, TsMode, PROXY_FLAG};

/// The variables of a test, in place of the process's.
fn vars(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |name| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
}

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
    let sel = TsMode::Relay { host: "tcp.ts.relay.ajam.dev".to_string(), port: 443 }.runtime_selection(None);
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
    assert_eq!(TsMode::default_relay(), TsMode::Relay { host: "tcp.ts.relay.ajam.dev".to_string(), port: 443 });
}

#[test]
fn the_proxy_is_the_flag_then_each_variable_in_podsshs_order() {
    let all: &[(&str, &str)] = &[
        ("https_proxy", "http://first.example:1"),
        ("HTTPS_PROXY", "http://second.example:2"),
        ("all_proxy", "http://third.example:3"),
        ("ALL_PROXY", "http://fourth.example:4"),
        ("no_proxy", "internal.example"),
        ("NO_PROXY", "other.example"),
    ];
    // The flag wins, and a flag names one proxy for each host.
    let p = choose_proxy(Some("http://flag.example:9"), vars(all)).unwrap().unwrap();
    assert_eq!((p.url(), p.source, p.no_proxy), ("http://flag.example:9".to_string(), PROXY_FLAG, None));
    // Then the variables, in the order of podssh-ws's `PROXY_VARS`; an empty
    // one counts as unset, and the lower-case `no_proxy` comes first.
    let expect = [
        ("https_proxy", "http://first.example:1"),
        ("HTTPS_PROXY", "http://second.example:2"),
        ("all_proxy", "http://third.example:3"),
        ("ALL_PROXY", "http://fourth.example:4"),
    ];
    for skip in 0..expect.len() {
        let mut set: Vec<(&'static str, &'static str)> =
            vec![("no_proxy", "internal.example"), ("NO_PROXY", "other.example")];
        for (i, (name, value)) in expect.iter().enumerate() {
            set.push((name, if i < skip { " " } else { value }));
        }
        let set: &'static [(&'static str, &'static str)] = Box::leak(set.into_boxed_slice());
        let p = choose_proxy(None, vars(set)).unwrap().unwrap();
        assert_eq!((p.source, p.url()), (expect[skip].0, expect[skip].1.to_string()));
        assert_eq!(p.no_proxy.as_deref(), Some("internal.example"));
    }
    assert_eq!(podssh_ws::dial::PROXY_VARS, expect.map(|(name, _)| name));
    // None set: direct.
    assert_eq!(choose_proxy(None, vars(&[("NO_PROXY", "x.example")])), Ok(None));
}

#[test]
fn the_fork_gets_the_port_and_the_credentials_as_podssh_reads_them() {
    // No port: 80, as each podssh command reads it; the fork would read 8080.
    let p = choose_proxy(Some("http://proxy.example"), vars(&[])).unwrap().unwrap();
    assert_eq!(p.url(), "http://proxy.example:80");
    // A bare host:port, as podssh takes it from a variable.
    let p = choose_proxy(None, vars(&[("HTTPS_PROXY", "proxy.example:3128")])).unwrap().unwrap();
    assert_eq!(p.url(), "http://proxy.example:3128");
    // Credentials, escaped again, and shown nowhere.
    let p = choose_proxy(Some("http://us%40er:p%3Ass@proxy.example:3128"), vars(&[])).unwrap().unwrap();
    assert_eq!(p.url(), "http://us%40er:p%3Ass@proxy.example:3128");
    let shown = format!("{p:?} {}", p.proxy);
    assert!(!shown.contains("p%3Ass") && !shown.contains("p:ss") && !shown.contains("us"), "{shown}");
}

#[test]
fn a_bad_proxy_is_named_by_its_source_and_never_quoted() {
    let refused = [
        (Some("socks5://user:secret@proxy.example:1080"), &[][..], "--ts-proxy"),
        (None, &[("HTTPS_PROXY", "http://user:secret@:3128")][..], "HTTPS_PROXY"),
        (None, &[("all_proxy", "http://user:secret@proxy.example:99999")][..], "all_proxy"),
    ];
    for (flag, set, source) in refused {
        let set: &'static [(&'static str, &'static str)] = Box::leak(set.to_vec().into_boxed_slice());
        let Err(ConfigError::BadProxyUrl(why)) = choose_proxy(flag, vars(set)) else { panic!("{source}: accepted") };
        assert!(why.starts_with(&format!("{source}: ")), "{why}");
        assert!(!why.contains("secret"), "the password is quoted: {why}");
    }
}
