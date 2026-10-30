//! A relay's name pinned to loopback addresses goes with no proxy, as a
//! loopback name does: the proxy's loopback is not this host's (T-318). A
//! test binary of its own, as the pins are the process's.

use podssh_ws::dial::proxy_from_vars;
use podssh_ws::resolve::set_pins;

#[test]
fn a_name_pinned_to_loopback_alone_goes_with_no_proxy() {
    let proxy = |name: &str| (name == "https_proxy").then(|| "http://proxy.example:3128".to_string());
    set_pins(vec![
        ("relay-a.test".into(), "127.0.0.1".parse().unwrap()),
        ("relay-b.test".into(), "203.0.113.5".parse().unwrap()),
        ("relay-c.test".into(), "::1".parse().unwrap()),
        ("relay-c.test".into(), "127.0.0.2".parse().unwrap()),
        ("relay-d.test".into(), "127.0.0.1".parse().unwrap()),
        ("relay-d.test".into(), "203.0.113.5".parse().unwrap()),
    ]);
    assert_eq!(proxy_from_vars("relay-a.test", proxy).unwrap(), None, "pinned to 127.0.0.1");
    assert_eq!(proxy_from_vars("RELAY-C.test.", proxy).unwrap(), None, "pinned to ::1 and 127.0.0.2");
    let kept = |host: &str| proxy_from_vars(host, proxy).unwrap().map(|p| p.host);
    assert_eq!(kept("relay-b.test").as_deref(), Some("proxy.example"), "a pin to another address");
    assert_eq!(kept("relay-d.test").as_deref(), Some("proxy.example"), "one pin not on loopback");
    assert_eq!(kept("relay-e.test").as_deref(), Some("proxy.example"), "no pin");
    set_pins(Vec::new());
}
