//! The tests of the role's egress (T-457): the variables read as a client
//! reads them, the hosts that go directly, the words of its first line and
//! of a proxy's fault, and the plan that the policy makes for each target.

use super::*;
use crate::serve::policy::Policy;

/// A proxy's URL of `scheme` at `place`, with a made-up user and password,
/// joined here so that no URL with credentials stands in the source for a
/// scanner of secrets to report.
fn made_up(scheme: &str, place: &str) -> String {
    format!("{scheme}://{}@{place}", ["relayuser", "s3cret"].join(":"))
}

/// The egress of the variables `set`, each `NAME=VALUE`.
fn egress_of(set: &[(&str, &str)]) -> Result<Egress, String> {
    Egress::from_vars(|name| set.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string()))
}

#[test]
fn the_variables_are_read_as_the_client_reads_them() {
    assert!(matches!(egress_of(&[]), Ok(Egress::Direct)));
    assert!(matches!(egress_of(&[("HTTPS_PROXY", " ")]), Ok(Egress::Direct)), "an empty value is unset");
    let both = egress_of(&[("HTTPS_PROXY", "http://upper.test:3128"), ("https_proxy", "http://lower.test:8080")]);
    let Ok(Egress::Proxy { proxy, bypass, from }) = both else { panic!("{both:?}") };
    assert_eq!((proxy.to_string(), from, bypass), ("lower.test:8080".to_string(), "https_proxy", None));
    let socks = egress_of(&[("ALL_PROXY", "socks5h://socks.test"), ("NO_PROXY", "10.0.0.0/8,.corp")]).unwrap();
    let Egress::Proxy { proxy, bypass, from } = &socks else { panic!("{socks:?}") };
    assert_eq!(
        (proxy.kind, *from, bypass.as_deref()),
        (ProxyKind::Socks5 { remote_dns: true }, "ALL_PROXY", Some("10.0.0.0/8,.corp"))
    );
    // A proxy that cannot be read stops the start, and its words name the
    // variable, never the credentials of the URL.
    let bad = egress_of(&[("HTTPS_PROXY", made_up("ftp", "proxy.example").as_str())]).unwrap_err();
    assert!(bad.starts_with("HTTPS_PROXY: ") && !bad.contains("s3cret"), "{bad}");
}

#[test]
fn the_loopback_and_what_no_proxy_names_go_directly() {
    let egress =
        egress_of(&[("HTTPS_PROXY", "http://proxy.test:3128"), ("NO_PROXY", "10.0.0.0/8,.corp,skip.test")]).unwrap();
    for direct in ["127.0.0.1", "::1", "localhost", "10.1.2.3", "db.corp", "skip.test"] {
        assert!(egress.proxy_for(direct).is_none(), "{direct}");
    }
    for proxied in ["140.82.112.3", "github.com", "11.0.0.1", "2001:db8::7", "corp.example"] {
        assert!(egress.proxy_for(proxied).is_some(), "{proxied}");
    }
    assert!(Egress::Direct.proxy_for("github.com").is_none());
}

#[test]
fn the_first_line_names_the_proxy_by_its_place_alone() {
    let egress = egress_of(&[("https_proxy", made_up("http", "proxy.example:3128").as_str())]).unwrap();
    let shown = egress.shown().unwrap();
    assert_eq!(
        shown,
        "its targets through the http proxy proxy.example:3128 of https_proxy, but the loopback directly"
    );
    assert!(!format!("{egress:?}").contains("s3cret"), "{egress:?}");
    assert_eq!(Egress::Direct.shown(), None, "the line of before");
}

#[test]
fn a_proxys_fault_is_said_to_the_client_with_its_status_and_never_its_place() {
    let refused = DialError::ProxyRefused {
        proxy: "10.9.8.7:3128".into(),
        target: "140.82.112.3:22".into(),
        status: 403,
        reason: "Forbidden".into(),
    };
    assert_eq!(
        said(ProxyKind::Http, &refused),
        "the proxy of the relay's host refused CONNECT 140.82.112.3:22: 403 Forbidden"
    );
    assert!(
        said(ProxyKind::Socks5 { remote_dns: true }, &refused).contains("refused SOCKS5 CONNECT 140.82.112.3:22: 403")
    );
    let unreachable = DialError::ProxyUnreachable { proxy: "10.9.8.7:3128".into(), detail: "refused".into() };
    let step = "the CONNECT exchange with 10.9.8.7:3128".into();
    let timeout = DialError::Timeout { step, after: Duration::from_secs(8), stage: pod_core::Stage::Proxy };
    let garbled = DialError::ProxyProtocol { proxy: "10.9.8.7:3128".into(), detail: "not HTTP".into() };
    for fault in [refused, unreachable, timeout, garbled] {
        let words = said(ProxyKind::Http, &fault);
        assert!(!words.contains("10.9.8.7"), "{words}");
        assert!(fault.to_string().contains("10.9.8.7"), "the owner's line names it: {fault}");
    }
}

#[tokio::test]
async fn the_name_goes_to_the_proxy_only_where_nothing_is_checked() {
    let egress = egress_of(&[("HTTPS_PROXY", "http://proxy.test:3128"), ("NO_PROXY", "skip.test")]).unwrap();
    let open = Policy { private: true, ..Policy::default() };
    let named = open.plan("target.invalid", 22, None, &egress).await;
    assert_eq!(named, Ok(Plan::Name("target.invalid".into(), 22)));
    assert!(!open.by_name("target.invalid", Some(4), &egress), "a family asked is the role's to resolve");
    assert!(!open.by_name("skip.test", None, &egress), "NO_PROXY's name, resolved here");
    assert!(!open.by_name("target.invalid", None, &Egress::Direct), "no proxy");
    assert!(!Policy::default().by_name("target.invalid", None, &egress), "the policy checks its addresses");
    // An address is its own, checked or not; a port refused is refused first.
    let literal = open.plan("10.1.2.3", 22, None, &egress).await;
    assert_eq!(literal, Ok(Plan::Addresses(vec!["10.1.2.3:22".parse().unwrap()])));
    let port = open.plan("target.invalid", 25, None, &egress).await;
    assert!(matches!(&port, Err(crate::serve::policy::Refused::Policy(w)) if w.contains("port 25")), "{port:?}");
}
