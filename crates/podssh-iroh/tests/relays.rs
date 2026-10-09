//! The relays of the iroh road (T-165): the flag before the variable before
//! the table, the URLs that a list of relays takes, and the failover: the
//! first relay that answers `/ping`, with its certificate checked, is the
//! home relay. A planted selection that ignores the flag fails the check of
//! the order. The relay that answers is iroh's own relay server on the
//! loopback, whose certificate podssh's trust store is given.

use std::collections::BTreeSet;
use std::time::Duration;

use iroh::{RelayMode, RelayUrl};
use podssh_iroh::relays::{self, Source};
use podssh_iroh::{ticket, Options, Udp};
use podssh_ws::{ProxyChoice, Trust};

const A: &str = "https://relay-a.example";
const B: &str = "https://relay-b.example:8443";
const LIMIT: Duration = Duration::from_secs(60);

type Select = dyn Fn(Option<&str>, Option<String>) -> Result<(Vec<RelayUrl>, Source), String>;

fn urls(list: &[RelayUrl]) -> Vec<String> {
    list.iter().map(ToString::to_string).collect()
}

/// Whether `select` takes the flag before the variable before the table.
fn orders_right(select: &Select) -> bool {
    let table = urls(&relays::defaults());
    let flag = select(Some(A), Some(B.into()));
    let variable = select(None, Some(B.into()));
    let blank = select(None, Some("  ".into()));
    let none = select(None, None);
    matches!(&flag, Ok((list, Source::Flag)) if urls(list) == ["https://relay-a.example/"])
        && matches!(&variable, Ok((list, Source::Variable)) if urls(list) == ["https://relay-b.example:8443/"])
        && matches!(&blank, Ok((list, Source::Table)) if urls(list) == table)
        && matches!(&none, Ok((list, Source::Table)) if urls(list) == table)
}

#[test]
fn the_flag_comes_before_the_variable_before_the_table() {
    assert!(orders_right(&relays::select));
}

#[test]
fn a_planted_selection_that_ignores_the_flag_fails_the_check() {
    let planted = |_: Option<&str>, variable: Option<String>| relays::select(None, variable);
    assert!(!orders_right(&planted), "the check cannot tell a selection that ignores the flag");
}

#[test]
fn a_relay_is_https_with_a_host_and_nothing_more() {
    for good in [
        "https://relay.example",
        "https://relay.example:8443",
        "https://relay.example/",
        "https://192.0.2.7",
        "https://use1-1.relay.n0.iroh.link.",
    ] {
        assert!(relays::parse_url(good).is_ok(), "{good}: {:?}", relays::parse_url(good));
    }
    for (bad, says) in [
        ("http://relay.example", "https:// only"),
        ("https://user@relay.example", "no user name"),
        ("https://relay.example/relay", "no path"),
        ("https://relay.example/?a=1", "no path, query"),
        ("https://relay.example/#top", "fragment"),
        ("https://-relay.example", "not a host name"),
        ("relay.example", "not a URL"),
        ("", "not a URL"),
    ] {
        let why = relays::parse_url(bad).unwrap_err();
        assert!(why.contains(says), "{bad}: {why}");
    }
    let list = relays::parse_list(&format!("{A}, {B},{A}")).unwrap();
    assert_eq!(urls(&list), ["https://relay-a.example/", "https://relay-b.example:8443/"], "in order, once each");
    assert!(relays::parse_list(&format!("{A},,{B}")).unwrap_err().contains("empty"));
    // The errors name where the list came from.
    assert!(relays::select(Some("http://x.example"), None).unwrap_err().starts_with("--iroh-relay:"));
    assert!(relays::select(None, Some("http://x.example".into())).unwrap_err().starts_with(relays::ENV));
}

#[test]
fn the_table_is_iroh_s_own_list() {
    let ours: BTreeSet<String> = urls(&relays::defaults()).into_iter().collect();
    let iroh: BTreeSet<String> = urls(&RelayMode::Default.relay_map().urls::<Vec<_>>()).into_iter().collect();
    assert_eq!(ours, iroh, "n0's relays in iroh changed: read them again");
}

/// A scratch directory unique to one test.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-iroh-relays-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A relay on a port of the loopback where nothing listens.
fn silent_relay() -> RelayUrl {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("https://localhost:{port}").parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_relay_that_answers_is_the_home_relay() {
    let dir = scratch("first");
    let relay = podssh_iroh::test_relay::spawn(&dir).await.expect("a relay on the loopback");
    let trust = Trust::File(relay.cert.clone());
    let silent = silent_relay();
    let (home, missed) = relays::home(&[silent, relay.url.clone()], &trust, &ProxyChoice::Direct).await;
    assert_eq!(home, vec![relay.url.clone()], "the relay that answered, alone");
    assert_eq!(missed.len(), 1, "{missed:?}");
    // An endpoint given it has it as its home relay, with its certificate
    // checked by podssh's trust store.
    let options =
        Options { relays: home, proxy: ProxyChoice::Direct, trust, udp: Udp::Off, accepts: true, ..Options::default() };
    let endpoint = podssh_iroh::bind(&options).await.expect("an endpoint");
    tokio::time::timeout(LIMIT, endpoint.online()).await.expect("a home relay");
    assert_eq!(ticket::home_relay(&endpoint), Some(relay.url.clone()));
    endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_relay_that_answers_iroh_gets_them_all() {
    let dir = scratch("none");
    let relay = podssh_iroh::test_relay::spawn(&dir).await.expect("a relay on the loopback");
    let list = [silent_relay(), relay.url.clone()];
    // podssh's own roots do not hold the test relay's certificate: it does
    // not answer either, and the reason says why.
    let (home, missed) = relays::home(&list, &Trust::Default, &ProxyChoice::Direct).await;
    assert_eq!(home, list.to_vec(), "each relay, for iroh's own probes");
    assert_eq!(missed.len(), 2, "{missed:?}");
    assert!(missed[1].contains("localhost"), "{missed:?}");
}
