//! The ranges of `--routes` in the role's policy (T-635): a private target
//! inside one is dialed, each address of a name is checked, and a target
//! outside each gets the refusal of a policy with no range, in its words.

use super::*;

fn with(words: &[&str]) -> Policy {
    let ranges = words.iter().map(|w| Range::strict(w).unwrap()).collect();
    Policy { ranges, ..Policy::default() }
}

fn at(text: &str) -> SocketAddr {
    SocketAddr::new(text.parse().unwrap(), 22)
}

#[tokio::test]
async fn a_listed_range_admits_one_private_target_and_refuses_the_next() {
    let policy = with(&["10.4.0.9"]);
    assert_eq!(policy.addresses("10.4.0.9", 22, None).await.unwrap(), [at("10.4.0.9")]);
    let next = policy.addresses("10.4.0.10", 22, None).await.unwrap_err();
    let before = Policy::default().addresses("10.4.0.10", 22, None).await.unwrap_err();
    assert_eq!((next.status(), next.answer()), (before.status(), before.answer()), "the words of before");
    assert!(next.logged().is_some_and(|l| l.contains("nor in a range of --routes")), "{next:?}");
    // A wider range, and IPv6.
    let policy = with(&["10.4.1.0/24", "fd00::/8"]);
    assert!(policy.addresses("10.4.1.200", 22, None).await.is_ok());
    assert!(policy.addresses("fd12::7", 22, None).await.is_ok());
    assert!(policy.addresses("10.4.2.1", 22, None).await.is_err());
}

#[test]
fn each_address_of_a_name_is_checked_not_any_one() {
    let policy = with(&["10.4.0.0/24"]);
    let inside = ip_of(&policy, &["10.4.0.9", "10.4.0.10"]);
    assert_eq!(inside, None, "each address in the range");
    assert_eq!(ip_of(&policy, &["10.4.0.9", "10.9.9.9"]), Some("10.9.9.9".parse().unwrap()), "one outside");
    assert_eq!(ip_of(&policy, &["10.9.9.9", "10.4.0.9"]), Some("10.9.9.9".parse().unwrap()), "in either order");
    assert_eq!(ip_of(&policy, &["10.4.0.9", "140.82.112.3"]), None, "a public address beside one in the range");
    assert_eq!(ip_of(&Policy::default(), &["10.4.0.9"]), Some("10.4.0.9".parse().unwrap()), "no range");
}

fn ip_of(policy: &Policy, addresses: &[&str]) -> Option<IpAddr> {
    let wanted: Vec<SocketAddr> = addresses.iter().map(|a| at(a)).collect();
    policy.unlisted(&wanted)
}

#[tokio::test]
async fn a_name_whose_each_address_a_range_holds_is_dialed() {
    // Each address that `localhost` may give, on any host: both loopbacks.
    let policy = with(&["127.0.0.0/8", "::1"]);
    let found = policy.addresses("localhost", 22, None).await.expect("each address of localhost is in a range");
    assert!(!found.is_empty() && found.iter().all(|a| a.ip().is_loopback()), "{found:?}");
    // The default policy refuses the same name.
    assert!(Policy::default().addresses("localhost", 22, None).await.is_err());
}

#[tokio::test]
async fn port_25_stays_refused_inside_a_range_and_an_empty_list_is_no_list() {
    let policy = with(&["10.0.0.0/8"]);
    let port = policy.addresses("10.0.0.1", 25, None).await.unwrap_err();
    assert!(matches!(&port, Refused::Policy(w) if w.contains("port 25 is refused")), "{port:?}");
    let empty = Policy { ranges: Vec::new(), ..Policy::default() };
    let refused = empty.addresses("10.0.0.1", 22, None).await.unwrap_err();
    assert_eq!(refused, Policy::default().addresses("10.0.0.1", 22, None).await.unwrap_err());
}

#[test]
fn a_range_never_sends_the_name_to_the_proxy_unchecked() {
    let proxy = |name: &str| (name == "HTTPS_PROXY").then(|| "http://127.0.0.1:3128".to_string());
    let egress = Egress::from_vars(proxy).unwrap();
    let policy = with(&["10.0.0.0/8"]);
    assert!(!policy.by_name("db.internal", None, &egress), "the role resolves the name and checks each address");
}
