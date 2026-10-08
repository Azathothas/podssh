//! DNS over HTTPS against the public resolvers podssh falls back to. Ignored
//! by default: it needs the network.
//!
//! ```sh
//! cargo test -p podssh-ws --test live_doh -- --ignored --nocapture
//! ```

use std::time::Duration;

use podssh_ws::resolve::{doh_lookup, doh_lookup_with, DOH_RESOLVERS, NXDOMAIN};
use tokio::time::Instant;

/// Each resolver's certificate must verify against its IP address with
/// podssh's own TLS provider, and each must answer.
#[tokio::test]
#[ignore = "network: public DNS-over-HTTPS resolvers"]
async fn every_fallback_resolver_answers_through_verified_tls() {
    let found = doh_lookup("github.com", Instant::now() + Duration::from_secs(20)).await;
    eprintln!("github.com via the resolver list: {found:?}");
    assert!(found.as_ref().is_ok_and(|ips| !ips.is_empty()), "{found:?}");
    // Each one alone, so a fallback that can never work is noticed.
    for resolver in DOH_RESOLVERS {
        let one = doh_lookup_with(&[*resolver], "github.com", Instant::now() + Duration::from_secs(10)).await;
        eprintln!("resolver {} alone: {one:?}", resolver.0);
        assert!(one.as_ref().is_ok_and(|ips| !ips.is_empty()), "{}: {one:?}", resolver.0);
    }
}

/// A name that cannot exist ends the lookup at the first resolver's answer,
/// instead of asking every resolver for every record type.
#[tokio::test]
#[ignore = "network: public DNS-over-HTTPS resolvers"]
async fn a_name_that_does_not_exist_stops_at_the_first_answer() {
    let missing = doh_lookup("podssh-no-such-name.invalid", Instant::now() + Duration::from_secs(20)).await;
    eprintln!("a reserved, nonexistent name: {missing:?}");
    let why = missing.expect_err("an .invalid name never resolves");
    assert_eq!(why, format!("{}: {NXDOMAIN}", DOH_RESOLVERS[0].0));
}
