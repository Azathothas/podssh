//! DNS over HTTPS against the public resolvers podssh falls back to. Ignored
//! by default: it needs the network.
//!
//! ```sh
//! cargo test -p podssh-ws --test live_doh -- --ignored --nocapture
//! ```

use std::time::Duration;

use podssh_ws::resolve::{doh_lookup, doh_lookup_with, DOH_RESOLVERS};
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
