//! The proxy that the environment names, as podssh selects it (T-162): with
//! `ALL_PROXY` alone, the iroh road reaches its relay through the proxy. An
//! endpoint with iroh's own selection, the planted defect, reads no
//! `ALL_PROXY`, and finds no relay. And a SOCKS5 proxy in `ALL_PROXY`
//! (T-280), the only way to the relay, which gets the relay's name. A test
//! binary of its own, as it sets the process's environment.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, RelayMode};
use podssh_iroh::{Options, Udp};
use podssh_ws::{ProxyChoice, Trust};

use common::{proxy, relay, LIMIT, RELAY_NAME};

/// The tests of this binary set the same variables: they take turns.
static ENVIRONMENT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Only `ALL_PROXY`, set to `url`, names a proxy.
fn all_proxy_alone(url: &str) {
    for name in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "all_proxy"] {
        std::env::remove_var(name);
    }
    std::env::set_var("ALL_PROXY", url);
}

/// An endpoint's options with the proxy of the environment: the relay, with
/// no UDP; the relay's certificate check skipped, as it is self-signed.
fn from_environment(relay: &iroh::RelayUrl) -> Options {
    Options {
        relays: vec![relay.clone()],
        proxy: ProxyChoice::FromEnvironment,
        trust: Trust::Default,
        udp: Udp::Off,
        secret: None,
        accepts: true,
        relay_tls: Some(CaTlsConfig::insecure_skip_verify()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_proxy_reaches_the_relay_where_iroh_s_own_selection_does_not() {
    let _turn = ENVIRONMENT.lock().await;
    let (relay_url, _relay) = relay().await;
    let (proxy, tunnels) = proxy(relay_url.port().unwrap()).await;
    all_proxy_alone(&format!("http://{proxy}"));

    let endpoint = podssh_iroh::bind(&from_environment(&relay_url)).await.expect("an endpoint");
    tokio::time::timeout(LIMIT, endpoint.online()).await.expect("podssh's selection reached the relay");
    assert!(tunnels.load(Ordering::SeqCst) > 0, "through the proxy");
    endpoint.close().await;

    // The planted defect: iroh's own selection, which reads HTTP_PROXY and
    // HTTPS_PROXY only, for its relay dial. (Its HTTPS probe of the relay
    // can still go through the proxy: the HTTP client under it reads
    // ALL_PROXY itself. A home relay needs both, so the endpoint gets none.)
    let planted = Endpoint::builder(presets::Minimal)
        .clear_address_lookup()
        .relay_mode(RelayMode::Custom(relay_url.clone().into()))
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .proxy_from_env()
        .clear_ip_transports()
        .bind()
        .await
        .expect("an endpoint");
    let online = tokio::time::timeout(Duration::from_secs(8), planted.online()).await;
    assert!(online.is_err(), "iroh's own selection reached the relay");
    planted.close().await;
}

/// A SOCKS5 proxy in `ALL_PROXY` is the only way to the relay, which it
/// reaches by name (T-280): the relay dial of the patched iroh-relay and the
/// HTTPS probe that picks the home relay each pass it, with the user and the
/// password of RFC 1929, and the relay's name with the address type 3. With
/// the refusal of SOCKS5 restored, the planted defect, no endpoint is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socks5_proxy_in_all_proxy_reaches_the_relay_by_name() {
    let _turn = ENVIRONMENT.lock().await;
    let (relay_url, _relay) = relay().await;
    let port = relay_url.port().unwrap();
    let (proxy, seen) = common::socks5::proxy(port, Some(("alice", "s3cret"))).await;
    all_proxy_alone(&format!("socks5h://alice:s3cret@{proxy}"));

    let endpoint = podssh_iroh::bind(&from_environment(&relay_url)).await.expect("an endpoint through SOCKS5");
    tokio::time::timeout(LIMIT, endpoint.online()).await.expect("the relay through the SOCKS5 proxy");
    endpoint.close().await;
    let seen = seen.lock().unwrap().clone();
    // The stand-in is the only way to the relay, so the relay dial and the
    // probe each came through it; each tunnel by name.
    assert!(!seen.is_empty(), "no tunnel through the stand-in");
    for each in &seen {
        assert_eq!((each.address_type, each.host.as_str(), each.port), (3, RELAY_NAME, port), "{seen:?}");
    }
}
