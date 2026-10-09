//! The proxy that the environment names, as podssh selects it (T-162): with
//! `ALL_PROXY` alone, the iroh road reaches its relay through the proxy. An
//! endpoint with iroh's own selection, the planted defect, reads no
//! `ALL_PROXY`, and finds no relay. A test binary of its own, as it sets the
//! process's environment.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, RelayMode};
use podssh_iroh::{Options, Udp};
use podssh_ws::{ProxyChoice, Trust};

use common::{proxy, relay, LIMIT};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_proxy_reaches_the_relay_where_iroh_s_own_selection_does_not() {
    let (relay_url, _relay) = relay().await;
    let (proxy, tunnels) = proxy(relay_url.port().unwrap()).await;
    for name in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "all_proxy"] {
        std::env::remove_var(name);
    }
    std::env::set_var("ALL_PROXY", format!("http://{proxy}"));

    let podssh = Options {
        relays: vec![relay_url.clone()],
        proxy: ProxyChoice::FromEnvironment,
        trust: Trust::Default,
        udp: Udp::Off,
        secret: None,
        accepts: true,
        relay_tls: Some(CaTlsConfig::insecure_skip_verify()),
    };
    let endpoint = podssh_iroh::bind(&podssh).await.expect("an endpoint");
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
