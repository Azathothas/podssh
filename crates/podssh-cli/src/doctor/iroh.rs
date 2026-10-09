//! The iroh road, in a build with the feature `iroh` (T-162): whether a UDP
//! socket binds here, so that the road may take direct paths, and whether its
//! first relay answers `/ping` through the proxy. An endpoint with no UDP
//! path gets its home relay from that probe alone, so a relay that does not
//! answer it leaves the road with no way in.

use std::time::{Duration, Instant};

use podssh_ws::{dial, http, ProxyChoice, Trust};

use super::Report;

/// The bound on the connection and the answer to `/ping`.
const TIMEOUT: Duration = Duration::from_secs(15);

pub(super) fn udp(report: &mut Report<'_>) {
    match podssh_iroh::probe::udp() {
        Ok(addr) => {
            report.ok("bind UDP", format!("bound {addr} and closed it, sending nothing: the iroh road may go direct"))
        }
        Err(e) => report.ok("bind UDP", format!("refused: {e}; the iroh road then uses its relay alone")),
    }
}

pub(super) async fn relay(report: &mut Report<'_>, trust: &Trust) {
    let Some(url) = podssh_iroh::endpoint::default_relays().into_iter().next() else {
        report.unknown("iroh relay", "this build knows no iroh relay");
        return;
    };
    match ping(&url, trust).await {
        Ok(line) => report.ok("iroh relay", line),
        Err(why) => report.fail("iroh relay", why),
    }
}

/// `GET /ping` on the relay, through the same proxy-aware, verified path as
/// the relay's own checks.
async fn ping(url: &iroh::RelayUrl, trust: &Trust) -> Result<String, String> {
    let host = url.host_str().ok_or_else(|| format!("{url}: no host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let started = Instant::now();
    let mut tls = podssh_ws::client::open_tls(host, port, host, trust, &ProxyChoice::FromEnvironment, TIMEOUT)
        .await
        .map_err(|e| format!("{host}: {e}"))?;
    let opened = match dial::proxy_from_env(host) {
        Ok(Some(proxy)) => format!("CONNECT {} through {proxy}", dial::authority(host, port)),
        _ => "directly".to_string(),
    };
    let host_header = if port == 443 { host.to_string() } else { dial::authority(host, port) };
    let exchange = http::exchange(&mut tls, "GET", &host_header, "/ping", &[], b"", 4096);
    let response = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| format!("{host}: /ping did not answer within {} s ({opened})", TIMEOUT.as_secs()))?
        .map_err(|e| format!("{host}: /ping: {e} ({opened})"))?;
    if response.status != 200 {
        return Err(format!("{host}: /ping answered HTTP {} {} ({opened})", response.status, response.body_text(120)));
    }
    Ok(format!("{host}: /ping answered in {} ms, certificate verified ({opened})", started.elapsed().as_millis()))
}
