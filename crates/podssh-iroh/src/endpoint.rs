//! An iroh endpoint set up as podssh sets up its other roads
//! (`docs/design.md`, section 7):
//!
//! - no address lookup (pkarr, DNS, mDNS): a peer is dialled by its key and
//!   its relay;
//! - the relays given; the table of [`crate::relays`] by default, whose
//!   first relay that answers `/ping` the caller gives alone (T-165);
//! - podssh's proxy for the relay's dial: iroh's own selection reads
//!   `HTTP_PROXY` first and knows no `ALL_PROXY` or `NO_PROXY`;
//! - podssh's name resolution ([`crate::resolve`]) and podssh's trust store
//!   for the relay's certificate;
//! - no UDP unless this host lets a UDP socket bind, as a probe found
//!   ([`crate::probe`]): the relay alone, else.

use std::sync::Arc;

use iroh::dns::DnsResolver;
use iroh::endpoint::{presets, BindOpts};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, NetReportConfig, RelayMap, RelayMode, RelayUrl, SecretKey};
use podssh_ws::{ProxyChoice, Trust};

/// The relays to use, and the endpoint's way out.
#[derive(Debug, Clone)]
pub struct Options {
    /// The relays: iroh takes the one with the least latency as the home
    /// relay, so a caller that wants the first that answers gives that one
    /// alone ([`crate::relays::home`]). Empty is the table of
    /// [`crate::relays::DEFAULT`].
    pub relays: Vec<RelayUrl>,
    /// How the relay's connection goes out.
    pub proxy: ProxyChoice,
    /// The trust anchors for the relay's certificate.
    pub trust: Trust,
    /// Whether to try direct UDP when a probe allows it.
    pub udp: Udp,
    /// This end's key: a new one when `None` (T-163 keeps one in a file).
    pub secret: Option<SecretKey>,
    /// Whether this end takes sessions, as a node does.
    pub accepts: bool,
    /// The trust for the relay's certificate in place of `trust`, as an
    /// embedder or a test gives it. podssh's own commands never set it.
    pub relay_tls: Option<CaTlsConfig>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            relays: Vec::new(),
            proxy: ProxyChoice::FromEnvironment,
            trust: Trust::Default,
            udp: Udp::Probe,
            secret: None,
            accepts: false,
            relay_tls: None,
        }
    }
}

/// Whether the endpoint may use direct UDP paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Udp {
    /// When a UDP socket binds on this host (see [`crate::probe::udp`]).
    Probe,
    /// Never: the relay carries each byte.
    Off,
}

/// Why an endpoint could not be made.
#[derive(Debug)]
pub enum BindError {
    /// The proxy setting cannot be used.
    Proxy(String),
    /// The trust store cannot be read.
    Trust(String),
    /// iroh refused the configuration, or could not bind.
    Iroh(String),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::Proxy(why) => write!(f, "the proxy setting is not usable for the iroh relay: {why}"),
            BindError::Trust(why) => write!(f, "the trust store for the iroh relay: {why}"),
            BindError::Iroh(why) => write!(f, "the iroh endpoint could not start: {why}"),
        }
    }
}

impl std::error::Error for BindError {}

/// The relays that an endpoint uses when it is given none: the table of
/// [`crate::relays::DEFAULT`], n0's public relays until the operator runs one.
pub fn default_relays() -> Vec<RelayUrl> {
    crate::relays::defaults()
}

/// The relay map of `relays`, or of the table when it is empty.
fn relay_mode(relays: &[RelayUrl]) -> RelayMode {
    let relays = if relays.is_empty() { default_relays() } else { relays.to_vec() };
    RelayMode::Custom(relays.into_iter().collect::<RelayMap>())
}

/// The proxy for the first relay, as podssh selects it, as the URL that iroh
/// takes; `None` for a direct dial. iroh takes one proxy for each relay, so
/// `NO_PROXY` is read for the first. The proxy's address is resolved here,
/// by podssh's chain, so iroh resolves no name at all.
async fn proxy_url(choice: &ProxyChoice, mode: &RelayMode) -> Result<Option<url::Url>, BindError> {
    let urls: Vec<RelayUrl> = mode.relay_map().urls();
    let host = urls.first().and_then(|relay| relay.host_str().map(str::to_string)).unwrap_or_default();
    let proxy = match choice {
        ProxyChoice::Direct => return Ok(None),
        ProxyChoice::Via(proxy) => proxy.clone(),
        ProxyChoice::FromEnvironment => match podssh_ws::dial::proxy_from_env(&host).map_err(BindError::Proxy)? {
            Some(proxy) => proxy,
            None => return Ok(None),
        },
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let addrs = podssh_ws::resolve::resolve(&proxy.host, proxy.port, deadline)
        .await
        .map_err(|why| BindError::Proxy(format!("could not resolve the proxy {}: {why}", proxy.host)))?;
    let addr = addrs.first().ok_or_else(|| BindError::Proxy(format!("the proxy {} has no address", proxy.host)))?;
    let url = url::Url::parse(&proxy.url_at(*addr)).map_err(|e| BindError::Proxy(e.to_string()))?;
    sendable(&url)?;
    Ok(Some(url))
}

/// Whether iroh can give the proxy the user name and password of `url`.
/// iroh puts the URL's text in `Proxy-Authorization` as it is, escapes and
/// all, and in base64url, where RFC 7617 asks for base64: the proxy would
/// refuse a name or password that needed an escape, or whose base64 holds
/// `+` or `/`, and say nothing of why. Such credentials are refused here,
/// with the reason.
fn sendable(url: &url::Url) -> Result<(), BindError> {
    use base64::Engine as _;
    let (user, password) = (url.username(), url.password().unwrap_or_default());
    if user.is_empty() && password.is_empty() {
        return Ok(());
    }
    let pair = format!("{user}:{password}");
    let escaped = pair.contains('%');
    let differs = base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()).contains(['+', '/']);
    if escaped || differs {
        return Err(BindError::Proxy(
            "the iroh road would send the proxy's user name and password in a form that the proxy refuses \
             (iroh sends them escaped, and in base64url); use the relay road, or a password of letters and \
             digits"
                .into(),
        ));
    }
    Ok(())
}

/// The trust for the relay's certificate: podssh's roots, through rustls's
/// own WebPKI verifier.
fn relay_tls(trust: &Trust) -> Result<CaTlsConfig, BindError> {
    let roots = podssh_ws::tls::roots_for(trust).map_err(|e| BindError::Trust(e.to_string()))?.roots;
    let roots = Arc::new(roots);
    Ok(CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
        rustls::client::WebPkiServerVerifier::builder_with_provider(roots.clone(), provider)
            .build()
            .map(|verifier| verifier as Arc<dyn rustls::client::danger::ServerCertVerifier>)
            .map_err(std::io::Error::other)
    })))
}

/// An endpoint with `options`; with the ALPN of podssh's sessions when it
/// takes them.
pub async fn bind(options: &Options) -> Result<Endpoint, BindError> {
    let tls = match &options.relay_tls {
        Some(tls) => tls.clone(),
        None => relay_tls(&options.trust)?,
    };
    let mode = relay_mode(&options.relays);
    let proxy = proxy_url(&options.proxy, &mode).await?;
    // The HTTPS probe of the relays picks the home relay when no UDP path
    // exists, and it goes through the proxy; the captive portal check is
    // one more connection, plain HTTP, that a sandbox's proxy refuses.
    let mut report = NetReportConfig::default();
    report.https_probes = true;
    report.captive_portal_check = false;
    let mut builder = Endpoint::builder(presets::Minimal)
        .clear_address_lookup()
        .relay_mode(mode)
        .dns_resolver(DnsResolver::custom(crate::resolve::Podssh))
        .ca_tls_config(tls)
        .net_report_config(report)
        // iroh's own UDP sockets are required by default: a host that
        // refuses UDP would stop the endpoint. They come back below, not
        // required, after the probe.
        .clear_ip_transports();
    if let Some(url) = proxy {
        builder = builder.proxy_url(url);
    }
    if options.udp == Udp::Probe && crate::probe::udp().is_ok() {
        let optional = || BindOpts::default().set_is_required(false);
        for any in ["0.0.0.0:0", "[::]:0"] {
            builder = builder.bind_addr_with_opts(any, optional()).map_err(|e| BindError::Iroh(e.to_string()))?;
        }
    }
    if let Some(secret) = &options.secret {
        builder = builder.secret_key(secret.clone());
    }
    if options.accepts {
        builder = builder.alpns(vec![crate::ALPN.to_vec()]);
    }
    builder.bind().await.map_err(|e| BindError::Iroh(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::sendable;

    fn url(text: &str) -> url::Url {
        url::Url::parse(text).unwrap()
    }

    #[test]
    fn plain_credentials_and_none_go_to_the_proxy() {
        assert!(sendable(&url("http://127.0.0.1:3128")).is_ok());
        assert!(sendable(&url("http://user:Secret123@127.0.0.1:3128")).is_ok());
    }

    #[test]
    fn credentials_that_iroh_would_send_wrong_are_refused() {
        // An escape: iroh would send `p%40ss`, not `p@ss`.
        assert!(sendable(&url("http://user:p%40ss@127.0.0.1:3128")).is_err());
        // `a:~~~` is `YTp+fn4=` in base64, and `YTp-fn4=` in base64url.
        assert!(sendable(&url("http://a:~~~@127.0.0.1:3128")).is_err());
    }
}
