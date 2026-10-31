//! An iroh endpoint set up as podssh sets up its other roads
//! (`docs/design.md`, section 7):
//!
//! - no address lookup (pkarr, DNS, mDNS): a peer is dialled by its key and
//!   its relay;
//! - the relays given; the table of [`crate::relays`] by default, whose
//!   first relay that answers `/ping` the caller gives alone (T-165);
//! - podssh's proxy for the relay's dial: iroh's own selection reads
//!   `HTTP_PROXY` first and knows no `ALL_PROXY` or `NO_PROXY`. An HTTP
//!   CONNECT proxy, or a SOCKS5 one, through the patch of iroh-relay that
//!   podssh carries (T-280, `vendor/patches/iroh-relay/`);
//! - podssh's name resolution ([`crate::resolve`]) and podssh's trust store
//!   for the relay's certificate;
//! - UDP only after a datagram came back: a round trip of QUIC address
//!   discovery to the home relay in the endpoint's first report, before
//!   anything is dialled or served ([`crate::probe`], T-359); the relay
//!   alone, else.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iroh::dns::DnsResolver;
use iroh::endpoint::{presets, BindOpts};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, NetReportConfig, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey};
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
    /// The port of the relays' QUIC address discovery in place of iroh's
    /// 7842, as a test gives it. podssh's own commands never set it.
    pub qad_port: Option<u16>,
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
            qad_port: None,
        }
    }
}

/// Whether the endpoint may use direct UDP paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Udp {
    /// After a datagram came back: a QUIC address discovery's round trip to
    /// the home relay (see [`crate::probe`]).
    Probe,
    /// After a UDP socket binds, with nothing sent: for a relay that runs no
    /// QUIC address discovery.
    On,
    /// Never: the relay carries each byte.
    Off,
}

/// The variable that chooses: `off` makes the relay carry each byte, as the
/// checks of a sandbox need (T-156); `on` takes UDP after a bind alone, as
/// before T-359, for a relay that runs no QUIC address discovery; anything
/// else is the probe.
pub const UDP_ENV: &str = "PODSSH_IROH_UDP";

impl Udp {
    /// [`Udp::Off`] or [`Udp::On`] when the variable says `off` or `on`;
    /// else [`Udp::Probe`].
    pub fn from_environment() -> Udp {
        Udp::from_value(std::env::var(UDP_ENV).ok().as_deref())
    }

    /// The choice of the variable's value.
    pub fn from_value(value: Option<&str>) -> Udp {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("off") => Udp::Off,
            Some(v) if v.eq_ignore_ascii_case("on") => Udp::On,
            _ => Udp::Probe,
        }
    }
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

/// The relay map of `relays`, or of the table when it is empty; each relay's
/// QUIC address discovery on iroh's port, or on `qad_port`.
fn relay_mode(relays: &[RelayUrl], qad_port: Option<u16>) -> RelayMode {
    let relays = if relays.is_empty() { default_relays() } else { relays.to_vec() };
    let configs = relays.into_iter().map(|url| {
        let mut config = RelayConfig::from(url);
        if let (Some(port), Some(quic)) = (qad_port, config.quic.as_mut()) {
            quic.port = port;
        }
        config
    });
    RelayMode::Custom(configs.collect::<RelayMap>())
}

/// The proxy for the first relay, as podssh selects it, as the URL that iroh
/// takes; `None` for a direct dial. iroh takes one proxy for each relay, so
/// `NO_PROXY` is read for the first. The proxy's address is resolved here,
/// by podssh's chain, so iroh resolves no name at all.
///
/// A SOCKS5 proxy is `socks5h://` at that address (T-280): the relay dial of
/// the patched iroh-relay and the HTTPS probe of the relays (reqwest's
/// SOCKS5) each send the relay's name, so this host needs no DNS for it.
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
    // The patched SOCKS5 dial and reqwest decode the user and the password
    // themselves, and send them as RFC 1929 says: only `CONNECT` has iroh's
    // flaw.
    if proxy.kind == podssh_ws::ProxyKind::Http {
        sendable(&url)?;
    }
    Ok(Some(url))
}

/// Whether iroh can give an HTTP proxy the user name and password of `url`.
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

/// An endpoint, and what its probe of UDP found.
#[derive(Debug)]
pub struct Opened {
    pub endpoint: Endpoint,
    pub udp: crate::probe::Answer,
}

/// How long the endpoint that a probe gave up on may take to close.
const CLOSE_LIMIT: Duration = Duration::from_secs(3);

/// What each endpoint of one [`open`] shares: the one made without UDP after
/// a probe takes the same.
struct Parts {
    tls: CaTlsConfig,
    mode: RelayMode,
    proxy: Option<url::Url>,
}

/// An endpoint with `options`; with the ALPN of podssh's sessions when it
/// takes them.
pub async fn bind(options: &Options) -> Result<Endpoint, BindError> {
    Ok(open(options).await?.endpoint)
}

/// An endpoint with `options`, and what the probe of UDP found. Its UDP
/// sockets stay only after a QUIC address discovery to the home relay came
/// back within [`crate::probe::REPORT_LIMIT`]; else the endpoint is made
/// again without them, with the same key, before it dials or serves.
pub async fn open(options: &Options) -> Result<Opened, BindError> {
    open_with(options, crate::probe::udp).await
}

/// [`open`], with the bind of the probe given, so that a test can plant a
/// refusal.
pub(crate) async fn open_with(
    options: &Options,
    bind_probe: fn() -> std::io::Result<SocketAddr>,
) -> Result<Opened, BindError> {
    use crate::probe::Answer;
    let tls = match &options.relay_tls {
        Some(tls) => tls.clone(),
        None => relay_tls(&options.trust)?,
    };
    let mode = relay_mode(&options.relays, options.qad_port);
    let proxy = proxy_url(&options.proxy, &mode).await?;
    let parts = Parts { tls, mode, proxy };
    let addr = match options.udp {
        Udp::Off => return Ok(Opened { endpoint: make(&parts, options, false, None).await?, udp: Answer::Off }),
        Udp::Probe | Udp::On => match bind_probe() {
            Ok(addr) => addr,
            Err(e) => {
                let endpoint = make(&parts, options, false, None).await?;
                return Ok(Opened { endpoint, udp: Answer::Refused(e) });
            }
        },
    };
    let endpoint = make(&parts, options, true, None).await?;
    if options.udp == Udp::On {
        return Ok(Opened { endpoint, udp: Answer::BindOnly(addr) });
    }
    let started = tokio::time::Instant::now();
    let came_back = crate::probe::round_trip(&endpoint, crate::probe::REPORT_LIMIT).await == Some(true);
    let took = started.elapsed();
    if came_back {
        return Ok(Opened { endpoint, udp: Answer::Answered(took) });
    }
    // The same key for the endpoint that takes its place: a node's ticket,
    // and a client's allowlisted key, name it.
    let secret = endpoint.secret_key().clone();
    let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
    let endpoint = make(&parts, options, false, Some(secret)).await?;
    Ok(Opened { endpoint, udp: Answer::Unknown(took) })
}

/// One endpoint of `parts`, with UDP sockets (not required) or none, and
/// `secret` in place of the options' key.
async fn make(parts: &Parts, options: &Options, udp: bool, secret: Option<SecretKey>) -> Result<Endpoint, BindError> {
    // The HTTPS probe of the relays picks the home relay when no UDP path
    // exists, and it goes through the proxy; the captive portal check is
    // one more connection, plain HTTP, that a sandbox's proxy refuses.
    let mut report = NetReportConfig::default();
    report.https_probes = true;
    report.captive_portal_check = false;
    let mut builder = Endpoint::builder(presets::Minimal)
        .clear_address_lookup()
        .relay_mode(parts.mode.clone())
        .dns_resolver(DnsResolver::custom(crate::resolve::Podssh))
        .ca_tls_config(parts.tls.clone())
        .net_report_config(report)
        // iroh's own UDP sockets are required by default: a host that
        // refuses UDP would stop the endpoint. They come back below, not
        // required, for the probe.
        .clear_ip_transports();
    if let Some(url) = &parts.proxy {
        builder = builder.proxy_url(url.clone());
    }
    if udp {
        let optional = || BindOpts::default().set_is_required(false);
        for any in ["0.0.0.0:0", "[::]:0"] {
            builder = builder.bind_addr_with_opts(any, optional()).map_err(|e| BindError::Iroh(e.to_string()))?;
        }
    }
    if let Some(secret) = secret.or_else(|| options.secret.clone()) {
        builder = builder.secret_key(secret);
    }
    if options.accepts {
        builder = builder.alpns(vec![crate::ALPN.to_vec()]);
    }
    builder.bind().await.map_err(|e| BindError::Iroh(e.to_string()))
}

#[cfg(test)]
#[path = "endpoint_udp_tests.rs"]
mod udp_tests;

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
