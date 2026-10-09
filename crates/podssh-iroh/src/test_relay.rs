//! A relay server on the loopback, for the tests of this crate and of the
//! command line (feature `test-relay`; never in a release): iroh's own relay
//! server, with a self-signed certificate for `localhost`, and that
//! certificate in a PEM file that podssh's trust store takes, so that the
//! road is tested with its certificate checked, as it runs.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use iroh::RelayUrl;
use iroh_relay::server::{CertConfig, RelayConfig, Server, ServerConfig, TlsConfig};

/// A running relay; it stops when this is dropped.
pub struct TestRelay {
    /// `https://NAME:PORT`; `localhost` for [`spawn`].
    pub url: RelayUrl,
    /// The relay's certificate, as `--ca-file` and `SSL_CERT_FILE` take it.
    pub cert: PathBuf,
    _server: Server,
}

/// A relay on the loopback, with its certificate written into `dir`.
pub async fn spawn(dir: &Path) -> std::io::Result<TestRelay> {
    let (certs, server_config) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
    run(dir, "localhost", certs, server_config).await
}

/// A relay on the loopback whose certificate is for `name`, which no
/// resolver knows: a stand-in proxy names it, so that each byte of the
/// relay's connections passes the proxy (T-156).
pub async fn spawn_named(dir: &Path, name: &str) -> std::io::Result<TestRelay> {
    let made = rcgen::generate_simple_self_signed(vec![name.to_string()]).map_err(std::io::Error::other)?;
    let certs = vec![made.cert.der().clone()];
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(made.signing_key.serialize_der());
    let server_config =
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(std::io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.into())
            .map_err(std::io::Error::other)?;
    run(dir, name, certs, server_config).await
}

async fn run(
    dir: &Path,
    name: &str,
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_config: rustls::ServerConfig,
) -> std::io::Result<TestRelay> {
    let tls = TlsConfig::new((Ipv4Addr::LOCALHOST, 0), CertConfig::Manual { server_config });
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls = Some(tls);
    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    let server = Server::spawn(config).await.map_err(std::io::Error::other)?;
    let port = server.https_addr().ok_or_else(|| std::io::Error::other("the relay has no HTTPS address"))?.port();
    let url: RelayUrl = format!("https://{name}:{port}").parse().map_err(std::io::Error::other)?;
    let cert = dir.join(format!("relay-cert-{name}.pem"));
    std::fs::write(&cert, pem(certs.first().map(|c| c.as_ref()).unwrap_or_default()))?;
    Ok(TestRelay { url, cert, _server: server })
}

/// A certificate's DER as PEM.
fn pem(der: &[u8]) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in text.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}
