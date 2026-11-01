#![doc = include_str!("../README.md")]

use std::sync::{Arc, LazyLock};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, ConfigBuilder, RootCertStore, WantsVerifier, crypto::CryptoProvider},
};
pub use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};
use url::Url;

#[cfg(feature = "insecure")]
mod insecure;

#[cfg(feature = "insecure")]
pub use insecure::connect_insecure;

/// The variable that names a test's CA file (podssh's patch 0027): a PEM file whose certificates
/// join [`webpki_roots::TLS_SERVER_ROOTS`], so that a stand-in control server and its DERP server,
/// of a CA of the test's own, are reached with TLS checked as before. Only a test sets it.
pub const TEST_CA_VAR: &str = "PODSSH_TS_TEST_CA_FILE";

static ROOT_CERT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    if let Some(path) = std::env::var_os(TEST_CA_VAR).filter(|path| !path.is_empty()) {
        add_test_ca(&mut roots, std::path::Path::new(&path));
    }
    Arc::new(roots)
});

/// Add each certificate of the PEM file at `path` to `roots`. A file that cannot be read, or that
/// holds no certificate, adds none and says so in the log: the handshakes with the test's servers
/// then fail as of an unknown issuer, and none passes unchecked.
fn add_test_ca(roots: &mut RootCertStore, path: &std::path::Path) {
    use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};

    let pem = match std::fs::read(path) {
        Ok(pem) => pem,
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "the test CA file is not read");
            return;
        }
    };
    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    for cert in CertificateDer::pem_slice_iter(&pem) {
        match cert {
            Ok(cert) => certs.push(cert),
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "a test CA certificate is not read");
            }
        }
    }
    let (added, ignored) = roots.add_parsable_certificates(certs);
    tracing::warn!(path = %path.display(), added, ignored, "test CA certificates added to the roots");
}

/// The crypto provider of each TLS config here, named rather than taken from the process default
/// (podssh's patch 0018): rustls has no default when its build holds two providers, as a build
/// beside a crate that turns on `ring` does, and each config built without one then panics.
static PROVIDER: LazyLock<Arc<CryptoProvider>> =
    LazyLock::new(|| Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()));

/// A client config builder on [`PROVIDER`], with rustls's safe default protocol versions.
pub(crate) fn config_builder() -> std::io::Result<ConfigBuilder<ClientConfig, WantsVerifier>> {
    ClientConfig::builder_with_provider(PROVIDER.clone())
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)
}

/// Establishes a TLS stream with a server over an existing connection.
///
/// See module-level documentation for information on root certificates.
pub async fn connect<Io>(server_name: ServerName<'_>, io: Io) -> std::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    connect_alpn::<Io>(server_name, io, []).await
}

/// Establishes a TLS stream with a server over an existing connection, with an optional set of
/// ALPN protocols to negotiate.
///
/// See module-level documentation for information on root certificates.
pub async fn connect_alpn<Io>(
    server_name: ServerName<'_>,
    io: Io,
    alpn: impl IntoIterator<Item = Vec<u8>>,
) -> tokio::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    // TODO(npry): custom tls cert verifier to support commonname overrides and self-signed certs
    let mut rustls_config = config_builder()?
        .with_root_certificates(ROOT_CERT_STORE.clone())
        .with_no_client_auth();

    rustls_config
        .alpn_protocols
        .extend(alpn.into_iter().map(|x| x.to_owned()));

    let connector = TlsConnector::from(Arc::new(rustls_config));

    let stream = connector.connect(server_name.to_owned(), io).await?;

    Ok(stream)
}

/// If possible, converts the host portion of the given [`Url`] to a [`ServerName`] for establishing
/// TLS streams.
pub fn server_name(url: &Url) -> Option<ServerName<'_>> {
    ServerName::try_from(url.host_str()?).ok()
}
