//! The `ClientConfig`, and the rule that hostname verification has no bypass.
//!
//! **There is no `--insecure`, and there is no parameter that would become
//! one.** A sibling project made verification a decision rather than an
//! option. The way that decision is held here is structural: the only
//! constructor takes a bundle and builds a `WebPkiServerVerifier`, and that
//! type's `verify_server_cert` calls `verify_server_name` unconditionally
//! (read in `rustls-0.23.45/src/webpki/server_verifier.rs:276`). A flag
//! would be a bypass someone sets in a hurry.
//!
//! A library that embeds podssh can bring its own `rustls::ClientConfig`
//! instead ([`Trust::caller`]): podbox keeps `ring` and TLS 1.2 for proxies
//! that intercept TLS. Its verifier is then the caller's, which podssh cannot
//! check; podssh's binary never takes that form, and a test keeps it out.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore};

use crate::bundle;
use crate::error::WsError;

/// The version of the compiled-in Mozilla roots (`webpki-roots`), and the day
/// that crates.io published it: the crate holds no date of its own. A test
/// reads Cargo.lock, so an update of the crate must update both. A binary
/// keeps the roots that it was built with; `podssh doctor` gives their age.
pub const ROOTS_VERSION: &str = "1.0.9";
pub const ROOTS_PUBLISHED: &str = "2026-07-18";

/// Where the trust anchors for the relay's certificate come from.
///
/// An explicit file (`--ca-file`, `SSL_CERT_FILE`) is used alone and never
/// widened. Otherwise podssh trusts everything it can find, so a host with no
/// setup still connects: a `podssh-ca.pem` next to the binary, the first
/// readable system bundle, and the Mozilla root store compiled into the binary
/// (`webpki-roots`). Hostname and chain verification are the same either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Only the certificates in this PEM file.
    File(PathBuf),
    /// The bundle next to the binary, a system bundle, and the compiled-in roots.
    Default,
    /// The caller's own configuration, with its provider, roots, verifier and
    /// protocol versions, used as it is. Built only by [`Trust::caller`].
    Caller(CallerConfig),
}

/// A caller's `rustls::ClientConfig` that [`Trust::caller`] accepted.
#[derive(Clone)]
pub struct CallerConfig(Arc<ClientConfig>);

impl CallerConfig {
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.0
    }
}

impl fmt::Debug for CallerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallerConfig(the caller's rustls::ClientConfig)")
    }
}

/// The same configuration, not an equal one: a `ClientConfig` has no
/// equality, and two of them can differ in a verifier that no field shows.
impl PartialEq for CallerConfig {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for CallerConfig {}

impl Trust {
    /// The caller's own TLS configuration, for each connection and each HTTPS
    /// request. Refused when it offers ALPN: the relay's WebSocket upgrade is
    /// HTTP/1.1 only, and a server that chose `h2` would not answer it. The
    /// configuration is never changed to fit; its verifier is the caller's,
    /// and podssh cannot check it.
    pub fn caller(config: Arc<ClientConfig>) -> Result<Trust, WsError> {
        if !config.alpn_protocols.is_empty() {
            let offered: Vec<String> =
                config.alpn_protocols.iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect();
            return Err(WsError::Config(format!(
                "the caller's TLS configuration offers ALPN ({}); the relay's WebSocket upgrade is \
                 HTTP/1.1 only. Give a configuration with no ALPN: podssh does not change it",
                offered.join(", ")
            )));
        }
        Ok(Trust::Caller(CallerConfig(config)))
    }
}

/// System CA bundle locations, most common first. They are often the same
/// file under different names, so only the first readable one is used.
pub const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
];

/// The trust anchors for `trust`. A caller's configuration holds its own,
/// which podssh cannot list.
pub fn roots_for(trust: &Trust) -> Result<TlsRoots, WsError> {
    match trust {
        Trust::File(path) => roots_from_bundle(path),
        Trust::Default => Ok(default_roots()),
        Trust::Caller(_) => {
            Err(WsError::Config("the caller's TLS configuration holds its own roots; podssh cannot list them".into()))
        }
    }
}

/// The rustls configuration for `trust`: the caller's as it is, or podssh's
/// own over the roots of `trust`.
pub fn config_for(trust: &Trust) -> Result<Arc<ClientConfig>, WsError> {
    match trust {
        Trust::Caller(caller) => Ok(caller.config().clone()),
        own => client_config(&roots_for(own)?),
    }
}

/// The default trust store: the compiled-in Mozilla roots, plus a
/// `podssh-ca.pem` next to the binary, plus the first readable system bundle.
/// Unreadable or unparsable extras are skipped; the compiled-in set is always
/// there, so this cannot come back empty.
pub fn default_roots() -> TlsRoots {
    let mut roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let mut sources = vec![format!(
        "{} compiled-in roots (webpki-roots {ROOTS_VERSION} of {ROOTS_PUBLISHED})",
        webpki_roots::TLS_SERVER_ROOTS.len()
    )];
    if let Ok(path) = bundle::default_bundle_path() {
        add_extra(&mut roots, &mut sources, &path);
    }
    for candidate in SYSTEM_BUNDLES {
        if add_extra(&mut roots, &mut sources, Path::new(candidate)) {
            break;
        }
    }
    let count = roots.len();
    TlsRoots { roots, source: sources.join(" + "), count }
}

/// Add the parsable certificates of one optional bundle. Returns whether any
/// were added.
fn add_extra(roots: &mut RootCertStore, sources: &mut Vec<String>, path: &Path) -> bool {
    let Ok(certs) = bundle::load_bundle(path) else { return false };
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added > 0 {
        sources.push(format!("{added} from {}", path.display()));
    }
    added > 0
}

#[derive(Debug)]
pub struct TlsRoots {
    pub roots: RootCertStore,
    /// Where they came from, printed by the doctor. "Verified" is only
    /// meaningful next to the path that was read.
    pub source: String,
    pub count: usize,
}

pub fn roots_from_bundle(path: &Path) -> Result<TlsRoots, WsError> {
    let certs = bundle::load_bundle(path).map_err(|why| WsError::Bundle { path: path.display().to_string(), why })?;
    let offered = certs.len();
    let mut roots = RootCertStore::empty();
    // `add_parsable_certificates` returns `(valid, invalid)` counts. A
    // silently dropped root produces a chain failure that reads as an
    // untrusted issuer rather than as a damaged file, so a non-zero invalid
    // count is an error naming both numbers.
    let (added, invalid) = roots.add_parsable_certificates(certs);
    if invalid > 0 {
        return Err(WsError::Bundle {
            path: path.display().to_string(),
            why: format!("{invalid} of {offered} certificate(s) could not be parsed as trust anchors"),
        });
    }
    if added == 0 {
        return Err(WsError::Bundle {
            path: path.display().to_string(),
            why: "the bundle produced no usable trust anchors".into(),
        });
    }
    Ok(TlsRoots { roots, source: path.display().to_string(), count: added })
}

/// Only the compiled-in Mozilla roots (`webpki-roots`), with no extras.
pub fn roots_from_compiled_set() -> TlsRoots {
    TlsRoots {
        count: webpki_roots::TLS_SERVER_ROOTS.len(),
        roots: RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() },
        source: format!(
            "the compiled-in webpki-roots set ({} anchors) — NOT a file",
            webpki_roots::TLS_SERVER_ROOTS.len()
        ),
    }
}

/// **The provider is passed explicitly, never installed as a process
/// default.** `install_default` is global and can only succeed once per
/// process, so a library that did it would take the choice away from whatever
/// embeds podssh, and a second call would return an error that reads like a
/// bug in the caller.
pub fn client_config(roots: &TlsRoots) -> Result<Arc<ClientConfig>, WsError> {
    client_config_with(roots, crate::crypto::provider())
}

/// [`client_config`] with a provider that the caller gives: the same
/// verifier and the same protocol versions, so that a test can offer one key
/// exchange group alone and still prove the configuration that ships.
pub fn client_config_with(roots: &TlsRoots, provider: CryptoProvider) -> Result<Arc<ClientConfig>, WsError> {
    let provider: Arc<CryptoProvider> = Arc::new(provider);
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots.roots.clone()), provider.clone())
            .build()
            .map_err(|e| WsError::Config(format!("server certificate verifier: {e}")))?;

    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| WsError::Config(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        // **No SNI suppression, no ALPN, no client certificate.** The relay
        // is a single hostname; a client that presents a client certificate
        // has nothing to present one for.
        .with_no_client_auth();

    Ok(Arc::new(config))
}
