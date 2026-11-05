//! The TLS configuration of a sealed hello (T-642): podssh's own provider
//! and verifier over the roots of the trust, as `tls::client_config` makes
//! them; TLS 1.3 alone, which ECH needs; and one name's list, with HPKE of
//! podssh's provider (`crypto::hpke`). One for each trust, name, list and
//! ALPN, kept for the process, so that a second connection resumes TLS
//! inside its sealed hello; a CA file that changed gets a new one.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use rustls::client::{EchConfig, EchMode};
use rustls::ClientConfig;
use rustls_pki_types::EchConfigListBytes;

use crate::tls::{self, Trust};

/// The configurations kept; past it, the oldest goes.
const MOST: usize = 16;

/// What tells that a CA file changed: its time and its length.
type Stamp = Option<(Option<SystemTime>, u64)>;

struct Kept {
    trust: Trust,
    stamp: Stamp,
    name: String,
    list: Vec<u8>,
    alpn: Vec<Vec<u8>>,
    config: Arc<ClientConfig>,
}

static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

fn lock() -> MutexGuard<'static, Vec<Kept>> {
    KEPT.lock().unwrap_or_else(PoisonError::into_inner)
}

fn stamp(trust: &Trust) -> Stamp {
    match trust {
        Trust::File(path) => file_stamp(path),
        Trust::Default | Trust::Caller(_) => None,
    }
}

fn file_stamp(path: &Path) -> Stamp {
    std::fs::metadata(path).ok().map(|m| (m.modified().ok(), m.len()))
}

/// The configuration that seals `name` with `list` under `trust`, offering
/// `alpn`; why where the list holds no config that podssh can seal with.
pub(super) fn sealed(trust: &Trust, name: &str, list: &[u8], alpn: &[&[u8]]) -> Result<Arc<ClientConfig>, String> {
    let (name, stamp) = (super::key(name), stamp(trust));
    let alpn: Vec<Vec<u8>> = alpn.iter().map(|p| p.to_vec()).collect();
    let same = |k: &&Kept| k.trust == *trust && k.stamp == stamp && k.name == name && k.list == list && k.alpn == alpn;
    if let Some(found) = lock().iter().find(same) {
        return Ok(found.config.clone());
    }
    // Made outside the lock: the roots of the default trust are read from
    // the system's stores.
    let config = make(trust, list, &alpn)?;
    let mut kept = lock();
    if let Some(found) = kept.iter().find(same) {
        return Ok(found.config.clone());
    }
    if kept.len() >= MOST {
        kept.remove(0);
    }
    kept.push(Kept { trust: trust.clone(), stamp, name, list: list.to_vec(), alpn, config: config.clone() });
    Ok(config)
}

/// A configuration that seals with `list`, of podssh's provider over the
/// roots of `trust`.
fn make(trust: &Trust, list: &[u8], alpn: &[Vec<u8>]) -> Result<Arc<ClientConfig>, String> {
    let ech = EchConfig::new(EchConfigListBytes::from(list.to_vec()), crate::crypto::hpke::SUITES)
        .map_err(|e| format!("the list holds no config that podssh can seal with ({e})"))?;
    let roots = tls::roots_for(trust).map_err(|e| e.to_string())?;
    let provider = Arc::new(crate::crypto::provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots.roots), provider.clone())
        .build()
        .map_err(|e| format!("server certificate verifier: {e}"))?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_ech(EchMode::from(ech))
        .map_err(|e| format!("a configuration with ECH: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        // No client certificate, as the plain configuration offers none.
        .with_no_client_auth();
    config.alpn_protocols = alpn.to_vec();
    Ok(Arc::new(config))
}
