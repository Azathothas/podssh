//! TLS for a server of podssh's (T-169, `podssh relay serve`): a certificate
//! chain and a P-256 key from PEM files, served with the process's provider
//! ([`crate::tls::context`]), so that the server needs no C either. The
//! server's side is `pod-tls`'s (`pod_tls::server`); its errors are words
//! here, as each caller says them. The pair served can change while the
//! server runs ([`Served`], T-447).

use std::sync::Arc;

use rustls::sign::CertifiedKey;

pub use pod_tls::server::{certificates, served, signing_key, Served, TlsAcceptor, ACME_TLS_1, HTTP1};

/// A TLS acceptor that presents `cert_pem`'s chain with `key_pem`'s key,
/// over TLS 1.3 and 1.2, offering `alpn`.
pub fn acceptor(cert_pem: &[u8], key_pem: &[u8], alpn: &[&[u8]]) -> Result<TlsAcceptor, String> {
    pod_tls::server::acceptor(provider(), cert_pem, key_pem, alpn).map_err(|e| e.to_string())
}

/// A TLS acceptor that presents what `served` holds at each handshake, over
/// TLS 1.3 and 1.2, offering `alpn`.
pub fn acceptor_for(served: Arc<Served>, alpn: &[&[u8]]) -> Result<TlsAcceptor, String> {
    pod_tls::server::acceptor_for(provider(), served, alpn).map_err(|e| e.to_string())
}

/// `cert_pem`'s chain with `key_pem`'s key, which must be the leaf's: a pair
/// read while a renewal had written one file of two is refused, so that the
/// server keeps the pair of before.
pub fn certified(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    pod_tls::server::certified(cert_pem, key_pem).map_err(|e| e.to_string())
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    crate::tls::context().provider().clone()
}
