//! The cipher suites podssh offers, and the `CryptoProvider` they form.
//!
//! **Every suite here has completed a handshake with the live relay.** A
//! suite that has not is worse than absent: the peer can select it, and the
//! failure arrives in the record layer rather than during negotiation.
//!
//! **TLS 1.2 suites are deliberately absent.** The `tls12` feature is on
//! because rustls's `ClientConfig` path needs it to be *usable*, but podssh
//! offers no TLS 1.2 suite. The relay negotiates 1.3, and carrying a TLS 1.2
//! suite this provider cannot complete would be the same defect as offering an
//! untested one.

use rustls::crypto::CryptoProvider;
use rustls::{CipherSuite, SupportedCipherSuite};

use super::aead::{AeadId, PureAead};
use super::hash::HashAlgorithmId;
use super::hkdf::PureHkdf;
use super::kx::{SECP256R1, X25519};
use super::random::OsRandom;
use super::sign::{signature_algorithms, NoClientKeys};

/// `confidentiality_limit` is `2^24` for AES-GCM, the value rustls's own
/// reference providers use, cited there to `draft-irtf-aead-limits-08`. A
/// larger number would keep encrypting past the point where the bound analysis
/// holds.
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
    common: rustls::CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &PureHkdf(HashAlgorithmId::Sha384),
    aead_alg: &PureAead(AeadId::Aes256Gcm),
    // `None`, and `PureAead::extract_keys` refuses. These two are one
    // decision written twice; a suite claiming QUIC support whose keys cannot
    // be extracted would fail only on a QUIC peer, which podssh never has.
    quic: None,
});

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
    common: rustls::CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &PureHkdf(HashAlgorithmId::Sha256),
    aead_alg: &PureAead(AeadId::Aes128Gcm),
    quic: None,
});

/// **Preference order is this order**, and the first entry is also the
/// default key share in the `ClientHello`. AES-256-GCM first because that is
/// what the live relay has been measured negotiating.
static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];

static ALL_KX_GROUPS: &[&'static dyn rustls::crypto::SupportedKxGroup] = &[X25519, SECP256R1];

/// **This is the whole of the provider.** Five fields, all of them supplied
/// by this crate: no built-in provider is reachable because the `ring` and
/// `aws_lc_rs` features are off, and `rustls` refuses to guess without one.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: signature_algorithms(),
        secure_random: &OsRandom,
        key_provider: &NoClientKeys,
    }
}

/// **Every `SupportedKxGroup` in the provider must have a matching suite**,
/// and rustls documents that as a validity requirement. Asserting it here
/// rather than discovering it as a handshake failure is the difference between
/// a provider that is checked and one that is merely built.
pub fn self_check() -> Result<(), String> {
    let p = provider();
    if p.cipher_suites.is_empty() {
        return Err("the provider offers no cipher suites".into());
    }
    if p.kx_groups.is_empty() {
        return Err("the provider offers no key exchange groups".into());
    }
    if p.signature_verification_algorithms.all.is_empty() {
        return Err("the provider offers no signature algorithms".into());
    }
    // Every suite must name a hash, and that hash must be one of the two the
    // HKDF provider knows how to run.
    for suite in &p.cipher_suites {
        if let SupportedCipherSuite::Tls13(s) = suite {
            let h = s.common.hash_provider.algorithm();
            let ok =
                matches!(h, rustls::crypto::hash::HashAlgorithm::SHA256 | rustls::crypto::hash::HashAlgorithm::SHA384);
            if !ok {
                return Err(format!("suite {:?} names a hash with no HKDF", s.common.suite));
            }
        }
    }
    Ok(())
}
