//! The certificate that a server of podssh's presents, changed while it
//! serves (T-447): a pair read again on SIGHUP, or one that ACME renewed,
//! is taken by the handshakes after the change, and a connection that is
//! open keeps the pair of its own handshake. Beside it, the certificates of
//! TLS-ALPN-01 (RFC 8737): a CA's validation offers `acme-tls/1` alone, and
//! gets the challenge's certificate for the name that it asks for, never the
//! served one; any other client never gets a challenge's.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// The ALPN of TLS-ALPN-01's validation (RFC 8737, section 6.2).
pub const ACME_TLS_1: &[u8] = b"acme-tls/1";

/// The pair served now, and the challenges of an ACME order under way.
#[derive(Debug, Default)]
pub struct Served {
    current: RwLock<Option<Arc<CertifiedKey>>>,
    /// By the name that the CA validates, lower-cased.
    challenges: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl Served {
    /// A server that presents `first`, or nothing until a pair is set: an
    /// ACME role's before its first certificate.
    pub fn new(first: Option<Arc<CertifiedKey>>) -> Arc<Served> {
        Arc::new(Served { current: RwLock::new(first), challenges: RwLock::default() })
    }

    /// Present `pair` from the next handshake on.
    pub fn set(&self, pair: Arc<CertifiedKey>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Some(pair);
    }

    /// The pair presented now.
    pub fn current(&self) -> Option<Arc<CertifiedKey>> {
        self.current.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Answer a validation of `name` with `pair`, until [`Served::clear_challenge`].
    pub fn set_challenge(&self, name: &str, pair: Arc<CertifiedKey>) {
        self.challenges.write().unwrap_or_else(PoisonError::into_inner).insert(name.to_ascii_lowercase(), pair);
    }

    pub fn clear_challenge(&self, name: &str) {
        self.challenges.write().unwrap_or_else(PoisonError::into_inner).remove(&name.to_ascii_lowercase());
    }

    /// What a hello gets: `offers_acme` when each protocol that it offers
    /// is `acme-tls/1`, as a CA's validation offers it.
    fn pick(&self, server_name: Option<&str>, offers_acme: bool) -> Option<Arc<CertifiedKey>> {
        if offers_acme {
            let name = server_name?.to_ascii_lowercase();
            return self.challenges.read().unwrap_or_else(PoisonError::into_inner).get(&name).cloned();
        }
        self.current()
    }
}

impl ResolvesServerCert for Served {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let offers_acme = hello.alpn().is_some_and(|offered| {
            let offered: Vec<&[u8]> = offered.collect();
            !offered.is_empty() && offered.iter().all(|p| *p == ACME_TLS_1)
        });
        self.pick(hello.server_name(), offers_acme)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::sign::SigningKey;
    use rustls::{SignatureAlgorithm, SignatureScheme};
    use rustls_pki_types::CertificateDer;

    /// A pair whose one certificate is `tag`, so a test tells pairs apart.
    fn pair(tag: u8) -> Arc<CertifiedKey> {
        #[derive(Debug)]
        struct NoKey;
        impl SigningKey for NoKey {
            fn choose_scheme(&self, _: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
                None
            }
            fn algorithm(&self) -> SignatureAlgorithm {
                SignatureAlgorithm::ECDSA
            }
        }
        Arc::new(CertifiedKey::new(vec![CertificateDer::from(vec![tag])], Arc::new(NoKey)))
    }

    fn tag(got: Option<Arc<CertifiedKey>>) -> Option<u8> {
        got.map(|p| p.cert[0].as_ref()[0])
    }

    #[test]
    fn the_next_hello_takes_the_pair_set_last() {
        let served = Served::new(None);
        assert_eq!(tag(served.pick(Some("relay.test"), false)), None, "no pair yet: no handshake");
        served.set(pair(1));
        assert_eq!(tag(served.pick(Some("relay.test"), false)), Some(1));
        // A connection keeps what its handshake took; the next takes the new.
        let held = served.pick(None, false);
        served.set(pair(2));
        assert_eq!(tag(held), Some(1));
        assert_eq!(tag(served.pick(None, false)), Some(2));
    }

    #[test]
    fn a_challenge_goes_to_a_validation_of_its_name_alone() {
        let served = Served::new(Some(pair(1)));
        served.set_challenge("Relay.Example.ORG", pair(9));
        assert_eq!(tag(served.pick(Some("relay.example.org"), true)), Some(9));
        // Another name, or no name, gets no certificate at all.
        assert_eq!(tag(served.pick(Some("other.example.org"), true)), None);
        assert_eq!(tag(served.pick(None, true)), None);
        // An ordinary client never sees the challenge's.
        assert_eq!(tag(served.pick(Some("relay.example.org"), false)), Some(1));
        served.clear_challenge("relay.example.org");
        assert_eq!(tag(served.pick(Some("relay.example.org"), true)), None);
    }
}
