// **A TLS server that presents the certificate `cert_encoding.rs` mints.**
// Included by `cert_for_test.rs`; not a test target of its own.
//
// **This is the rustls side and nothing else.** The bytes come from the
// encoding half and the client configuration under test comes from
// `podssh_ws::tls::client_config`; what is here is the part between them, and
// every fault recorded below was in that part rather than in either end.

use std::sync::Arc;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;

use super::encoding::{
    der_length_covers_the_certificate, read_len, self_signed_inner, TestCert,
};


/// **A `TlsAcceptor` serving `dns_name`, and a root store that trusts it.**
///
/// Every step can fail, so this returns a `Result`. MEASURED 2026-10-02:
/// the earlier version unwrapped each step, and the `roots.add` line was
/// inside an `anyhow` block that never compiled alongside the one in use — so
/// a step that could fail was never actually compiled, let alone exercised.
/// A test helper that cannot fail should say so; one that can should not hide
/// it.
pub fn server_for(
    dns_name: &str,
) -> Result<(tokio_rustls::TlsAcceptor, rustls::RootCertStore), String> {
    // **TWO certificates: an anchor and a leaf.** MEASURED 2026-10-02: the
    // first version minted ONE self-signed certificate and used it as both the
    // trust anchor and the server's certificate, and webpki refused the
    // handshake with `OtherError(CaUsedAsEndEntity)` — an anchor is a CA and a
    // server may not present a CA as its end-entity certificate.
    let anchor = self_signed_inner(&format!("{dns_name}-anchor"), true);
    let leaf = self_signed_inner(dns_name, false);

    der_length_covers_the_certificate(&anchor.der);
    der_length_covers_the_certificate(&leaf.der);

    let mut roots = rustls::RootCertStore::empty();
    // **`?`, not `.expect`.** MEASURED 2026-10-02: this line unwrapped
    // `Result<CertificateDer, Error>` into an `anyhow::Error`, which
    // `RootCertStore::add` does not accept. It could only compile after the
    // explicit `.expect` beside it was removed — so both paths were never
    // compiled at once, and the one that had been reading green was the one
    // without this guard. A trust anchor that fails to load is a property the
    // caller must be able to fail on, not a panic from a test helper.
    roots
        .add(rustls_pki_types::CertificateDer::from(anchor.der.clone()))
        .map_err(|e| format!("the self-signed CA is not a usable anchor: {e}"))?;

    // The server presents the leaf alone. The anchor reaches the client
    // inside the trust store, which is exactly what a deployment's CA bundle
    // does — the same arrangement `tls::roots_from_bundle` builds.
    let chain = vec![rustls_pki_types::CertificateDer::from(leaf.der.clone())];
    let key = key_for(&leaf)?;

    // podssh's own provider has no `KeyProvider` that loads a key —
    // `crypto::sign::NoClientKeys` refuses every one, because podssh is a
    // client and never holds a private key. MEASURED 2026-10-02: using
    // podssh's provider unmodified for the server failed with *"podssh is a
    // client and holds no private keys"*. The server side of a test needs
    // one, so the test supplies its own; the client configuration under test
    // is untouched by this.
    let mut provider = podssh_ws::crypto::provider();
    provider.key_provider = &TestKeyProvider;
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS 1.3 is not offered: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("the server cannot present its own certificate: {e}"))?;

    Ok((
        tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        roots,
    ))
}

/// **The key is the LEAF's own key**, because the leaf is the certificate
/// being presented. The anchor's key never leaves `server_for`.
///
/// **A real SEC1 `ECPrivateKey`, assembled by hand.** MEASURED
/// 2026-10-02: this handed rustls a 32-byte scalar wrapped in
/// `PrivateSec1KeyDer`, which `secret_sec1_der()` yields *verbatim* — there is
/// no unwrapping and no re-encoding — so the test's `KeyProvider` was handed
/// raw bytes where a DER structure was declared.
///
/// That single error produced **`BadSignature` on all three hostname tests,
/// including the control that asks for the name the certificate actually
/// carries**, while the client's chain verification passed: the failure was in
/// the server's `CertificateVerify`, which is a `DigitallySignedStruct` over
/// the handshake transcript rather than a certificate signature, so it carries
/// the same error name as a chain that does not verify.
///
/// Every other candidate was ruled out by measurement before this one, and
/// that order is the point: the minted certificate verifies against its own
/// SPKI (`certificate_structure.rs`), `load_private_key` recovers exactly the
/// key the SPKI publishes, and rustls' own `keys_match` re-derives the SPKI
/// from the key and compares it to the certificate's. Naming a field from a
/// `BadSignature` on its own is how this would have been misdiagnosed twice.
fn key_for(leaf: &TestCert) -> Result<rustls_pki_types::PrivateKeyDer<'static>, String> {
    use super::encoding::{oid, seq, tlv};

    let signing = SigningKey::from_bytes((&leaf.key_der[..]).into())
        .map_err(|_| "the test key is not a valid P-256 scalar".to_string())?;
    let point = signing.verifying_key().to_encoded_point(false);
    let point = point.as_bytes();

    // RFC 5915 ECPrivateKey ::= SEQUENCE { version, privateKey, [0] parameters,
    // [1] publicKey }. The optional fields are what make it a curve-agnostic
    // structure rather than a bare scalar.
    let mut body = vec![0x02, 0x01, 0x01]; // INTEGER 1
    body.extend_from_slice(&[0x04, 0x20]); // OCTET STRING, 32 bytes
    body.extend_from_slice(&leaf.key_der);
    body.extend_from_slice(&tlv(0xa0, &oid(&[1, 2, 840, 10045, 3, 1, 7])));
    body.extend_from_slice(&tlv(0xa1, &tlv(0x03, &[&[0x00][..], point].concat())));

    Ok(rustls_pki_types::PrivateKeyDer::from(
        rustls_pki_types::PrivateSec1KeyDer::from(seq(&[body])),
    ))
}

/// **A `KeyProvider` for the test's server side only.**
///
/// podssh's own is `NoClientKeys`, which refuses every key, and that is
/// right: podssh is a client. MEASURED 2026-10-02: using podssh's provider
/// for the server failed with *"podssh is a client and holds no private
/// keys"*, and the fix is to give the server its own loader rather than to
/// weaken the client's.
#[derive(Debug)]
struct TestKeyProvider;

impl rustls::crypto::KeyProvider for TestKeyProvider {
    fn load_private_key(
        &self,
        key_der: rustls_pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        // MEASURED 2026-10-02: `with_single_cert` DOES consult the provider,
        // so returning an error here fails the server setup with
        // "the test server carries its key directly; it never asks the
        // provider". The loader is real, not a stub.
        //
        // **It parses the SEC1 structure rather than guessing at an offset.**
        // MEASURED 2026-10-02: the earlier version did
        // `all[all.len() - 32..]`, which reads the *last* 32 bytes of the
        // container and is right only when nothing follows the scalar. Its
        // comment claimed MEASURED evidence that `PrivateKeyDer::Pkcs8` was
        // what arrived; that had never been observed, and
        // `PrivateSec1KeyDer` demonstrably stores its bytes verbatim — so the
        // comment described a re-encoding that does not happen. One walk, from
        // the front, with the DER length deciding where the field ends.
        let contents = read_sequence(key_der.secret_der(), 0)?;
        let fields = tlv_fields(&contents, "an ECPrivateKey")?;
        // Each field is a *value*, not a TLV: the INTEGER's content is
        // `01`, not `02 01 01`. MEASURED 2026-10-02: comparing against the
        // TLV made every handshake fail at setup with *"an ECPrivateKey starts
        // with INTEGER 1"*, which is the correct complaint about a container
        // that does not start with one.
        if fields.len() < 2 || fields[0] != [0x01] {
            return Err(rustls::Error::General(
                "an ECPrivateKey starts with INTEGER 1".into(),
            ));
        }
        // The tag is checked by the *length*, not by a prefix on the value:
        // `tlv_fields` strips headers, so the scalar is all 32 bytes.
        // MEASURED 2026-10-02: an earlier version stripped a leading `0x04`
        // and answered *"the privateKey is an OCTET STRING"* for a key that
        // was one — the guard and the parser had been written against two
        // different shapes of the same buffer.
        let secret: &[u8] = &fields[1];
        let bytes: [u8; 32] = <[u8; 32]>::try_from(secret)
            .map_err(|_| rustls::Error::General("the test key is not 32 bytes".into()))?;
        let signing = SigningKey::from_bytes(&bytes.into())
            .map_err(|_| rustls::Error::General("the test key is not a valid scalar".into()))?;
        Ok(Arc::new(TestSigningKey { signing }))
    }
}

#[derive(Debug)]
struct TestSigningKey {
    signing: p256::ecdsa::SigningKey,
}

impl rustls::sign::SigningKey for TestSigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        // **A scheme this key can actually produce, chosen by preference.**
        //
        // MEASURED 2026-10-02: the earlier version returned
        // `Some(TestSigner { .. })` whenever the client merely *offered*
        // `ECDSA_NISTP256_SHA256`, and hard-coded `scheme()` to that value while
        // podssh's provider puts **P-384 first** in its preference list. rustls
        // hands `choose_scheme` the client's `signature_algorithms` extension in
        // wire order, which is podssh's order, so `scheme()` — not `offered` —
        // decided the algorithm. The client then verified a P-256 signature
        // with `ECDSA_P384_SHA384`, whose `from_sec1_bytes` rejects a P-256 key
        // outright, and the whole handshake answered `BadSignature`.
        //
        // **A scheme whose declared curve this key is on is the only kind
        // that can be returned from here**, and that is the rule rather than
        // this test's own preference: `SigningKey::choose_scheme` promises the
        // signer it returns is `for` the algorithm `Signer::scheme` names.
        // **This key is P-256 and this certificate is on P-256, so P-384 is
        // not an option here** however the peer prefers it, and saying so
        // plainly is what keeps a future edit from returning one.
        let offered = offered
            .iter()
            .find(|s| **s == rustls::SignatureScheme::ECDSA_NISTP256_SHA256);
        match offered {
            Some(scheme) => Some(Box::new(TestSigner {
                signing: self.signing.clone(),
                scheme: *scheme,
            })),
            None => None,
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct TestSigner {
    signing: p256::ecdsa::SigningKey,
    /// The scheme this signer actually produces, so `scheme()` cannot disagree
    /// with the key.
    scheme: rustls::SignatureScheme,
}

impl rustls::sign::Signer for TestSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let sig: p256::ecdsa::Signature = self.signing.sign(message);
        let der = sig.to_der().as_bytes().to_vec();
        Ok(der)
        // **Sign the message and let the scheme hash it.** rustls hands
        // `Signer::sign` an unhashed transcript (`crypto/signer.rs:80`) and the
        // verifier hashes the same bytes once, so both sides agree. Handing
        // `p256` a pre-hashed message, which it hashes again, produces a
        // signature nothing can verify — the same fault the certificate
        // builder had, in the same crate, one layer out.
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.scheme
    }
}

/// The content of the SEQUENCE at `der[0]`, and every TLV inside it.
fn read_sequence(der: &[u8], at: usize) -> Result<Vec<u8>, rustls::Error> {
    match der.get(at) {
        Some(0x30) => {}
        other => {
            return Err(rustls::Error::General(format!(
                "expected a SEQUENCE at offset {at}, found {other:02x?}"
            )))
        }
    }
    let (len, start) = read_len(der, at + 1);
    if start + len > der.len() {
        return Err(rustls::Error::General(
            "the private key's declared length overruns the container".into(),
        ));
    }
    Ok(der[start..start + len].to_vec())
}

/// Split a concatenation of TLVs into each value's content.
fn tlv_fields(contents: &[u8], what: &str) -> Result<Vec<Vec<u8>>, rustls::Error> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < contents.len() {
        let (len, start) = read_len(contents, at + 1);
        let end = start + len;
        if end > contents.len() {
            return Err(rustls::Error::General(format!("{what} overruns")));
        }
        out.push(contents[start..end].to_vec());
        at = end;
    }
    Ok(out)
}