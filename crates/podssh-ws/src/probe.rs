//! ⛔ **A verifier that prints the peer's chain and accepts it.**
//!
//! ⛔ **This exists for exactly one purpose: to read what the live relay
//! presents when podssh's real verifier refuses it.** E03's acceptance failed
//! with `UnsupportedSignatureAlgorithmContext`, and the question that failure
//! answers is "which algorithm is the chain actually signed with" — a
//! question a rejection cannot answer and a print can.
//!
//! ⛔ **It is a verifier that accepts everything, and it is marked
//! `dangerous` at every call site.** It must never be reachable from
//! `podssh::connect`, and the test suite asserts that the shipped
//! configuration does not use it.

use std::time::{SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

#[derive(Debug)]
pub struct PrintChain;

impl ServerCertVerifier for PrintChain {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        println!("--- chain presented by the peer ---");
        describe(0, "end entity", end_entity.as_ref());
        for (i, cert) in intermediates.iter().enumerate() {
            describe(i + 1, "intermediate", cert.as_ref());
        }
        println!("--- end of chain ---\n");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // ⛔ **An empty list made the client send a `signature_algorithms`
        // extension with nothing in it**, and the server answered
        // `DecodeError`. ⛔ This verifier accepts every signature, so it must
        // also *offer* the schemes a TLS 1.3 server needs to sign with —
        // otherwise it is not permissive, it is broken.
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// ⛔ **A minimal DER walk, enough to name the algorithm and the curve.** The
/// alternative was a full X.509 parser, and the question being answered is
/// narrower than that: which `signatureAlgorithm` signed this, and is the
/// subject public key on P-256 or P-384.
fn describe(index: usize, role: &str, der: &[u8]) {
    println!("cert {index} ({role}), {} bytes", der.len());
    if let Some(sig) = signature_algorithm_oid(der) {
        println!("  signatureAlgorithm OID: {sig}");
    }
    if let Some(curve) = public_key_curve(der) {
        println!("  subjectPublicKeyInfo: {curve}");
    }
    if let Some(san) = subject_alt_names(der) {
        println!("  subjectAltName DNS: {san}");
    }
}

/// The `signatureAlgorithm` OID, read as the DER bytes that follow the
/// AlgorithmIdentifier SEQUENCE. ⛔ Best-effort and labelled as such: this is
/// a diagnostic, and a wrong answer here would be worse than no answer, so the
/// caller prints the raw hex when the walk fails.
fn signature_algorithm_oid(der: &[u8]) -> Option<String> {
    // A certificate is SEQUENCE { tbsCertificate, signatureAlgorithm, ... }.
    let tbs_len = der_sequence_len(der, 0x30)?;
    let alg = tbs_len.next_offset;
    let len = der_sequence_len(der, alg)?;
    let oid = read_oid(der, len.body_start)?;
    Some(oid)
}

/// ⛔ **The named-curve OIDs, matched on their DER body bytes.** The tag and
/// length byte are included because the previous version searched for the
/// body alone and found the same three bytes inside an unrelated OID.
fn public_key_curve(der: &[u8]) -> Option<String> {
    // secp384r1 = 1.3.132.0.34  -> 06 05 2b 81 04 00 22
    if find_bytes(der, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]).is_some() {
        return Some("secp384r1 (1.3.132.0.34)".into());
    }
    // secp256r1 = 1.2.840.10045.3.1.7 -> 06 08 2a 86 48 ce 3d 03 01 07
    if find_bytes(der, &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]).is_some() {
        return Some("secp256r1 (1.2.840.10045.3.1.7)".into());
    }
    // Ed25519 = 1.3.101.112 -> 06 03 2b 65 70
    if find_bytes(der, &[0x06, 0x03, 0x2b, 0x65, 0x70]).is_some() {
        return Some("Ed25519 (1.3.101.112)".into());
    }
    // RSA = 1.2.840.113549.1.1.1 -> 06 09 2a 86 48 86 f7 0d 01 01 01
    if find_bytes(der, &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]).is_some() {
        return Some("rsaEncryption (1.2.840.113549.1.1.1)".into());
    }
    Some("a curve this probe does not name".into())
}

fn subject_alt_names(der: &[u8]) -> Option<String> {
    // dNSName is context tag [2] primitive.
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = find_bytes(&der[i..], &[0x82]) {
        let at = i + p + 1;
        let l = der[at] as usize;
        if l > 0 && at + 1 + l <= der.len() {
            if let Ok(s) = std::str::from_utf8(&der[at + 1..at + 1 + l]) {
                if s.contains('.') && s.len() < 100 {
                    out.push(s.to_string());
                }
            }
        }
        i = at + 1;
    }
    if out.is_empty() {
        None
    } else {
        Some(out.join(", "))
    }
}

struct Seq {
    body_start: usize,
    next_offset: usize,
}

fn der_sequence_len(der: &[u8], at: usize) -> Option<Seq> {
    if *der.get(at)? != 0x30 {
        return None;
    }
    let first = *der.get(at + 1)? as usize;
    if first < 0x80 {
        return Some(Seq { body_start: at + 2, next_offset: at + 2 + first });
    }
    let n = first & 0x7f;
    let mut len = 0usize;
    for k in 0..n {
        len = (len << 8) | *der.get(at + 2 + k)? as usize;
    }
    let body = at + 2 + n;
    Some(Seq { body_start: body, next_offset: body + len })
}

fn read_oid(der: &[u8], at: usize) -> Option<String> {
    if *der.get(at)? != 0x06 {
        return None;
    }
    let len = *der.get(at + 1)? as usize;
    let body = &der[at + 2..at + 2 + len];
    let mut hex = String::new();
    for b in body {
        hex.push_str(&format!("{b:02x}"));
    }
    Some(hex)
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// ⛔ Present so the import is used; this verifier has no clock of its own.
#[allow(dead_code)]
fn _now() -> UnixTime {
    UnixTime::since_unix_epoch(
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default(),
    )
}
