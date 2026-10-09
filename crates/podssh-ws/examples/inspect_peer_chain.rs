//! ⛔ **A one-off probe, run once, to read the live relay's certificate
//! chain.** ⛔ It is NOT a test: it prints, it asserts nothing, and it is
//! excluded from the suite by living in `examples/`. The question it answers
//! is "which curve and which signature algorithm does the relay actually
//! present", and the answer decides whether E03's provider is complete.
//!
//! The verifier below prints the chain and accepts it, because the question
//! comes up exactly when podssh's own verifier refuses the chain. It lives in
//! this example and not in the library, so that no build of `podssh-ws`
//! contains a verifier that turns TLS verification off for whoever installs
//! it (T-065). `tests/no_permissive_verifier.rs` keeps it out of each crate.
//!
//! Run with:  cargo run -p podssh-ws --example inspect_peer_chain

use std::net::ToSocketAddrs as _;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

#[cfg_attr(test, allow(dead_code))]
#[tokio::main]
async fn main() {
    let host = "tcp.ssh.relay.ajam.dev";
    let addr = format!("{host}:443").to_socket_addrs().expect("resolve").next().expect("an address");

    let roots = podssh_ws::tls::roots_from_compiled_set();
    let config = podssh_ws::tls::client_config(&roots).expect("a config");
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name = rustls_pki_types::ServerName::try_from(host.to_string()).expect("a name");

    // ⛔ `dangerous` is used here deliberately and ONLY here: this probe wants
    // to see the peer's chain precisely because podssh's own verifier refuses
    // it. Nothing in the shipped path uses this.
    let mut cfg = (*config).clone();
    cfg.dangerous().set_certificate_verifier(Arc::new(PrintChain));

    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    match connector.connect(name, tcp).await {
        Ok(tls) => {
            let (_, session) = tls.get_ref();
            println!("handshake OK with a permissive verifier");
            println!("suite: {:?}", session.negotiated_cipher_suite().map(|s| s.suite()));
            if let Some(certs) = session.peer_certificates() {
                for (i, c) in certs.iter().enumerate() {
                    println!("cert {i}: {} bytes", c.as_ref().len());
                }
            }
        }
        Err(e) => println!("handshake failed even with a permissive verifier: {e}"),
    }
}

/// ⛔ **A verifier that prints the peer's chain and accepts it.**
#[derive(Debug)]
struct PrintChain;

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
/// subject public key on P-256 or P-384. A field that a short or odd
/// certificate does not hold is "cannot read", never a panic.
fn describe(index: usize, role: &str, der: &[u8]) {
    println!("cert {index} ({role}), {} bytes", der.len());
    match signature_algorithm_oid(der) {
        Some(sig) => println!("  signatureAlgorithm OID: {sig}"),
        None => println!("  signatureAlgorithm OID: cannot read"),
    }
    if let Some(curve) = public_key_curve(der) {
        println!("  subjectPublicKeyInfo: {curve}");
    }
    match subject_alt_names(der) {
        Some(san) => println!("  subjectAltName DNS: {san}"),
        None => println!("  subjectAltName DNS: cannot read"),
    }
}

/// The `signatureAlgorithm` OID, read as the DER bytes that follow the
/// AlgorithmIdentifier SEQUENCE. ⛔ Best-effort and labelled as such: this is
/// a diagnostic, and a wrong answer here would be worse than no answer.
fn signature_algorithm_oid(der: &[u8]) -> Option<String> {
    // A certificate is SEQUENCE { tbsCertificate, signatureAlgorithm, ... }:
    // walk in from offset 0. (The walk once began at offset 0x30, the tag,
    // and so read whatever SEQUENCE sat at byte 48.)
    let cert = der_sequence_len(der, 0)?;
    let tbs = der_sequence_len(der, cert.body_start)?;
    let alg = der_sequence_len(der, tbs.next_offset)?;
    read_oid(der, alg.body_start)
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
    while let Some(p) = find_bytes(der.get(i..)?, &[0x82]) {
        let at = i + p + 1;
        // A tag in the last byte has no length: the certificate is short.
        let Some(&l) = der.get(at) else { break };
        let l = l as usize;
        if let Some(name) = der.get(at + 1..at + 1 + l).filter(|_| l > 0) {
            if let Ok(s) = std::str::from_utf8(name) {
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
    // A length past the end of a short certificate: cannot read.
    let body = der.get(at + 2..at + 2 + len)?;
    let mut hex = String::new();
    for b in body {
        hex.push_str(&format!("{b:02x}"));
    }
    Some(hex)
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two indexes that a short certificate used to panic on: a dNSName
    /// tag in the last byte, and an OID whose length runs past the end.
    #[test]
    fn a_short_certificate_is_cannot_read_and_no_panic() {
        assert_eq!(subject_alt_names(&[0x30, 0x82]), None);
        assert_eq!(read_oid(&[0x06, 0x05, 0x2b], 0), None);
        let short = [0x30, 0x06, 0x30, 0x02, 0x06, 0x09];
        assert_eq!(signature_algorithm_oid(&short), None);
        describe(0, "short", &short);
    }

    /// SEQUENCE { SEQUENCE { NULL }, SEQUENCE { OID 1.3.101.112 } }: the OID
    /// of the second SEQUENCE is the signature algorithm.
    #[test]
    fn the_signature_algorithm_follows_the_tbs_certificate() {
        let der = [0x30, 0x0b, 0x30, 0x02, 0x05, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        assert_eq!(signature_algorithm_oid(&der).as_deref(), Some("2b6570"));
    }

    #[test]
    fn a_whole_oid_and_a_name_are_read() {
        assert_eq!(read_oid(&[0x06, 0x03, 0x2b, 0x65, 0x70], 0).as_deref(), Some("2b6570"));
        let mut der = vec![0x04, 0x82, 0x0b];
        der.extend_from_slice(b"example.org");
        assert_eq!(subject_alt_names(&der).as_deref(), Some("example.org"));
    }
}
