//! The CSR and the challenge's certificate, read by x509-parser and checked
//! with p256, neither of them the code that wrote them.

use super::*;
use p256::ecdsa::signature::Verifier as _;

const NAME: &str = "relay.podssh.test";
/// 2026-11-02T12:00:00Z.
const NOW: i64 = 1_793_620_800;

/// A self-signed certificate for `name` with no critical extension that
/// webpki does not know, so that the server's check of its key runs; and
/// its key, each as PEM.
pub(crate) fn plain(name: &str) -> (String, Zeroizing<String>) {
    let key = Key::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    let cert = params.self_signed(&key).unwrap();
    (pem("CERTIFICATE", cert.der()), key.pem())
}

/// `signature` (DER) is `public`'s over `message`, as p256 checks it.
fn verifies(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public).expect("a P-256 point");
    let signature = p256::ecdsa::Signature::from_der(signature).expect("an ECDSA signature in DER");
    key.verify(message, &signature).is_ok()
}

#[test]
fn a_csr_names_its_name_alone_and_its_key_signs_it() {
    let key = Key::generate().unwrap();
    let der = csr(NAME, &key).unwrap();
    let (rest, request) = X509CertificationRequest::from_der(&der).expect("x509-parser reads the CSR");
    assert!(rest.is_empty());
    let info = &request.certification_request_info;
    assert_eq!(info.subject.iter().count(), 0, "no subject: the names are in subjectAltName");
    let mut names = Vec::new();
    for ext in request.requested_extensions().expect("an extension request") {
        if let ParsedExtension::SubjectAlternativeName(san) = ext {
            names.extend(san.general_names.iter().map(|n| format!("{n:?}")));
        }
    }
    assert_eq!(names, vec![format!("{:?}", GeneralName::DNSName(NAME))]);
    let public = &info.subject_pki.subject_public_key.data;
    assert_eq!(&public[..], rcgen::PublicKeyData::der_bytes(&key));
    assert!(verifies(public, info.raw, &request.signature_value.data), "the CSR's signature");
}

#[test]
fn the_challenge_certificate_holds_one_name_and_the_digest_of_the_key_authorization() {
    let authorization = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s";
    let (cert_pem, key_pem) = challenge(NAME, authorization, NOW).unwrap();
    let der = pem_block(&cert_pem, "CERTIFICATE").expect("a CERTIFICATE block");
    let (_, cert) = parse_x509_certificate(&der).expect("x509-parser reads it");
    let names: Vec<String> = match cert.subject_alternative_name() {
        Ok(Some(san)) => san.value.general_names.iter().map(|n| format!("{n:?}")).collect(),
        other => panic!("no subjectAltName: {other:?}"),
    };
    assert_eq!(names, vec![format!("{:?}", GeneralName::DNSName(NAME))], "exactly one name");
    let acme: Vec<_> = cert.extensions().iter().filter(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31").collect();
    assert_eq!(acme.len(), 1, "one acmeIdentifier");
    assert!(acme[0].critical, "acmeIdentifier is critical (RFC 8737, section 3)");
    // Its value is a DER OCTET STRING of the 32 bytes of the digest.
    let digest = sha2::Sha256::digest(authorization.as_bytes());
    let mut want = vec![0x04, 0x20];
    want.extend_from_slice(&digest[..]);
    assert_eq!(acme[0].value, &want[..]);
    // Self-signed: its own key verifies its signature.
    let public = &cert.public_key().subject_public_key.data;
    assert!(verifies(public, cert.tbs_certificate.as_ref(), &cert.signature_value.data));
    // podssh's server takes the pair, and the facts of its leaf.
    let (_, facts) = load(cert_pem.as_bytes(), key_pem.as_bytes()).expect("the server loads the pair");
    assert_eq!(facts.names, vec![NAME.to_string()]);
    assert!(facts.not_before <= NOW && facts.not_after > NOW + 6 * 86_400, "{facts:?}");
}

#[test]
fn a_key_kept_as_pem_loads_again_and_another_key_is_refused_with_the_chain() {
    let (cert_a, key_a) = plain(NAME);
    let (_, key_b) = plain(NAME);
    // The pair of a renewal read with one file of two written: refused.
    let why = load(cert_a.as_bytes(), key_b.as_bytes()).unwrap_err();
    assert!(why.contains("not the one of the certificate"), "{why}");
    // One file of a key and its chain, as ACME's is kept.
    let both = format!("{}{}", key_a.as_str(), cert_a);
    assert!(load(both.as_bytes(), both.as_bytes()).is_ok());
    let der = pem_block(&key_a, "PRIVATE KEY").expect("a PRIVATE KEY block");
    let again = Key::from_pkcs8(&der).expect("its PKCS #8 loads again");
    assert_eq!(again.pem().as_str(), key_a.as_str());
}

#[test]
fn pem_wraps_at_64_columns_and_reads_back() {
    let der: Vec<u8> = (0..=200u8).collect();
    let text = pem("CERTIFICATE", &der);
    assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n") && text.ends_with("-----END CERTIFICATE-----\n"));
    assert!(text.lines().all(|l| l.len() <= 64), "{text}");
    assert_eq!(pem_block(&text, "CERTIFICATE").as_deref().map(Vec::as_slice), Some(&der[..]));
    assert!(pem_block(&text, "PRIVATE KEY").is_none());
}
