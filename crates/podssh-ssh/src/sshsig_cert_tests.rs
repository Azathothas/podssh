use russh::keys::{Algorithm, EcdsaCurve, PrivateKey};

use super::*;
use crate::cert::{certify, Request};
use crate::sshsig::{self, Line};

/// The data that each test signs, and the time of each check: a day in the
/// validity of each certificate here.
const DATA: &[u8] = b"hello, signed with a certificate\n";
const NOW: &str = "20261012Z";

fn time(text: &str) -> i64 {
    sshsig::parse_time(text).unwrap()
}

fn ed25519() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}

fn prehash(data: &[u8]) -> Vec<u8> {
    sshsig::digest(&mut &data[..], HashAlg::Sha512).unwrap()
}

/// A certificate of `user` by `ca` for `principals`, valid through 2026
/// (UTC), made with ssh-key's builder as `podssh keygen -s` makes one; `host`
/// makes it a host certificate.
fn certificate(ca: &PrivateKey, user: &PrivateKey, principals: &[&str], host: bool) -> Certificate {
    let mut request = Request::new("signer", host);
    request.principals = principals.iter().map(|p| p.to_string()).collect();
    request.valid_after = time("20260101Z") as u64;
    request.valid_before = time("20270101Z") as u64;
    certify(ca, user.public_key(), &request, HashAlg::Sha512).unwrap()
}

/// The signature of DATA by `user`, armoured with `certificate`, read back.
fn made_with(user: &PrivateKey, certificate: &Certificate) -> Signed {
    let signature = sshsig::sign(user, "git", HashAlg::Sha512, &prehash(DATA)).unwrap();
    let text = sshsig::armour(&signature, Some(certificate)).unwrap();
    sshsig::read_signature(text.as_bytes()).unwrap()
}

/// A signature made with a certificate is written as OpenSSH writes one, and
/// read back with its certificate; it holds with the certificate's key, for
/// each kind of key, and refuses changed data.
#[test]
fn a_signature_made_with_a_certificate_is_written_and_read() {
    let ca = ed25519();
    let users = [
        ed25519(),
        PrivateKey::random(&mut rand::rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).unwrap(),
        PrivateKey::from(crate::rsa_key::generate(2048).unwrap()),
    ];
    for user in &users {
        let cert = certificate(&ca, user, &["alice@example.com"], false);
        let signature = sshsig::sign(user, "git", HashAlg::Sha512, &prehash(DATA)).unwrap();
        let text = sshsig::armour(&signature, Some(&cert)).unwrap();
        assert!(text.starts_with("-----BEGIN SSH SIGNATURE-----\n"), "{text}");
        assert!(text.ends_with("\n-----END SSH SIGNATURE-----\n"), "{text}");
        assert!(text.lines().all(|l| l.len() <= 70), "{text}");
        assert!(certificate_inside(text.as_bytes()));
        let read = sshsig::read_signature(text.as_bytes()).unwrap();
        let inside = read.certificate.as_ref().expect("the certificate");
        assert_eq!(inside.to_bytes().unwrap(), cert.to_bytes().unwrap());
        assert_eq!(read.signature.public_key(), user.public_key().key_data());
        sshsig::check(&read.signature, "git", &prehash(DATA)).unwrap();
        assert_eq!(
            sshsig::check(&read.signature, "git", &prehash(b"changed\n")).unwrap_err(),
            "Signature verification failed: incorrect signature"
        );
        assert!(!certificate_inside(sshsig::armour(&signature, None).unwrap().as_bytes()), "a plain signature");
    }
    let signature = sshsig::sign(&users[0], "git", HashAlg::Sha512, &prehash(DATA)).unwrap();
    let other = certificate(&ca, &users[1], &["alice@example.com"], false);
    assert_eq!(sshsig::armour(&signature, Some(&other)).unwrap_err(), "the certificate is not of the key that signed");
}

/// A certificate whose CA signature does not hold is refused as the
/// signature is read, as OpenSSH refuses it when it reads one.
#[test]
fn a_certificate_that_its_ca_did_not_sign_is_refused() {
    let (ca, user) = (ed25519(), ed25519());
    let cert = certificate(&ca, &user, &["alice@example.com"], false);
    let mut bytes = cert.to_bytes().unwrap();
    let at = bytes.windows(5).position(|w| w == b"alice").unwrap();
    bytes[at] = b'm';
    let forged = Certificate::from_bytes(&bytes).unwrap();
    let signature = sshsig::sign(&user, "git", HashAlg::Sha512, &prehash(DATA)).unwrap();
    let text = sshsig::armour(&signature, Some(&forged)).unwrap();
    assert_eq!(
        sshsig::read_signature(text.as_bytes()).unwrap_err(),
        "Couldn't parse signature: the certificate's signature does not verify against its CA"
    );
}

/// A `cert-authority` line names the certificate's CA and never another CA;
/// a plain line of the key does not name its certificate, as OpenSSH
/// compares the types; the line of the CA allows a principal that the
/// certificate lists.
#[test]
fn a_cert_authority_line_names_the_certificate_ca_alone() {
    let (ca, other_ca, user) = (ed25519(), ed25519(), ed25519());
    let cert = certificate(&ca, &user, &["alice@example.com", "bob@example.org"], false);
    let signed = made_with(&user, &cert);
    let line = |key: &PrivateKey| key.public_key().to_openssh().unwrap();
    let lines = sshsig::allowed_signers(&format!(
        "*@example.com cert-authority {}\n*@example.com cert-authority {}\nalice@example.com {}\n",
        line(&ca),
        line(&other_ca),
        line(&user)
    ));
    let signer = |n: usize| match &lines[n] {
        Line::Signer(s) => s.clone(),
        Line::Bad { why, .. } => panic!("line {n}: {why}"),
    };
    let now = time(NOW);
    assert!(sshsig::names_key(&signer(0), &signed), "the line of its CA");
    assert!(!sshsig::names_key(&signer(1), &signed), "the line of another CA");
    assert!(!sshsig::names_key(&signer(2), &signed), "a plain line of its key");
    assert_eq!(not_authorized(&cert, signer(0).key.key_data(), Some("alice@example.com"), now), None);
    assert_eq!(
        not_authorized(&cert, signer(1).key.key_data(), Some("alice@example.com"), now),
        Some("Certificate invalid: not signed by the CA of the line")
    );
    let plain = sshsig::read_signature(sshsig::armour(&signed.signature, None).unwrap().as_bytes()).unwrap();
    assert!(plain.certificate.is_none());
    assert!(sshsig::names_key(&signer(2), &plain), "the plain signature by the line of its key");
    assert!(!sshsig::names_key(&signer(0), &plain), "the plain signature by no line of a CA");
}

/// A certificate refuses in the words of OpenSSH's
/// `sshkey_cert_check_authority`, in its order.
#[test]
fn a_certificate_refuses_with_openssh_words() {
    let (ca, user) = (ed25519(), ed25519());
    let ca_key = ca.public_key().key_data();
    let cert = certificate(&ca, &user, &["alice@example.com"], false);
    let now = time(NOW);
    let alice = Some("alice@example.com");
    assert_eq!(not_authorized(&cert, ca_key, None, now), None, "find-principals asks for no principal");
    assert_eq!(
        not_authorized(&cert, ca_key, Some("carol@example.com"), now),
        Some("Certificate invalid: name is not a listed principal")
    );
    assert_eq!(not_authorized(&cert, ca_key, alice, time("20251231Z")), Some("Certificate invalid: not yet valid"));
    assert_eq!(
        not_authorized(&cert, ca_key, alice, time("20270101Z")),
        Some("Certificate invalid: expired"),
        "valid before its end, not at it"
    );
    let host = certificate(&ca, &user, &["alice@example.com"], true);
    assert_eq!(not_authorized(&host, ca_key, alice, now), Some("Certificate invalid: not a user certificate"));
    let none = certificate(&ca, &user, &[], false);
    assert_eq!(not_authorized(&none, ca_key, alice, now), Some("Certificate lacks principal list"));
}

/// `find-principals` gives the principals of the certificate that the
/// patterns of the line allow, as OpenSSH's `cert_filter_principals`.
#[test]
fn find_principals_filters_those_of_the_certificate() {
    let (ca, user) = (ed25519(), ed25519());
    let ca_key = ca.public_key().key_data();
    let cert = certificate(&ca, &user, &["alice@example.com", "bob@example.org"], false);
    let now = time(NOW);
    assert_eq!(principals(&cert, ca_key, "*@example.com", now).unwrap(), ["alice@example.com"]);
    assert_eq!(
        principals(&cert, ca_key, "*@example.com,bob@*", now).unwrap(),
        ["alice@example.com", "bob@example.org"]
    );
    assert_eq!(principals(&cert, ca_key, "carol@example.com", now).unwrap_err(), "no valid principals found");
    assert_eq!(principals(&cert, ca_key, "*", time("20270101Z")).unwrap_err(), "no valid principals found");
}
