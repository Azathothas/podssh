use russh::keys::{Algorithm, EcdsaCurve};

use super::*;

/// Signatures of the `ssh-keygen -Y sign` of OpenSSH for Windows 10.0p2
/// (2026-10-11) over `sshsig_testdata/data`: Ed25519 in the namespace
/// `git`, and RSA in the namespace `file` with `-O hashalg=sha256`.
const DATA: &[u8] = include_bytes!("sshsig_testdata/data");
const ED25519_PUB: &str = include_str!("sshsig_testdata/ed25519.pub");
const ED25519_SIG: &str = include_str!("sshsig_testdata/ed.sig");
const RSA_PUB: &str = include_str!("sshsig_testdata/rsa.pub");
const RSA_SIG: &str = include_str!("sshsig_testdata/rsa.sig");

fn prehash(data: &[u8], hash: HashAlg) -> Vec<u8> {
    digest(&mut &data[..], hash).unwrap()
}

/// A signature of OpenSSH's holds here, and refuses another namespace and
/// changed data, with OpenSSH's words.
#[test]
fn the_signatures_of_openssh_verify() {
    for (public, armoured, namespace) in [(ED25519_PUB, ED25519_SIG, "git"), (RSA_PUB, RSA_SIG, "file")] {
        let read = read_signature(armoured.as_bytes()).unwrap();
        assert!(read.certificate.is_none());
        let signature = read.signature;
        let key = PublicKey::from_openssh(public.trim()).unwrap();
        assert_eq!(signature.public_key(), key.key_data());
        let hash = signature.hash_alg();
        check(&signature, namespace, &prehash(DATA, hash)).unwrap();
        assert_eq!(
            check(&signature, "other", &prehash(DATA, hash)).unwrap_err(),
            "Couldn't verify signature: namespace does not match"
        );
        assert_eq!(
            check(&signature, namespace, &prehash(b"changed\n", hash)).unwrap_err(),
            "Signature verification failed: incorrect signature"
        );
    }
    assert_eq!(read_signature(RSA_SIG.as_bytes()).unwrap().signature.hash_alg(), HashAlg::Sha256);
}

/// podssh signs with each kind of key, with each hash, and its signature
/// holds; an RSA key signs with `rsa-sha2-512`, as OpenSSH's does.
#[test]
fn each_kind_of_key_signs() {
    let keys = [
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap(),
        PrivateKey::random(&mut rand::rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).unwrap(),
        PrivateKey::from(crate::rsa_key::generate(2048).unwrap()),
    ];
    for key in &keys {
        for hash in [HashAlg::Sha512, HashAlg::Sha256] {
            let signature = sign(key, "file", hash, &prehash(DATA, hash)).unwrap();
            let text = armour(&signature, None).unwrap();
            assert!(text.starts_with("-----BEGIN SSH SIGNATURE-----\n"), "{text}");
            let read = read_signature(text.as_bytes()).unwrap().signature;
            check(&read, "file", &prehash(DATA, hash)).unwrap();
            assert!(check(&read, "git", &prehash(DATA, hash)).is_err());
            if key.algorithm().is_rsa() {
                assert_eq!(read.signature().algorithm(), Algorithm::Rsa { hash: Some(HashAlg::Sha512) });
            }
        }
    }
    assert!(sign(&keys[0], "", HashAlg::Sha512, &prehash(DATA, HashAlg::Sha512)).is_err(), "an empty namespace");
}

/// The lines of an allowed-signers file as ssh-keygen(1) reads them.
#[test]
fn allowed_signers_parse_as_ssh_keygen_reads_them() {
    let key = ED25519_PUB.trim();
    let text = format!(
        "# a comment\n\nalice@example.com {key}\n\
         *@example.org,bob@example.com namespaces=\"file,git\" {key}\n\
         erin@example.com valid-after=\"20200101\",valid-before=\"20991231Z\" {key}\n\
         ca@example.com cert-authority {key}\n\
         bad@example.com color=\"red\" {key}\n\
         lone@example.com\n\
         nokey@example.com namespaces=\"git\"\n"
    );
    let lines = allowed_signers(&text);
    let signer = |n: usize| match &lines[n] {
        Line::Signer(s) => s.clone(),
        Line::Bad { why, .. } => panic!("line {n}: {why}"),
    };
    assert_eq!(
        (signer(0).line, signer(0).principals.as_str(), signer(0).namespaces.is_none()),
        (3, "alice@example.com", true)
    );
    assert_eq!(signer(1).namespaces.as_deref(), Some("file,git"));
    assert_eq!(signer(2).valid_before, Some(4_102_358_400));
    assert_eq!(signer(2).valid_after, parse_time("20200101"));
    assert!(signer(3).cert_authority);
    let bad: Vec<(usize, String)> = lines[4..]
        .iter()
        .map(|l| match l {
            Line::Bad { line, why, .. } => (*line, why.clone()),
            Line::Signer(s) => panic!("line {} parsed", s.line),
        })
        .collect();
    assert_eq!(
        bad,
        [
            (7, "bad options: unsupported option \"color\"".to_string()),
            (8, "invalid line".to_string()),
            (9, "missing key".to_string())
        ]
    );
}

/// Times are local unless they end in Z; a malformed one is refused.
#[test]
fn times_are_local_unless_utc() {
    assert_eq!(parse_time("20200101Z"), Some(1_577_836_800));
    assert_eq!(parse_time("202001011230Z"), Some(1_577_836_800 + 12 * 3600 + 30 * 60));
    assert_eq!(parse_time("20200101123045Z"), Some(1_577_836_800 + 12 * 3600 + 30 * 60 + 45));
    let local = Local.from_local_datetime(&NaiveDate::from_ymd_opt(2020, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap());
    assert_eq!(parse_time("20200101"), Some(local.earliest().unwrap().timestamp()));
    for bad in ["2020010", "20201301", "2020-01-01", "20200101X", ""] {
        assert_eq!(parse_time(bad), None, "{bad}");
    }
    assert_eq!(format_time(parse_time("20200101").unwrap()), "2020-01-01T00:00:00");
}

/// Principals match with their case, wildcards and negation, as OpenSSH's
/// `match_pattern_list` with no change of case.
#[test]
fn principals_match_as_openssh_matches_them() {
    assert!(pattern_list("*@example.org,bob@example.com", "x@example.org"));
    assert!(pattern_list("*@example.org,bob@example.com", "bob@example.com"));
    assert!(!pattern_list("*@example.org,bob@example.com", "Bob@example.com"), "case counts");
    assert!(!pattern_list("!bad@example.org,*@example.org", "bad@example.org"));
    assert!(pattern_list("!bad@example.org,*@example.org", "good@example.org"));
    assert!(!pattern_list("", "x"));
}

/// A line refuses a signature with OpenSSH's words: the namespace first,
/// then its times.
#[test]
fn a_line_refuses_with_openssh_words() {
    let key = PublicKey::from_openssh(ED25519_PUB.trim()).unwrap();
    let mut signer = Signer {
        line: 1,
        principals: "a".into(),
        namespaces: Some("file,m*".into()),
        valid_after: None,
        valid_before: None,
        cert_authority: false,
        key,
    };
    let now = parse_time("20261011Z").unwrap();
    assert_eq!(refuses(&signer, "file", now), None);
    assert_eq!(refuses(&signer, "mail", now), None, "a namespace is a pattern");
    assert_eq!(refuses(&signer, "git", now).unwrap(), "key is not permitted for use in signature namespace \"git\"");
    signer.namespaces = None;
    signer.valid_before = parse_time("20200101");
    let why = refuses(&signer, "git", now).unwrap();
    assert!(
        why.starts_with("key has expired: verify time ") && why.ends_with(" > valid-before 2020-01-01T00:00:00"),
        "{why}"
    );
    signer.valid_before = None;
    signer.valid_after = parse_time("20991231");
    let why = refuses(&signer, "git", now).unwrap();
    assert!(
        why.starts_with("key is not yet valid: verify time ") && why.contains(" < valid-after 2099-12-31T00:00:00"),
        "{why}"
    );
    let signature = read_signature(ED25519_SIG.as_bytes()).unwrap();
    assert!(names_key(&signer, &signature));
    signer.cert_authority = true;
    assert!(!names_key(&signer, &signature), "a cert-authority line names a CA, not the key that signed");
}
