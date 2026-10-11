use russh::keys::{Algorithm, EcdsaCurve, HashAlg};

use super::*;

/// A certificate that the `ssh-keygen -s` of OpenSSH for Windows 10.0p2
/// made (2026-10-11), with each kind of option, its CA, and what its
/// `ssh-keygen -L` printed after the line of the file.
const OPENSSH_CERT: &str = include_str!("cert_testdata/user-cert.pub");
const OPENSSH_CA: &str = include_str!("cert_testdata/ca.pub");
const OPENSSH_L: &str = include_str!("cert_testdata/L.txt");

const NOW: i64 = 1_791_734_397; // 2026-10-11T12:39:57Z

/// `-L` prints what OpenSSH printed for its own certificate: each line, the
/// validity in this host's local time.
#[test]
fn describe_prints_what_openssh_printed() {
    let certificate = Certificate::from_openssh(OPENSSH_CERT.trim()).unwrap();
    let ca = PublicKey::from_openssh(OPENSSH_CA.trim()).unwrap();
    assert_eq!(certificate.signature_key(), ca.key_data());
    let ours = describe(&certificate);
    let theirs: Vec<&str> = OPENSSH_L.lines().collect();
    assert_eq!(ours.len(), theirs.len(), "{ours:#?}");
    for (ours, theirs) in ours.iter().zip(&theirs) {
        if theirs.trim_start().starts_with("Valid:") {
            let after = crate::sshsig::parse_time("20260101Z").unwrap() as u64;
            let before = crate::sshsig::parse_time("20270101Z").unwrap() as u64;
            assert_eq!(*ours, format!("        Valid: {}", format_validity(after, before)));
        } else {
            assert_eq!(ours, theirs);
        }
    }
}

/// `-V` as ssh-keygen takes it, and its refusals in OpenSSH's words.
#[test]
fn validity_as_ssh_keygen_takes_it() {
    let local = |t: &str| crate::sshsig::parse_time(t).unwrap() as u64;
    let n = NOW as u64;
    assert_eq!(validity("+1d", NOW).unwrap(), ((n - 59) / 60 * 60, n + 86_400));
    assert_eq!(validity("+52w1d", NOW).unwrap().1, n + 52 * 604_800 + 86_400);
    assert_eq!(validity("-1h:+1h", NOW).unwrap(), (n - 3600, n + 3600));
    assert_eq!(validity("20260101:20270101", NOW).unwrap(), (local("20260101"), local("20270101")));
    assert_eq!(validity("20260101123000:20270101Z", NOW).unwrap(), (local("20260101123000"), local("20270101Z")));
    assert_eq!(validity("always:forever", NOW).unwrap(), (0, FOREVER));
    assert_eq!(validity("always:20991231", NOW).unwrap(), (0, local("20991231")));
    assert_eq!(validity("20991231:forever", NOW).unwrap(), (local("20991231"), FOREVER));
    for bad in ["garbage", "-1d", "+", "+1x", ":forever", "always:"] {
        assert_eq!(validity(bad, NOW).unwrap_err(), format!("Invalid certificate life specification {bad}"), "{bad}");
    }
    assert_eq!(validity("20270101:20260101", NOW).unwrap_err(), "Empty certificate validity interval");
    assert_eq!(validity("2027:forever", NOW).unwrap_err(), "Invalid from time \"2027\"");
}

#[test]
fn a_serial_is_decimal() {
    assert_eq!(serial("0"), Ok(0));
    assert_eq!(serial("18446744073709551615"), Ok(u64::MAX));
    for bad in ["0x10", "-1", "abc", "", "18446744073709551616"] {
        assert_eq!(serial(bad).unwrap_err(), format!("Invalid serial number \"{bad}\""));
    }
}

/// `-O` as ssh-keygen takes it: the five `permit-` extensions by default,
/// `clear`, the `no-` options, the command, the addresses and the options
/// of their own; a host certificate holds none.
#[test]
fn options_as_ssh_keygen_takes_them() {
    let mut request = Request::new("id", false);
    let (critical, extensions) = request.options();
    assert!(critical.is_empty());
    assert_eq!(extensions.keys().collect::<Vec<_>>(), PERMITS.iter().collect::<Vec<_>>());
    for option in [
        "clear",
        "permit-PTY",
        "force-command=/bin/true",
        "source-address=192.0.2.0/24,2001:db8::/32",
        "extension:x@example.com=v",
        "critical:y@example.com",
    ] {
        request.option(option).unwrap();
    }
    let (critical, extensions) = request.options();
    let pairs = |m: &BTreeMap<String, String>| m.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>();
    assert_eq!(
        pairs(&critical),
        ["force-command=/bin/true", "source-address=192.0.2.0/24,2001:db8::/32", "y@example.com="]
    );
    assert_eq!(pairs(&extensions), ["permit-pty=", "x@example.com=v"]);
    let mut request = Request::new("id", false);
    for option in ["no-pty", "No-X11-Forwarding", "verify-required"] {
        request.option(option).unwrap();
    }
    let (critical, extensions) = request.options();
    assert_eq!(pairs(&critical), ["verify-required="]);
    assert_eq!(pairs(&extensions), ["permit-agent-forwarding=", "permit-port-forwarding=", "permit-user-rc="]);
    assert_eq!(request.option("frobnicate").unwrap_err(), "Unsupported certificate option \"frobnicate\"");
    request.option("force-command=a").unwrap();
    assert_eq!(request.option("force-command=b").unwrap_err(), "force-command already specified");
    assert_eq!(request.option("source-address=nonsense").unwrap_err(), "Invalid source-address list");
    assert_eq!(request.option("source-address=192.0.2.0/33").unwrap_err(), "Invalid source-address list");
    let host = Request::new("id", true);
    assert_eq!(host.options(), (BTreeMap::new(), BTreeMap::new()));
}

/// A certificate of each kind of CA holds against its CA, says its
/// fields, and an RSA CA signs with the SHA that `-t` names.
#[test]
fn each_kind_of_ca_certifies() {
    let user = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let cas = [
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap(),
        PrivateKey::random(&mut rand::rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).unwrap(),
        PrivateKey::from(crate::rsa_key::generate(2048).unwrap()),
    ];
    let mut request = Request::new("the id", false);
    request.principals = vec!["alice".into(), "bob".into()];
    request.serial = 7;
    (request.valid_after, request.valid_before) = validity("-1h:+1h", NOW).unwrap();
    for ca in &cas {
        for hash in [HashAlg::Sha512, HashAlg::Sha256] {
            let certificate = certify(ca, user.public_key(), &request, hash).unwrap();
            let fingerprint = ca.public_key().fingerprint(HashAlg::Sha256);
            certificate.validate_at(NOW as u64, [&fingerprint]).unwrap();
            assert!(certificate.validate_at((NOW + 7200) as u64, [&fingerprint]).is_err(), "valid after its end");
            assert_eq!(certificate.key_id(), "the id");
            assert_eq!(certificate.serial(), 7);
            assert_eq!(certificate.valid_principals(), ["alice", "bob"]);
            if ca.algorithm().is_rsa() {
                assert_eq!(certificate.signature().algorithm(), Algorithm::Rsa { hash: Some(hash) });
            }
            let text = certificate.to_openssh().unwrap();
            assert!(text.starts_with("ssh-ed25519-cert-v01@openssh.com "), "{text}");
        }
    }
    let mut host = Request::new("host-id", true);
    host.principals = vec![];
    let certificate = certify(&cas[0], user.public_key(), &host, HashAlg::Sha512).unwrap();
    assert!(certificate.cert_type().is_host() && certificate.valid_principals().is_empty());
    let lines = describe(&certificate);
    assert_eq!(lines[0], "        Type: ssh-ed25519-cert-v01@openssh.com host certificate");
    assert!(lines.contains(&"        Valid: forever".to_string()));
    assert!(
        lines.contains(&"        Principals: (none)".to_string())
            && lines.contains(&"        Extensions: (none)".to_string())
    );
}
