//! `podssh keygen -Y` as a process (T-020): SSH signatures, with the lines,
//! the messages and the streams of OpenSSH's `ssh-keygen -Y`; and signatures
//! made with a certificate, which `cert-authority` lines allow (T-289).
//! OpenSSH itself checks the signatures of each kind of key, and those of a
//! certificate, in `scripts/interop-keygen.sh`; signing with an agent's key
//! is in `tests/agent_cli.rs`. The keys and the certificates are made here.

mod cleanup;
mod keygen_support;

use std::path::Path;

use keygen_support::*;

/// A key of `kind` in `dir`, its public line, and a file of data.
fn key_and_data(dir: &Path, kind: &str) -> (String, String, String) {
    let key = file(dir, &format!("id_{kind}"));
    let made = podssh(&["keygen", "-q", "-t", kind, "-N", "", "-C", "signer", "-f", &key]);
    assert_eq!(made.code, 0, "{}", made.err);
    let public = key_part(&std::fs::read_to_string(format!("{key}.pub")).unwrap());
    let data = file(dir, "data");
    std::fs::write(&data, b"hello, signed\n").unwrap();
    (key, public, data)
}

/// `sign` writes FILE.sig and says so as `ssh-keygen` does; `verify` finds
/// the principal of the allowed signers with the key and says `Good`, and
/// refuses changed data and another namespace with OpenSSH's words.
#[test]
fn sign_then_verify_against_the_allowed_signers() {
    let dir = scratch();
    for kind in ["ed25519", "ecdsa", "rsa"] {
        let (key, public, data) = key_and_data(&dir, kind);
        let _ = std::fs::remove_file(format!("{data}.sig"));
        let run = podssh_input(&["keygen", "-Y", "sign", "-f", &key, "-n", "git", &data], b"", &dir);
        assert_eq!(run.code, 0, "{kind}: {}", run.err);
        assert_eq!(run.err, format!("Signing file {data}\nWrite signature to {data}.sig\n"));
        let sig = format!("{data}.sig");
        assert!(std::fs::read_to_string(&sig).unwrap().starts_with("-----BEGIN SSH SIGNATURE-----\n"));
        let allowed = file(&dir, "allowed");
        std::fs::write(&allowed, format!("alice@example.com {public}\n")).unwrap();
        let verify = |input: &[u8], namespace: &str| {
            podssh_input(
                &["keygen", "-Y", "verify", "-f", &allowed, "-I", "alice@example.com", "-n", namespace, "-s", &sig],
                input,
                &dir,
            )
        };
        let good = verify(b"hello, signed\n", "git");
        assert_eq!(good.code, 0, "{kind}: {}", good.err);
        let name = kind.to_ascii_uppercase();
        assert!(
            good.out.starts_with(&format!("Good \"git\" signature for alice@example.com with {name} key SHA256:")),
            "{}",
            good.out
        );
        let changed = verify(b"changed\n", "git");
        assert_eq!((changed.code, changed.out.as_str()), (1, "Could not verify signature.\n"));
        assert_eq!(changed.err, "Signature verification failed: incorrect signature\n");
        let other = verify(b"hello, signed\n", "file");
        assert_eq!(other.err, "Couldn't verify signature: namespace does not match\n");
    }
}

/// With no file, `sign` signs standard input to standard output, and
/// `check-novalidate` holds it; a signature that is there is never written
/// over.
#[test]
fn sign_standard_input_and_never_over_a_signature() {
    let dir = scratch();
    let (key, _, data) = key_and_data(&dir, "ed25519");
    let run = podssh_input(&["keygen", "-Y", "sign", "-f", &key, "-n", "file"], b"on stdin\n", &dir);
    assert_eq!(run.code, 0, "{}", run.err);
    assert_eq!(run.err, "Signing data on standard input\n");
    let sig = file(&dir, "stdin.sig");
    std::fs::write(&sig, &run.out).unwrap();
    let check = podssh_input(&["keygen", "-Y", "check-novalidate", "-n", "file", "-s", &sig], b"on stdin\n", &dir);
    assert_eq!(check.code, 0, "{}", check.err);
    assert!(check.out.starts_with("Good \"file\" signature with ED25519 key SHA256:"), "{}", check.out);
    assert_eq!(podssh_input(&["keygen", "-q", "-Y", "sign", "-f", &key, "-n", "file", &data], b"", &dir).code, 0);
    let before = std::fs::read(format!("{data}.sig")).unwrap();
    let again = podssh_input(&["keygen", "-Y", "sign", "-f", &key, "-n", "git", &data], b"", &dir);
    assert_eq!(again.code, 1);
    assert!(again.err.contains("already exists"), "{}", again.err);
    assert_eq!(std::fs::read(format!("{data}.sig")).unwrap(), before, "the signature changed");
}

/// `find-principals` and `match-principals` print what `ssh-keygen` prints:
/// each principal of a line that allows the key, and the principals of each
/// line that names one; `No principal matched.` when none does.
#[test]
fn sign_and_find_the_principals() {
    let dir = scratch();
    let (key, public, data) = key_and_data(&dir, "ed25519");
    assert_eq!(podssh_input(&["keygen", "-q", "-Y", "sign", "-f", &key, "-n", "git", &data], b"", &dir).code, 0);
    let allowed = file(&dir, "allowed");
    std::fs::write(
        &allowed,
        format!(
            "*@example.org,bob@example.com namespaces=\"file,git\" {public}\ncarol@example.com namespaces=\"mail\" {public}\n"
        ),
    )
    .unwrap();
    let sig = format!("{data}.sig");
    let found = podssh_input(&["keygen", "-Y", "find-principals", "-f", &allowed, "-s", &sig], b"", &dir);
    assert_eq!((found.code, found.out.as_str(), found.err.as_str()), (0, "*@example.org\nbob@example.com\n", ""));
    let matched = podssh_input(&["keygen", "-Y", "match-principals", "-f", &allowed, "-I", "x@example.org"], b"", &dir);
    assert_eq!((matched.code, matched.out.as_str()), (0, "*@example.org,bob@example.com\n"));
    let none =
        podssh_input(&["keygen", "-Y", "match-principals", "-f", &allowed, "-I", "nobody@example.net"], b"", &dir);
    assert_eq!((none.code, none.err.as_str()), (1, "No principal matched.\n"));
}

/// What `-Y` lacks, and its flags without it, are refused as usage errors;
/// `-r`, a revocation list, is refused by name.
#[test]
fn sign_refusals() {
    let dir = scratch();
    let (key, _, data) = key_and_data(&dir, "ed25519");
    for (args, says) in [
        (vec!["keygen", "-Y", "sign", "-f", &key, &data], "-Y sign needs -n NAMESPACE"),
        (vec!["keygen", "-Y", "frob", "-f", &key], "-Y frob: the operations are"),
        (vec!["keygen", "-n", "git", "-f", &key], "-n goes with -Y"),
        (vec!["keygen", "-Y", "verify", "-f", &key, "-n", "git"], "-Y verify needs -I PRINCIPAL, -s FILE"),
        (vec!["keygen", "-Y", "sign", "-O", "hashalg=md5", "-f", &key, "-n", "git"], "-O hashalg=md5"),
        (vec!["keygen", "-Y", "verify", "-r", "krl", "-f", &key], "revocation"),
    ] {
        let run = podssh_input(&args, b"", &dir);
        assert_eq!(run.code, 64, "{args:?}: {}", run.err);
        assert!(run.err.contains(says), "{args:?}: {}", run.err);
    }
    let no_agent = podssh_input(&["keygen", "-Y", "sign", "-U", "-f", &key, "-n", "git", &data], b"", &dir);
    assert_eq!(no_agent.code, 1, "{}", no_agent.err);
    assert!(no_agent.err.contains("the agent does not hold the key"), "{}", no_agent.err);
}

/// A CA key in `dir`: its file, and the key part of its public line.
fn make_ca(dir: &Path, name: &str) -> (String, String) {
    let ca = file(dir, name);
    let made = podssh(&["keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", &ca]);
    assert_eq!(made.code, 0, "{}", made.err);
    let public = key_part(&std::fs::read_to_string(format!("{ca}.pub")).unwrap());
    (ca, public)
}

/// KEY.pub certified by the CA `ca` with the flags `flags` of `-s`: the file
/// KEY-cert.pub, which replaces the one that is there.
fn certify(ca: &str, key: &str, flags: &[&str]) -> String {
    let public = format!("{key}.pub");
    let mut args = vec!["keygen", "-q", "-s", ca, "-I", "signer"];
    args.extend_from_slice(flags);
    args.push(&public);
    let made = podssh(&args);
    assert_eq!(made.code, 0, "{}", made.err);
    format!("{key}-cert.pub")
}

/// `-Y sign -f KEY-cert.pub` signs with the certificate, as OpenSSH's does;
/// a `cert-authority` line of its CA allows the signature for a principal
/// that the certificate lists, with OpenSSH's lines, and refuses another in
/// its words; `check-novalidate` and `find-principals` name the certificate.
#[test]
fn a_certificate_signs_and_its_cert_authority_line_allows_it() {
    let dir = scratch();
    let (key, _, data) = key_and_data(&dir, "ed25519");
    let (ca, ca_public) = make_ca(&dir, "ca");
    let cert = certify(&ca, &key, &["-n", "alice@example.com,bob@example.org"]);
    let run = podssh_input(&["keygen", "-Y", "sign", "-f", &cert, "-n", "git", &data], b"", &dir);
    assert_eq!(run.code, 0, "{}", run.err);
    assert_eq!(run.err, format!("Signing file {data}\nWrite signature to {data}.sig\n"));
    let sig = format!("{data}.sig");
    let allowed = file(&dir, "allowed");
    std::fs::write(&allowed, format!("*@example.com,bob@example.org cert-authority {ca_public}\n")).unwrap();
    let verify = |principal: &str, more: &[&str]| {
        let mut args = vec!["keygen", "-Y", "verify", "-f", &allowed, "-I", principal, "-n", "git", "-s", &sig];
        args.extend_from_slice(more);
        podssh_input(&args, b"hello, signed\n", &dir)
    };
    // The fingerprint is the key's, as OpenSSH prints it for a certificate.
    let listed = podssh(&["keygen", "-l", "-f", &format!("{key}.pub")]).out;
    let fingerprint = listed.split_whitespace().nth(1).unwrap_or_default().to_string();
    let good = verify("alice@example.com", &[]);
    assert_eq!(good.code, 0, "{}", good.err);
    assert_eq!(good.out, format!("Good \"git\" signature for alice@example.com with ED25519-CERT key {fingerprint}\n"));
    let printed = verify("bob@example.org", &["-O", "print-pubkey"]);
    let second = printed.out.lines().nth(1).unwrap_or_default();
    assert!(second.starts_with("ssh-ed25519-cert-v01@openssh.com "), "{}", printed.out);
    let other = verify("carol@example.com", &[]);
    assert_eq!((other.code, other.out.as_str()), (1, "Could not verify signature.\n"));
    assert_eq!(
        other.err,
        format!("{allowed}:1: certificate not authorized: Certificate invalid: name is not a listed principal\n")
    );
    let novalidate =
        podssh_input(&["keygen", "-Y", "check-novalidate", "-n", "git", "-s", &sig], b"hello, signed\n", &dir);
    assert_eq!(novalidate.out, format!("Good \"git\" signature with ED25519-CERT key {fingerprint}\n"));
    let found = podssh_input(&["keygen", "-Y", "find-principals", "-f", &allowed, "-s", &sig], b"", &dir);
    assert_eq!((found.code, found.out.as_str(), found.err.as_str()), (0, "alice@example.com\nbob@example.org\n", ""));
}

/// A line of another CA, and a plain line of the key, allow no signature of
/// its certificate and say nothing, as OpenSSH; the plain signature of the
/// key is allowed by its plain line, and by no line of a CA.
#[test]
fn a_certificate_of_another_ca_or_a_plain_line_allows_nothing() {
    let dir = scratch();
    let (key, public, data) = key_and_data(&dir, "ed25519");
    let (ca, ca_public) = make_ca(&dir, "ca");
    let (_, other_public) = make_ca(&dir, "other-ca");
    let cert = certify(&ca, &key, &["-n", "alice@example.com"]);
    assert_eq!(podssh_input(&["keygen", "-q", "-Y", "sign", "-f", &cert, "-n", "git", &data], b"", &dir).code, 0);
    let cert_sig = file(&dir, "cert.sig");
    std::fs::rename(format!("{data}.sig"), &cert_sig).unwrap();
    assert_eq!(podssh_input(&["keygen", "-q", "-Y", "sign", "-f", &key, "-n", "git", &data], b"", &dir).code, 0);
    let plain_sig = format!("{data}.sig");
    let others = file(&dir, "others");
    let lines = format!("alice@example.com cert-authority {other_public}\nalice@example.com {public}\n");
    std::fs::write(&others, lines).unwrap();
    let ours = file(&dir, "ours");
    std::fs::write(&ours, format!("alice@example.com cert-authority {ca_public}\n")).unwrap();
    let verify = |signers: &str, sig: &str| {
        podssh_input(
            &["keygen", "-Y", "verify", "-f", signers, "-I", "alice@example.com", "-n", "git", "-s", sig],
            b"hello, signed\n",
            &dir,
        )
    };
    let refused = verify(&others, &cert_sig);
    assert_eq!((refused.code, refused.out.as_str(), refused.err.as_str()), (1, "Could not verify signature.\n", ""));
    assert_eq!(verify(&ours, &cert_sig).code, 0, "the line of its CA");
    assert_eq!(verify(&others, &plain_sig).code, 0, "the plain line, for the plain signature");
    let plain = verify(&ours, &plain_sig);
    assert_eq!((plain.code, plain.err.as_str()), (1, ""), "no line of a CA allows a plain signature");
}

/// With `-f KEY` and KEY-cert.pub beside it, the plain key signs: OpenSSH's
/// `-Y sign` reads the public key of KEY from KEY.pub, never the
/// certificate.
#[test]
fn a_key_beside_its_certificate_signs_without_it() {
    let dir = scratch();
    let (key, _, data) = key_and_data(&dir, "ed25519");
    let (ca, _) = make_ca(&dir, "ca");
    certify(&ca, &key, &["-n", "alice@example.com"]);
    assert_eq!(podssh_input(&["keygen", "-q", "-Y", "sign", "-f", &key, "-n", "git", &data], b"", &dir).code, 0);
    let sig = format!("{data}.sig");
    let check = podssh_input(&["keygen", "-Y", "check-novalidate", "-n", "git", "-s", &sig], b"hello, signed\n", &dir);
    assert!(check.out.starts_with("Good \"git\" signature with ED25519 key SHA256:"), "{}", check.out);
}

/// A certificate is refused in OpenSSH's words when it has expired, is not
/// valid yet, is a host certificate or lists no principal; `-f KEY-cert.pub`
/// does not sign with no private key at KEY, or with another key there.
#[test]
fn certificate_signatures_refused_in_openssh_words() {
    let dir = scratch();
    let (key, _, data) = key_and_data(&dir, "ed25519");
    let (ca, ca_public) = make_ca(&dir, "ca");
    let allowed = file(&dir, "allowed");
    std::fs::write(&allowed, format!("alice@example.com cert-authority {ca_public}\n")).unwrap();
    let sig = format!("{data}.sig");
    let refusal = |flags: &[&str], more: &[&str]| -> String {
        let cert = certify(&ca, &key, flags);
        let _ = std::fs::remove_file(&sig);
        let signed = podssh_input(&["keygen", "-q", "-Y", "sign", "-f", &cert, "-n", "git", &data], b"", &dir);
        assert_eq!(signed.code, 0, "{flags:?}: {}", signed.err);
        let mut args =
            vec!["keygen", "-Y", "verify", "-f", &allowed, "-I", "alice@example.com", "-n", "git", "-s", &sig];
        args.extend_from_slice(more);
        let run = podssh_input(&args, b"hello, signed\n", &dir);
        assert_eq!((run.code, run.out.as_str()), (1, "Could not verify signature.\n"), "{flags:?}");
        run.err
    };
    let said = |why: &str| format!("{allowed}:1: certificate not authorized: {why}\n");
    let old = ["-n", "alice@example.com", "-V", "20200101Z:20210101Z"];
    assert_eq!(refusal(&old, &[]), said("Certificate invalid: expired"));
    assert_eq!(refusal(&old, &["-O", "verify-time=20190101Z"]), said("Certificate invalid: not yet valid"));
    assert_eq!(refusal(&["-h", "-n", "alice@example.com"], &[]), said("Certificate invalid: not a user certificate"));
    assert_eq!(refusal(&[], &[]), said("Certificate lacks principal list"));
    let cert = certify(&ca, &key, &["-n", "alice@example.com"]);
    let lonely = file(&dir, "lonely-cert.pub");
    std::fs::copy(&cert, &lonely).unwrap();
    let run = podssh_input(&["keygen", "-Y", "sign", "-f", &lonely, "-n", "git", &data], b"", &dir);
    assert_eq!(run.code, 1, "{}", run.err);
    assert!(run.err.contains(&format!("No private key found for public key \"{lonely}\"")), "{}", run.err);
    let other = file(&dir, "other");
    assert_eq!(podssh(&["keygen", "-q", "-N", "", "-f", &other]).code, 0);
    let wrong = format!("{other}-cert.pub");
    std::fs::copy(&cert, &wrong).unwrap();
    let run = podssh_input(&["keygen", "-Y", "sign", "-f", &wrong, "-n", "git", &data], b"", &dir);
    assert_eq!(run.code, 1, "{}", run.err);
    assert!(run.err.contains(&format!("Public key {wrong} doesn't match private {other}")), "{}", run.err);
}
