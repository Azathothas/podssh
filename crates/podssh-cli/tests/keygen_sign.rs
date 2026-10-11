//! `podssh keygen -Y` as a process (T-020): SSH signatures, with the lines,
//! the messages and the streams of OpenSSH's `ssh-keygen -Y`. OpenSSH itself
//! checks the signatures of each kind of key in `scripts/interop-keygen.sh`;
//! signing with an agent's key is in `tests/agent_cli.rs`.

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
