//! `podssh keygen -e`, `-i` and `-m` as a process (T-022): the formats of
//! other systems, and `-y` and `-l` of a key in each format that `podssh ssh
//! -i` reads. OpenSSH itself reads them in `scripts/interop-keygen.sh`.

mod cleanup;
mod keygen_support;

use keygen_support::*;

/// A key of `kind` in `dir`, with no passphrase: its file and its public
/// key.
fn key(dir: &std::path::Path, kind: &str) -> (String, String) {
    let key = file(dir, &format!("id_{kind}"));
    let made = podssh(&["keygen", "-q", "-t", kind, "-N", "", "-f", &key]);
    assert_eq!(made.code, 0, "{}", made.err);
    let public = key_part(&std::fs::read_to_string(format!("{key}.pub")).unwrap());
    (key, public)
}

/// `-e` writes each form, and `-i` reads it back as the same key.
#[test]
fn convert_export_and_import_each_form() {
    let dir = scratch();
    for kind in ["ecdsa", "rsa", "ed25519"] {
        let (key, public) = key(&dir, kind);
        for (format, first) in [
            ("RFC4716", "---- BEGIN SSH2 PUBLIC KEY ----"),
            ("PKCS8", "-----BEGIN PUBLIC KEY-----"),
            ("PEM", if kind == "rsa" { "-----BEGIN RSA PUBLIC KEY-----" } else { "-----BEGIN PUBLIC KEY-----" }),
        ] {
            let exported = podssh(&["keygen", "-e", "-m", format, "-f", &format!("{key}.pub")]);
            if kind == "ed25519" && format != "RFC4716" {
                assert_eq!(exported.code, 1, "{kind} {format}");
                assert!(exported.err.contains(&format!("has no {format} form")), "{}", exported.err);
                continue;
            }
            assert_eq!(exported.code, 0, "{kind} {format}: {}", exported.err);
            assert!(exported.out.starts_with(first), "{}", exported.out);
            let out = file(&dir, "exported");
            std::fs::write(&out, &exported.out).unwrap();
            let imported = podssh(&["keygen", "-i", "-m", format, "-f", &out]);
            assert_eq!(imported.code, 0, "{kind} {format}: {}", imported.err);
            assert_eq!(key_part(&imported.out), public, "{kind} {format}");
        }
    }
}

/// `-m PEM` and `PKCS8` write a private key of that form, also with a
/// passphrase; `-y` asks for it and reads the key, and `-l` reads it with
/// no `.pub` beside.
#[test]
fn convert_private_forms_and_read_them() {
    let dir = scratch();
    let ask = askpass(&dir);
    for (kind, format, first) in [
        ("rsa", "PEM", "-----BEGIN RSA PRIVATE KEY-----"),
        ("ecdsa", "PEM", "-----BEGIN EC PRIVATE KEY-----"),
        ("ecdsa", "PKCS8", "-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    ] {
        let key = file(&dir, &format!("{kind}-{format}"));
        let made = podssh_asked(&["keygen", "-q", "-t", kind, "-m", format, "-f", &key], &ask, "", "pem words");
        assert_eq!(made.code, 0, "{}", made.err);
        assert!(std::fs::read_to_string(&key).unwrap().starts_with(first), "{kind} {format}");
        let public = key_part(&std::fs::read_to_string(format!("{key}.pub")).unwrap());
        let shown = podssh_asked(&["keygen", "-y", "-f", &key], &ask, "pem words", "");
        assert_eq!(shown.code, 0, "{}", shown.err);
        assert_eq!(key_part(&shown.out), public);
        std::fs::remove_file(format!("{key}.pub")).unwrap();
        let line = podssh_asked(&["keygen", "-l", "-f", &key], &ask, "pem words", "");
        assert_eq!(line.code, 0, "{}", line.err);
        assert!(line.out.contains("SHA256:"), "{}", line.out);
    }
}

/// `-p -m PKCS8` writes a key of OpenSSH's format in PKCS#8, the same key.
#[test]
fn convert_with_p() {
    let dir = scratch();
    let ask = askpass(&dir);
    let (key, public) = key(&dir, "ecdsa");
    let run = podssh_asked(&["keygen", "-q", "-p", "-m", "PKCS8", "-f", &key], &ask, "", "");
    assert_eq!(run.code, 0, "{}", run.err);
    assert!(std::fs::read_to_string(&key).unwrap().starts_with("-----BEGIN PRIVATE KEY-----"));
    let shown = podssh(&["keygen", "-y", "-f", &key]);
    assert_eq!(key_part(&shown.out), public, "{}", shown.err);
}

/// What `-e`, `-i` and `-m` cannot do is refused, in OpenSSH's words where
/// it has some.
#[test]
fn convert_refusals() {
    let dir = scratch();
    let (key, _) = key(&dir, "ed25519");
    for (args, says) in [
        (vec!["keygen", "-e", "-m", "bogus", "-f", &key], "Unsupported conversion format \"bogus\""),
        (vec!["keygen", "-e", "-i", "-f", &key], "-e and -i go alone"),
        (vec!["keygen", "-c", "-C", "x", "-m", "PEM", "-f", &key], "-m goes with -e, -i, -p or a new key"),
    ] {
        let run = podssh(&args);
        assert_eq!(run.code, 64, "{args:?}: {}", run.err);
        assert!(run.err.contains(says), "{args:?}: {}", run.err);
    }
    let line = podssh(&["keygen", "-i", "-f", &format!("{key}.pub")]);
    assert_eq!(line.code, 1);
    assert!(line.err.contains("---- BEGIN SSH2 PUBLIC KEY ----"), "{}", line.err);
    let private = podssh(&["keygen", "-i", "-m", "PEM", "-f", &key]);
    assert_eq!(private.code, 1);
    assert!(private.err.contains("imports public keys only"), "{}", private.err);
}
