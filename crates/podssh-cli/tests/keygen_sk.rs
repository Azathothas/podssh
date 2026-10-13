//! Keys of security keys (T-229) as processes, with no device: `podssh
//! keygen -t ed25519-sk` refuses with the probe's reason, asks nothing and
//! writes nothing; a login with the key file of one skips it and says why.
//! A key file of OpenSSH's format, made here from a key in software as a
//! device would give it, is read by `-y` and `-l` and rewritten by `-c`.
//! PODSSH_SK_DEVICE set to none stands in for a host with no device, which
//! this test's host may not be.

mod cleanup;
mod keygen_support;
mod ssh_harness;

use std::path::Path;
use std::process::Command;

use keygen_support::*;
use podssh_ssh::keygen::{generate, KeyKind};
use podssh_ssh::russh::keys::ssh_key::LineEnding;
use podssh_ssh::sk::{private_key, Alg, Enrolled, USER_PRESENCE_REQUIRED};

const NO_DEVICE: [(&str, &str); 1] = [("PODSSH_SK_DEVICE", "none")];

/// A key file of an ED25519-SK key, as `ssh-keygen` writes one, and its
/// `.pub`: the public key of a key in software, and a handle of 64 bytes.
fn security_key_file(path: &Path, comment: &str) -> String {
    let base = generate(KeyKind::Ed25519, "").unwrap();
    let point = base.public_key().key_data().ed25519().unwrap().0.to_vec();
    let enrolled = Enrolled { public: point, key_handle: vec![7; 64] };
    let key = private_key(Alg::Ed25519, &enrolled, "ssh:", USER_PRESENCE_REQUIRED, comment).unwrap();
    std::fs::write(path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    let line = key.public_key().to_openssh().unwrap();
    std::fs::write(format!("{}.pub", path.display()), format!("{line}\n")).unwrap();
    line
}

/// With no device, nothing is asked and nothing is written, with or
/// without -N: the probe comes first.
#[test]
fn keygen_of_a_security_key_with_no_device_refuses_and_writes_nothing() {
    let dir = scratch();
    for (kind, args) in [("ed25519-sk", &["-N", ""][..]), ("ecdsa-sk", &[][..])] {
        let key = file(&dir, &format!("id_{kind}"));
        let mut all = vec!["keygen", "-t", kind, "-f", key.as_str()];
        all.extend_from_slice(args);
        let run = podssh_with(&all, &NO_DEVICE);
        assert_eq!(run.code, 1, "{kind}: {}", run.err);
        assert!(run.err.contains("no security key: PODSSH_SK_DEVICE is none"), "{kind}: {}", run.err);
        assert!(!run.err.contains("passphrase") && run.out.is_empty(), "{kind}: asked: {}{}", run.out, run.err);
        assert!(!Path::new(&key).exists() && !Path::new(&format!("{key}.pub")).exists(), "{kind}: a file");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A usage error comes before the probe: a bad -O, -m, a size, and -O with
/// a key that is not of a security key.
#[test]
fn keygen_of_a_security_key_checks_its_options_first() {
    let dir = scratch();
    let key = file(&dir, "id_ed25519_sk");
    let cases: [&[&str]; 5] = [
        &["-t", "ed25519-sk", "-O", "application=git"],
        &["-t", "ecdsa-sk", "-O", "rk"],
        &["-t", "ed25519-sk", "-m", "PEM"],
        &["-t", "ecdsa-sk", "-b", "384"],
        &["-t", "ed25519", "-O", "resident"],
    ];
    for args in cases {
        let mut all = vec!["keygen", "-N", "", "-f", key.as_str()];
        all.extend_from_slice(args);
        let run = podssh_with(&all, &NO_DEVICE);
        assert_eq!(run.code, 64, "{args:?}: {}", run.err);
        assert!(!Path::new(&key).exists());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// podssh reads a key file of a security key as OpenSSH writes it, and
/// rewrites it with a new comment and the same key.
#[test]
fn a_key_file_of_a_security_key_is_read_and_rewritten() {
    let dir = scratch();
    let key = file(&dir, "id_ed25519_sk");
    let line = security_key_file(Path::new(&key), "made@device");
    let printed = podssh(&["keygen", "-y", "-f", &key]);
    assert_eq!(printed.code, 0, "{}", printed.err);
    assert_eq!(key_part(&printed.out), key_part(&line));
    let listed = podssh(&["keygen", "-l", "-f", &key]);
    assert!(listed.out.starts_with("256 SHA256:"), "{}", listed.out);
    assert!(listed.out.trim_end().ends_with("made@device (ED25519-SK)"), "{}", listed.out);
    let changed = podssh(&["keygen", "-c", "-C", "renamed", "-P", "", "-f", &key]);
    assert_eq!(changed.code, 0, "{}", changed.err);
    let again = podssh(&["keygen", "-y", "-f", &key]);
    assert_eq!(key_part(&again.out), key_part(&line), "the same key");
    let public = std::fs::read_to_string(format!("{key}.pub")).unwrap();
    assert!(public.starts_with("sk-ssh-ed25519@openssh.com ") && public.trim_end().ends_with(" renamed"), "{public}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A login with the key file of a security key and no device: the key is
/// skipped before the server sees it, and the failure says why.
#[test]
fn a_login_with_a_security_key_and_no_device_says_why() {
    let dir = scratch();
    let key = dir.join("id_ed25519_sk");
    security_key_file(&key, "");
    let host_key = file(&dir, "host_key");
    assert_eq!(podssh(&["keygen", "-q", "-N", "", "-f", &host_key]).code, 0);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(Path::new(&host_key)));
    let known = dir.join("known_hosts");
    let output = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["ssh", "--direct", "-p", &port.to_string(), "-v", "-o", "BatchMode=yes", "-o", "IdentityAgent=none"])
        .args(["-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={}", known.display()))
        .arg("-i")
        .arg(&key)
        .args(["key-sk@127.0.0.1", "greet"])
        .env("PODSSH_SK_DEVICE", "none")
        .env("PODSSH_SSH_CONFIG", "none")
        .env("HOME", &dir)
        .env("USERPROFILE", &dir)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_ASKPASS")
        .env_remove("PODSSH_OFFLINE")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(255), "{err}");
    assert!(err.contains("no security key: PODSSH_SK_DEVICE is none"), "{err}");
    assert!(err.contains("id_ed25519_sk"), "the key file is named: {err}");
    drop(runtime);
    std::fs::remove_dir_all(&dir).unwrap();
}
