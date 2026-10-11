//! No private-key operation of the `rsa` crate is left in podssh's source
//! (T-257): its RSA is not constant-time (the Marvin attack,
//! RUSTSEC-2023-0071). An RSA user key signs through aws-lc-rs
//! (`crates/podssh-ssh/src/rsa_key.rs`), `podssh keygen -t rsa` makes its
//! key there, and `podssh agent` keeps no RSA key, as russh's agent server
//! would sign it through `rsa`. The `rsa` crate stays for verification
//! (`crates/podssh-ws/src/crypto/rsa_sig.rs`). Test modules may use it, to
//! make a key that aws-lc-rs refuses.

use std::path::{Path, PathBuf};

/// Each of these names a private-key operation of `rsa`, or a way to one.
const FORBIDDEN: [&str; 5] =
    ["RsaKeypair::random", "pkcs1v15", "try_sign", "sign_with_hash_alg", "authenticate_openssh_cert"];

/// What may appear in one file only: the file, and the text.
const ONLY_IN: [(&str, &str); 5] = [
    // russh signs a key that it holds; podssh hands it only keys that are
    // not RSA, through one function.
    ("podssh-ssh/src/rsa_key.rs", "PrivateKeyWithHashAlg::new"),
    ("podssh-ssh/src/rsa_key.rs", "RsaKeypair"),
    ("podssh-ssh/src/rsa_key.rs", "RsaPrivateKey"),
    // russh's agent server signs the keys that it holds; podssh agent's
    // front refuses an RSA key before russh's server sees it.
    ("podssh-cli/src/agent/serve.rs", "agent::server"),
    // A path of the `rsa` crate itself: verification only.
    ("podssh-ws/src/crypto/rsa_sig.rs", "rsa::"),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A test module of the source: a file `*_tests.rs`, or `tests.rs`.
fn is_test_module(name: &str) -> bool {
    name.ends_with("_tests.rs") || name.ends_with("/tests.rs")
}

/// `rsa::` at the root of a path: the crate `rsa`, not `aws_lc_rs::rsa::`.
fn crate_rsa(line: &str) -> bool {
    line.match_indices("rsa::").any(|(at, _)| {
        let before = line[..at].chars().next_back();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':')
    })
}

/// What `text`, the file `name` (relative to `crates/`, with `/`), holds
/// that the rules forbid.
fn scan(name: &str, text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut once = 0;
    for (no, line) in text.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        let at = format!("crates/{name}:{}", no + 1);
        for pattern in FORBIDDEN {
            if code.contains(pattern) {
                found.push(format!("{at}: {pattern}"));
            }
        }
        if code.contains("PrivateKey::random") && code.contains("Rsa") {
            found.push(format!("{at}: PrivateKey::random of an RSA key"));
        }
        for (file, pattern) in ONLY_IN {
            let hit = if pattern == "rsa::" { crate_rsa(code) } else { code.contains(pattern) };
            if hit && name != file {
                found.push(format!("{at}: {pattern}, which belongs in crates/{file} only"));
            }
        }
        once += code.matches("PrivateKeyWithHashAlg::new").count();
    }
    if once > 1 {
        found.push(format!("crates/{name}: PrivateKeyWithHashAlg::new {once} times, where once is due"));
    }
    found
}

/// The number of files read, and what they hold that the rules forbid.
fn hits() -> (usize, Vec<String>) {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(crates).unwrap().flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    let mut found = Vec::new();
    for file in &files {
        let name = file.strip_prefix(crates).unwrap_or(file).to_string_lossy().replace('\\', "/");
        if !is_test_module(&name) {
            found.extend(scan(&name, &std::fs::read_to_string(file).unwrap()));
        }
    }
    (files.len(), found)
}

#[test]
fn no_rsa_private_key_operation_in_the_source() {
    let (files, found) = hits();
    // A scan that reads nothing passes on any tree.
    assert!(files > 100, "the scan read {files} files: is it reading the workspace?");
    assert!(found.is_empty(), "a private-key operation of the rsa crate: {found:#?}");
}

/// The scan finds each way back to the `rsa` crate: the key generation and
/// the login of podssh before T-257, a second way to russh's signing, the
/// crate itself, and an RSA key of russh's own generator.
#[test]
fn no_rsa_private_key_operation_finds_each_plant() {
    let planted = [
        (
            "podssh-ssh/src/keygen.rs",
            "        KeyKind::Rsa(bits) => RsaKeypair::random(&mut rng, bits).map(PrivateKey::from),",
        ),
        (
            "podssh-ssh/src/keys.rs",
            "        let call = handle.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash));",
        ),
        (
            "podssh-ssh/src/rsa_key.rs",
            "Ok(PrivateKeyWithHashAlg::new(Arc::new(key), hash))\nlet again = PrivateKeyWithHashAlg::new(k, None);",
        ),
        ("podssh-ssh/src/keys.rs", "use rsa::pkcs1v15::SigningKey;"),
        ("podssh-ssh/src/keys.rs", "let key = rsa::RsaPrivateKey::new(&mut rng, 2048)?;"),
        ("podssh-ssh/src/keygen.rs", "PrivateKey::random(&mut rng, Algorithm::Rsa { hash: None })"),
        ("podssh-cli/src/agent/keys.rs", "use podssh_ssh::russh::keys::agent::server;"),
        ("podssh-ssh/src/keys.rs", "let signature = signature::Signer::try_sign(&key, &data)?;"),
    ];
    for (name, text) in planted {
        assert!(!scan(name, text).is_empty(), "the scan missed, in {name}: {text}");
    }
    // What the source is allowed: aws-lc-rs's module, a comment, and the
    // verifier's own file.
    for (name, text) in [
        ("podssh-ssh/src/rsa_key.rs", "use aws_lc_rs::rsa::{KeyPair, KeySize};"),
        ("podssh-ssh/src/keys.rs", "// the `rsa` crate's RsaKeypair::random signs nothing here"),
        ("podssh-ws/src/crypto/rsa_sig.rs", "use rsa::{Pkcs1v15Sign, Pss, RsaPublicKey};"),
    ] {
        assert!(scan(name, text).is_empty(), "the scan refused, in {name}: {text}");
    }
}
