//! No crate of this workspace carries a certificate verifier that accepts
//! each certificate, or installs one in a configuration. Such a verifier
//! turns TLS verification off, with no flag and no warning, for whoever
//! installs it. The one that prints a chain for a diagnosis lives in
//! `examples/inspect_peer_chain.rs` (T-065), so no build of a library has it.
//! The shipped configuration installs the WebPKI verifier with
//! `with_custom_certificate_verifier`, which the scan allows.

use std::path::{Path, PathBuf};

// `ServerCertVerifier for` matches an impl however the trait is named
// (`impl ServerCertVerifier for`, `impl rustls::client::danger::ServerCertVerifier for`).
const FORBIDDEN: [&str; 3] = ["ServerCertVerifier for", "set_certificate_verifier", "ServerCertVerified::assertion"];

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

/// The source files of each crate, and what of `FORBIDDEN` each one holds.
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
        let text = std::fs::read_to_string(file).unwrap();
        for pattern in FORBIDDEN {
            if text.contains(pattern) {
                let name = file.strip_prefix(crates).unwrap_or(file);
                found.push(format!("crates/{}: {pattern}", name.display()));
            }
        }
    }
    (files.len(), found)
}

#[test]
fn no_crate_accepts_each_certificate() {
    let (files, found) = hits();
    // A scan that reads nothing passes on any tree.
    assert!(files > 100, "the scan read {files} files: is it reading the workspace?");
    assert!(found.is_empty(), "a permissive verifier in the source: {found:#?}");
}

/// podssh's binary never takes a caller's TLS configuration (T-066): its
/// verifier would be one that podssh cannot check.
#[test]
fn the_binary_never_takes_a_callers_configuration() {
    let cli = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("podssh-cli").join("src");
    let mut files = Vec::new();
    rust_files(&cli, &mut files);
    // 42 files on 2026-10-09; a scan that reads nothing passes on any tree.
    assert!(files.len() > 30, "the scan read {} files of podssh-cli", files.len());
    let found: Vec<String> = files
        .iter()
        .filter(|f| {
            let text = std::fs::read_to_string(f).unwrap();
            text.contains("Trust::caller") || text.contains("Trust::Caller") || text.contains("CallerConfig")
        })
        .map(|f| f.strip_prefix(&cli).unwrap_or(f).display().to_string())
        .collect();
    assert!(found.is_empty(), "podssh-cli takes a caller's TLS configuration: {found:#?}");
}
