//! The random source (T-064): a source that gives no bytes is an error and
//! never a panic, at each place that draws, and no other path draws. A panic
//! ends the whole process where an error ends one session. The source itself
//! and the key exchanges are `pod-tls`'s, whose tests are there.

use std::path::{Path, PathBuf};

use podssh_ws::crypto::random::OsRandom;
use podssh_ws::handshake::{generate_key_from, masking_key_from};
use podssh_ws::WsError;
use rustls::crypto::{GetRandomFailed, SecureRandom};

/// A source of rustls that gives no bytes.
#[derive(Debug)]
struct Failing;

impl SecureRandom for Failing {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        Err(GetRandomFailed)
    }
}

#[test]
fn the_websocket_keys_report_a_source_that_gives_no_bytes() {
    assert!(matches!(generate_key_from(&Failing), Err(WsError::Handshake(_))));
    assert!(matches!(masking_key_from(&Failing), Err(WsError::Frame(_))));
    assert_eq!(generate_key_from(&OsRandom).unwrap().len(), 24, "16 bytes in base64");
}

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

/// No path of the library draws in a way that can panic: no `fill_bytes(`
/// (only `try_fill_bytes(`), no generator that takes an RNG
/// (`::random(&mut`), and the OS's source in no file: each draw goes through
/// `crypto::random` of `pod-tls`. The OS's source has each name that rand
/// has given it: `OsRng` up to 0.9, `SysRng` since 0.10, and the thread's
/// generator, which reseeds from it and panics if it fails.
#[test]
fn only_the_random_module_reads_the_os_and_nothing_can_panic() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    // A scan that reads nothing passes on any tree.
    assert!(files.len() > 15, "the scan read {} files", files.len());
    let mut found = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let name = file.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
        if text.matches("fill_bytes(").count() != text.matches("try_fill_bytes(").count() {
            found.push(format!("{name}: fill_bytes("));
        }
        if text.contains("::random(&mut") {
            found.push(format!("{name}: a generator that takes an RNG"));
        }
        for source in ["OsRng", "SysRng", "rand::rng(", "thread_rng", "ThreadRng"] {
            if text.contains(source) {
                found.push(format!("{name}: {source}"));
            }
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}
