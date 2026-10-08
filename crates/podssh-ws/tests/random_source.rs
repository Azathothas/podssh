//! The random source (T-064): a source that gives no bytes is an error and
//! never a panic, at each place that draws, and no other path draws. A panic
//! ends the whole process where an error ends one session.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use p256::elliptic_curve::sec1::ToEncodedPoint;
use podssh_ws::crypto::kx::start_with;
use podssh_ws::crypto::random::{fill_from, OsRandom};
use podssh_ws::handshake::{generate_key_from, masking_key_from};
use podssh_ws::WsError;
use rustls::crypto::{GetRandomFailed, SecureRandom};
use rustls::NamedGroup;

/// A source of `rand` that gives no bytes. Its `fill_bytes` panics, as that
/// of `OsRng` does, so a caller that still uses it fails the test.
struct NoBytes;

impl rand::RngCore for NoBytes {
    fn next_u32(&mut self) -> u32 {
        panic!("next_u32 was called")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("next_u64 was called")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("fill_bytes was called: it panics when the OS gives no bytes")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
        Err(rand::Error::new(std::io::Error::other("no entropy")))
    }
}

/// A source of rustls that gives no bytes.
#[derive(Debug)]
struct Failing;

impl SecureRandom for Failing {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        Err(GetRandomFailed)
    }
}

/// A source that gives the same byte each time.
#[derive(Debug)]
struct Constant(u8);

impl SecureRandom for Constant {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        buf.fill(self.0);
        Ok(())
    }
}

/// A source whose first draws are 0xff (not below the order of P-256), and
/// then the OS's bytes.
#[derive(Debug)]
struct BadFirst(AtomicUsize);

impl SecureRandom for BadFirst {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let left = self.0.load(Ordering::SeqCst);
        if left > 0 {
            self.0.store(left - 1, Ordering::SeqCst);
            buf.fill(0xff);
            return Ok(());
        }
        OsRandom.fill(buf)
    }
}

#[test]
fn a_source_that_gives_no_bytes_is_an_error() {
    assert!(fill_from(&mut NoBytes, &mut [0u8; 8]).is_err());
    let mut buf = [0u8; 32];
    fill_from(&mut rand::rngs::OsRng, &mut buf).expect("the OS gives bytes here");
    assert_ne!(buf, [0u8; 32]);
}

#[test]
fn the_websocket_keys_report_a_source_that_gives_no_bytes() {
    assert!(matches!(generate_key_from(&Failing), Err(WsError::Handshake(_))));
    assert!(matches!(masking_key_from(&Failing), Err(WsError::Frame(_))));
    assert_eq!(generate_key_from(&OsRandom).unwrap().len(), 24, "16 bytes in base64");
}

#[test]
fn each_key_exchange_reports_a_source_that_gives_no_bytes() {
    for group in [NamedGroup::X25519, NamedGroup::secp256r1] {
        let error = start_with(group, &Failing).err().expect("no bytes, no key exchange");
        assert_eq!(error, rustls::Error::FailedToGetRandomBytes, "{group:?}");
    }
}

/// A draw of P-256 that is zero or not below the order is drawn again; a
/// source that gives only such draws fails as one that gives none.
#[test]
fn p256_draws_again_when_a_draw_is_out_of_range() {
    for byte in [0x00, 0xff] {
        let error = start_with(NamedGroup::secp256r1, &Constant(byte)).err().expect("no usable draw");
        assert_eq!(error, rustls::Error::FailedToGetRandomBytes, "{byte:#x}");
    }
    let source = BadFirst(AtomicUsize::new(3));
    assert!(start_with(NamedGroup::secp256r1, &source).is_ok());
    assert_eq!(source.0.load(Ordering::SeqCst), 0, "three draws were refused first");
}

/// podssh's P-256 exchange agrees with `p256`'s own `EphemeralSecret`, which
/// podssh did not write, on the shared secret.
#[test]
fn p256_agrees_with_an_exchange_that_podssh_did_not_write() {
    let theirs = p256::ecdh::EphemeralSecret::random(&mut rand::rngs::OsRng);
    let their_public = theirs.public_key().to_encoded_point(false);
    let ours = start_with(NamedGroup::secp256r1, &OsRandom).unwrap();
    let our_public = p256::PublicKey::from_sec1_bytes(ours.pub_key()).expect("an uncompressed point");
    let shared = ours.complete(their_public.as_bytes()).expect("a valid share");
    assert_eq!(shared.secret_bytes(), theirs.diffie_hellman(&our_public).raw_secret_bytes().as_slice());
}

#[test]
fn x25519_agrees_with_itself() {
    let a = start_with(NamedGroup::X25519, &OsRandom).unwrap();
    let b = start_with(NamedGroup::X25519, &OsRandom).unwrap();
    let (pa, pb) = (a.pub_key().to_vec(), b.pub_key().to_vec());
    assert_eq!(a.complete(&pb).unwrap().secret_bytes(), b.complete(&pa).unwrap().secret_bytes());
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
/// (`::random(&mut`), and `OsRng` only in `crypto/random.rs`.
#[test]
fn only_the_random_module_reads_the_os_and_nothing_can_panic() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    // 23 files on 2026-10-09; a scan that reads nothing passes on any tree.
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
        if text.contains("OsRng") && name != "crypto/random.rs" {
            found.push(format!("{name}: OsRng"));
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}
