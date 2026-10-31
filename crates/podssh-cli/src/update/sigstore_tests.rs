//! The bundle of v1.0.0-beta.2's `SHA256SUMS`, as the release published it,
//! and each thing that it must refuse.

use super::*;

const SUMS: &[u8] = include_bytes!("../../tests/fixtures/update/SHA256SUMS-v1.0.0-beta.2");
const BUNDLE: &str = include_str!("../../tests/fixtures/update/SHA256SUMS-v1.0.0-beta.2.sigstore.json");
const WHO: Identity = Identity { repo: "Azathothas/podssh", tag: "v1.0.0-beta.2" };

/// `BUNDLE` with the string at `path` replaced by `with`.
fn bundle_with(path: &[&str], with: &str) -> Vec<u8> {
    let mut b: serde_json::Value = serde_json::from_str(BUNDLE).unwrap();
    let mut at = &mut b;
    for key in path {
        at = if let Ok(i) = key.parse::<usize>() { &mut at[i] } else { &mut at[*key] };
    }
    *at = serde_json::Value::String(with.into());
    serde_json::to_vec(&b).unwrap()
}

/// `text`, base64, with one bit of its byte `at` changed.
fn flipped(text: &str, at: usize) -> String {
    let mut bytes = base64::engine::general_purpose::STANDARD.decode(text).unwrap();
    bytes[at] ^= 1;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn field(path: &[&str]) -> String {
    let b: serde_json::Value = serde_json::from_str(BUNDLE).unwrap();
    let mut at = &b;
    for key in path {
        at = if let Ok(i) = key.parse::<usize>() { &at[i] } else { &at[*key] };
    }
    at.as_str().unwrap().to_string()
}

#[test]
fn the_published_bundle_signs_the_published_sums() {
    verify(BUNDLE.as_bytes(), SUMS, &WHO).expect("beta.2's bundle verifies");
}

#[test]
fn another_tag_or_another_repository_is_refused() {
    let tag = verify(BUNDLE.as_bytes(), SUMS, &Identity { tag: "v1.0.0-beta.3", ..WHO }).unwrap_err();
    assert!(
        tag.contains("not https://github.com/Azathothas/podssh/.github/workflows/release.yml@refs/tags/v1.0.0-beta.3"),
        "{tag}"
    );
    let repo = verify(BUNDLE.as_bytes(), SUMS, &Identity { repo: "someone/podssh", ..WHO }).unwrap_err();
    assert!(repo.contains("someone/podssh"), "{repo}");
}

#[test]
fn a_changed_file_is_refused() {
    let mut sums = SUMS.to_vec();
    sums[0] ^= 1;
    assert!(verify(BUNDLE.as_bytes(), &sums, &WHO).unwrap_err().contains("signs another file"));
}

#[test]
fn a_changed_signature_promise_or_body_is_refused() {
    let sig = field(&["messageSignature", "signature"]);
    let why = verify(&bundle_with(&["messageSignature", "signature"], &flipped(&sig, 20)), SUMS, &WHO).unwrap_err();
    assert!(why.contains("the file's signature"), "{why}");
    let promise_path = ["verificationMaterial", "tlogEntries", "0", "inclusionPromise", "signedEntryTimestamp"];
    let promise = field(&promise_path);
    let why = verify(&bundle_with(&promise_path, &flipped(&promise, 20)), SUMS, &WHO).unwrap_err();
    assert!(why.contains("Rekor's promise of the entry"), "{why}");
    let body_path = ["verificationMaterial", "tlogEntries", "0", "canonicalizedBody"];
    let body = field(&body_path);
    let why = verify(&bundle_with(&body_path, &flipped(&body, 40)), SUMS, &WHO).unwrap_err();
    assert!(why.contains("Rekor's promise of the entry"), "{why}");
}

#[test]
fn a_leaf_that_fulcio_did_not_sign_is_refused() {
    let leaf_path = ["verificationMaterial", "certificate", "rawBytes"];
    let leaf = field(&leaf_path);
    // A bit of the leaf's signature, near its end, changed.
    let len = base64::engine::general_purpose::STANDARD.decode(&leaf).unwrap().len();
    let why = verify(&bundle_with(&leaf_path, &flipped(&leaf, len - 10)), SUMS, &WHO).unwrap_err();
    // The chain's own words: the entry's check of the leaf, later, would
    // refuse it too, and must not be what this test reads.
    assert!(why.contains("'s signature by") && why.contains("sigstore-intermediate"), "{why}");
}
