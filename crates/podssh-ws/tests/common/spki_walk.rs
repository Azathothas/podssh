// **A TLV walk over a certificate, shared by every test that reads one.**
// `include!`d by `certificate_structure.rs` and, for the `which_signature_is
// _failing` diagnostic, by `hostname_verification.rs`.
//
// **A walk, not a byte-pattern search.** MEASURED 2026-10-02: an earlier
// version searched for `03 48 00` to find the `signatureValue` BIT STRING and
// panicked with *"the signature BIT STRING"* — while every other test in the
// binary passed. A DER `SEQUENCE` inside an ECDSA signature varies in length
// from signing to signing, because ECDSA's `s` is randomised, so a fixed
// length is right only about half the time. That is the worst shape of test
// failure available: a defect in the *test*, reported as a missing field in
// the *certificate*, one run in two.
//
// Every offset here is relative to the buffer it was found in, and the
// buffer is named at each step. MEASURED 2026-10-02: a version mixed a
// range from one buffer with an index into another and reported
// `left: 48, right: 163` — a signature BIT STRING's tag read at the
// extensions' offset — which reads as a malformed certificate rather than as
// two coordinate systems.

use std::ops::Range;

// The walk is `include!`d inside `mod walk { .. }` in `certificate_structure.rs`,
// whose sibling `mod cert` re-exports the encoding helpers, so the path from
// here is `super::cert::encoding::read_len`.
use super::cert::encoding::read_len;

/// The `subjectPublicKey` exactly as webpki hands it to a verification
/// algorithm: the SPKI BIT STRING's **content**, unused-bits byte included.
/// MEASURED 2026-10-02: the leading `0x04` that used to be stripped here is
/// what `from_sec1_bytes` parses, and stripping it is what made every
/// handshake answer `BadSignature`. The byte before it is the BIT STRING's
/// unused-bit count, which webpki consumes and does not forward.
pub fn spki_point(der: &[u8]) -> Vec<u8> {
    let (tbs_contents, _) = read_sequence(der, 0);
    let (inner_contents, _) = read_sequence(&tbs_contents, 0);
    let fields = tlv_fields(&inner_contents, "a tbsCertificate");

    // **The SPKI is the field IMMEDIATELY BEFORE the subjectPublicKeyInfo
    // position, not "the last field".** TBSCertificate is
    // version, serialNumber, signature, issuer, validity, subject, spki, and
    // then the OPTIONAL [1] issuerUniqueID, [2] subjectUniqueID and [3]
    // extensions. An anchor here carries no SAN, so it has extensions but
    // fewer of them, and "the field before the last one" returned the validity
    // or the subject instead of the key — which is why the extracted point did
    // not match the one the builder published and every signature check failed.
    //
    // MEASURED 2026-10-02: the anchor's extracted point began
    // `04c44d47bc347c0d` where the published one began `f6aa2122a80fb2d6`.
    // Counting from the end of the REQUIRED fields is position 6 and does
    // not move when optional fields are added, which is the property a walk
    // needs.
    const SPKI_FIELD: usize = 6;
    assert!(
        fields.len() > SPKI_FIELD,
        "a tbsCertificate has a subjectPublicKeyInfo at field {SPKI_FIELD}"
    );
    eprintln!(
        "TBS-FIELDS {} tags {:?}",
        fields.len(),
        fields
            .iter()
            .map(|f| inner_contents[f.1.start])
            .collect::<Vec<u8>>()
    );
    let (spki_contents, _) = read_sequence(&inner_contents, fields[SPKI_FIELD].1.start);
    let inner = tlv_fields(&spki_contents, "a SubjectPublicKeyInfo");
    assert_eq!(inner.len(), 2, "an SPKI is an AlgorithmIdentifier and a key");
    inner[1].0.clone()
}

/// The 65-byte SEC1 encoding webpki ends up passing: the BIT STRING's content
/// with the unused-bits byte removed.
pub fn sec1_point(content: &[u8]) -> Vec<u8> {
    content[1..].to_vec()
}

/// A BIT STRING's bytes, minus the unused-bits count that leads it.
pub fn bitstring_bytes(content: &[u8], what: &str) -> Vec<u8> {
    assert_eq!(content[0], 0, "{what} has unused bits");
    content[1..].to_vec()
}

/// The `signatureValue` BIT STRING's bytes: the last element of the
/// certificate, reached by parsing the certificate rather than by searching it.
pub fn signature_of(der: &[u8]) -> Vec<u8> {
    let (contents, _) = read_sequence(der, 0);
    let fields = tlv_fields(&contents, "a certificate");
    assert_eq!(fields.len(), 3, "a certificate has three fields");
    bitstring_bytes(&fields[2].0, "the signatureValue")
}

/// The `tbsCertificate` TLV, exactly as `untrusted::Reader::read_partial`
/// reports it consumed — header included.
pub fn tbs_tlv_of(der: &[u8]) -> Vec<u8> {
    let (contents, _) = read_sequence(der, 0);
    let (_, after_tbs) = read_sequence(&contents, 0);
    // **The header is part of what was signed.** `read_sequence` hands back
    // the content, which is one thing a helper can reasonably return and the
    // one thing a signature must not be computed over: webpki passes the bytes
    // `read_partial` reports consumed, and that is the whole TLV.
    // MEASURED 2026-10-02: returning the content instead made the extracted
    // tbs 248 bytes beginning `a0 03 02 01 02` where the builder's begins
    // `30 82 00 f4` — an extraction defect and a builder defect producing one
    // identical `BadSignature`.
    contents[..after_tbs].to_vec()
}

/// `der[at..]`, asserted to be a SEQUENCE: returns its content and the offset
/// just past it.
pub fn read_sequence(der: &[u8], at: usize) -> (Vec<u8>, usize) {
    assert_eq!(der[at], 0x30, "expected a SEQUENCE at offset {at}");
    let (len, start) = read_len(der, at + 1);
    (der[start..start + len].to_vec(), start + len)
}

/// Split a concatenation of TLVs, returning each value's content and the range
/// its TLV occupies **within `contents`**. Panics rather than guessing: a
/// helper that returns a default offset produces a test that passes for the
/// wrong reason.
pub fn tlv_fields(contents: &[u8], what: &str) -> Vec<(Vec<u8>, Range<usize>)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < contents.len() {
        let (len, start) = read_len(contents, at + 1);
        let end = start + len;
        assert!(end <= contents.len(), "{what} overruns its container");
        out.push((contents[start..end].to_vec(), at..end));
        at = end;
    }
    out
}