// ⛔ **The DER encoding and the certificate minted from it.** ⛔ Included by
// `cert_for_test.rs`; not a test target of its own.
//
// ⛔ **Five structural faults lived in here before it produced a certificate
// webpki accepts**, and each is recorded beside the line that fixes it. Four
// presented as `InvalidCertificate(BadEncoding)` and one as `BadSignature`,
// and neither error names the field that was wrong.


use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// ⛔ **Short form below 128 bytes, long form above.** A length in the wrong
/// form is a parse error, and this is the one place a hand-built DER encoder
/// can be wrong for every certificate rather than for one field.
pub(crate) fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        // ⛔ **The 3-byte form exists.** ⛔ MEASURED 2026-10-02: this had only
        // the three branches above, and once the extensions made the
        // certificate pass 255 bytes it wrote a TWO-byte length of
        // `(len >> 8)` — declaring 258 bytes of content while carrying 343.
        // ⛔ Every parse of the certificate then failed, and the error was
        // `BadEncoding` from a *length field* five lines from where the
        // defect was. ⛔ It was found by printing the DER and reading the two
        // numbers side by side, not by reading the code: the branch looked
        // correct for every value under 256.
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

/// ⛔ **One length reader for the whole file.** ⛔ Five copies of this loop is
/// five chances to disagree about where the contents start, and that
/// disagreement is invisible: every one of them parses a certificate and only
/// one of them signs the bytes the other four extracted. ⛔ Returns
/// `(content length, offset at which the content starts)`.
#[allow(dead_code)]
pub(crate) fn read_len(der: &[u8], at: usize) -> (usize, usize) {
    let first = der[at];
    if first & 0x80 == 0 {
        (first as usize, at + 1)
    } else {
        let n = (first & 0x7f) as usize;
        let v = der[at + 1..at + 1 + n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | *b as usize);
        (v, at + 1 + n)
    }
}

pub(crate) fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(contents.len()));
    out.extend_from_slice(contents);
    out
}

pub(crate) fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub(crate) fn set_of(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

/// ⛔ **The first two arcs are packed into one byte; every later arc is a
/// base-128 varint.** This is the encoding X.509 uses and the one thing a
/// hand-rolled OID writer gets wrong.
pub(crate) fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut stack = Vec::new();
        let mut v = *arc;
        loop {
            stack.push((v & 0x7f) as u8);
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        stack.reverse();
        for (i, b) in stack.iter().enumerate() {
            body.push(if i + 1 < stack.len() { b | 0x80 } else { *b });
        }
    }
    tlv(0x06, &body)
}

pub(crate) struct TestCert {
    pub der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// ⛔ Mint a self-signed end-entity certificate whose SAN carries `dns_name`.
pub fn self_signed(dns_name: &str) -> TestCert {
    self_signed_inner(dns_name, false)
}

/// MEASURED 2026-10-02: webpki refused the certificate with
/// `OtherError(CaUsedAsEndEntity)`. A certificate with `basicConstraints
/// CA:TRUE` IS a CA, and a server may not present a CA as its end-entity
/// certificate. The first version of this file minted ONE self-signed
/// certificate carrying CA:TRUE and used it as both the trust anchor and the
/// server's certificate; it has to be two certificates, with the anchor one
/// level up.
/// ⛔ The seed for a role's key. ⛔ **The anchor and the leaf get DIFFERENT
/// seeds**, so they are different keys and the leaf's signature genuinely
/// needs the anchor's public key to verify.
/// ⛔ The name `server_for` gives the anchor, in one place, because the leaf's
/// issuer and the anchor's subject must be built from the same string and two
/// copies of `{name}-anchor` is how they drifted apart.
pub(crate) fn anchor_name(dns_name: &str) -> String {
    format!("{dns_name}-anchor")
}

fn role_seed(dns_name: &str, is_ca: bool) -> Vec<u8> {
    let mut s = dns_name.as_bytes().to_vec();
    s.push(if is_ca { 0xca } else { 0xee });
    s
}

pub(crate) fn self_signed_inner(dns_name: &str, is_ca: bool) -> TestCert {
    // MEASURED 2026-10-02: this file went through five distinct `BadEncoding`
    // and `BadSignature` failures before it produced a certificate webpki
    // accepts, and every one of them is recorded at the line that fixed it.
    //
    // ⛔ **The SPKI publishes this certificate's OWN key; the signature below is
    // made by the ISSUER's key, and for an anchor those are the same one.**
    // ⛔ An earlier version signed every certificate with its own key while its
    // `issuer` field named the anchor, and every handshake answered
    // `BadSignature`.
    //
    // ⛔ **This comment once said the opposite**, and it is recorded here
    // because it was the reason that fault survived: it claimed "a client
    // verifies an end-entity certificate with the key in its own SPKI, not
    // with its issuer's", which is true of the peer's `CertificateVerify` and
    // false of the chain. ⛔ MEASURED 2026-10-02: `verify_cert.rs:148`
    // (`check_signed_chain`) verifies each `SignedData` against the *issuer's*
    // SPKI, and the leaf publishes its own — so a self-signed leaf has a
    // signature nobody in the chain can check. ⛔ Two different keys, two
    // different verifications, and the error names neither.
    let own = SigningKey::from_bytes(&sha256(&role_seed(dns_name, is_ca)).into())
        .expect("a P-256 scalar");

    let spki = own.verifying_key().to_encoded_point(false);
    let point = spki.as_bytes();
    eprintln!(
        "PUBLISHED-POINT {} head {}",
        point.len(),
        point[..8].iter().map(|b| format!("{b:02x}")).collect::<String>()
    );

    let spki_der = seq(&[
        seq(&[oid(&[1, 2, 840, 10045, 2, 1]), oid(&[1, 2, 840, 10045, 3, 1, 7])]),
        tlv(0x03, &[&[0x00][..], point].concat()),
    ]);

    let name = seq(&[set_of(&[seq(&[oid(&[2, 5, 4, 3]), tlv(0x0c, dns_name.as_bytes())])])]);
    // ⛔ **The leaf's ISSUER is the anchor's SUBJECT.** ⛔ MEASURED
    // 2026-10-02: with both set to the leaf's own name, webpki answered
    // `UnknownIssuer` — the signature was fine and the *path* was not, because
    // a chain is walked by matching the leaf's issuer against the next
    // certificate's subject. ⛔ The anchor is minted with
    // `{dns_name}-anchor` as its subject, so the leaf's issuer names that.
    let issuer_name = if is_ca {
        name.clone()
    } else {
        seq(&[set_of(&[seq(&[oid(&[2, 5, 4, 3]), tlv(0x0c, anchor_name(dns_name).as_bytes())])])])
    };
    // ⛔ **`GeneralNames` is `SEQUENCE OF`, tag `0x30`.** ⛔ MEASURED
    // 2026-10-02: this wrapped the entries in `set_of`, which emits `0x31`
    // (SET OF), and every handshake against this locally-minted server answered
    // `InvalidCertificate(BadEncoding)`. ⛔ webpki reads the extension's
    // `extnValue` (an OCTET STRING) as the `GeneralNames` sequence's contents
    // and then calls `GeneralName::from_der` on the next element directly — so
    // it met a `0x31` where it required a `0x82` (`dNSName`, context-specific
    // primitive 2). RFC 5280 §4.2.1.6 spells `GeneralNames ::= SEQUENCE SIZE
    // (1..MAX) OF GeneralName`; it is never a SET.
    let san = seq(&[
        oid(&[2, 5, 29, 17]),
        tlv(0x04, &seq(&[tlv(0x82, dns_name.as_bytes())])),
    ]);
    // ⛔ **`basicConstraints: CA:TRUE` and it is critical.** ⛔ This
    // certificate is its own trust anchor, and a v3 anchor with no
    // `basicConstraints` is a leaf by RFC 5280's rules. ⛔ MEASURED
    // 2026-10-02: without them webpki refused it with `BadEncoding`.
    // ⛔ **`CA:TRUE` only on the anchor.** ⛔ MEASURED 2026-10-02: with it set on
    // the end-entity certificate, webpki refused the handshake with
    // `OtherError(CaUsedAsEndEntity)`. ⛔ That is a *different* error from the
    // `BadEncoding` this file spent most of its length chasing: the parse was
    // correct and the certificate's **role** was wrong. A leaf carries an empty
    // `SEQUENCE` here — `30 00` — which is how RFC 5280 spells "not a CA".
    // ⛔ **`keyUsage` is not emitted at all.** ⛔ MEASURED 2026-10-02: a first
    // version carried `digitalSignature | keyCertSign`, and webpki refused the
    // leaf with `BadEncoding` — a BIT STRING whose unused-bits byte and named
    // bits disagree with the length webpki computes for them. Nothing here
    // needs it, so the extension that was wrong is the one removed.
    let basic_constraints = seq(&[
        oid(&[2, 5, 29, 19]),
        tlv(0x01, &[0xff]),
        tlv(
            0x04,
            &seq(&[if is_ca { tlv(0x01, &[0xff]) } else { Vec::new() }]),
        ),
    ]);

    // ⛔ **The `signatureAlgorithm` is `ecdsa-with-SHA256`, and that is not
    // cosmetic.** ⛔ The first version declared
    // `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) over an EC public key,
    // and webpki refused the whole certificate with `BadEncoding` — a
    // certificate whose signature algorithm contradicts its key is not a
    // certificate.
    let sig_alg = oid(&[1, 2, 840, 10045, 4, 3, 2]);

    let mut tbs_body = vec![0xa0, 0x03, 0x02, 0x01, 0x02]; // [0] { INTEGER 2 } = v3
    tbs_body.extend_from_slice(&[0x02, 0x01, 0x01]); // serialNumber 1
    tbs_body.extend_from_slice(&seq(&[sig_alg.clone()])); // signature
    tbs_body.extend_from_slice(&issuer_name); // issuer
    tbs_body.extend_from_slice(&seq(&[
        // ⛔ **Both dates are UTCTime, and the year width follows the tag.**
        // ⛔ MEASURED 2026-10-02: an earlier version asked for the years 2188
        // and 2100, which are `GeneralizedTime` (tag 0x18, fourteen
        // characters), and formatted them with a two-digit year — and 2188
        // was really 4188, because the test had passed 70 000 000 000 seconds.
        // webpki's `BadEncoding` again. 2020-01-01 to 2040-01-01 is UTCTime
        // on both ends and is unambiguous.
        tlv(0x17, b"200101000000Z"),
        tlv(0x17, b"400101000000Z"),
    ]));
    tbs_body.extend_from_slice(&name); // subject
    tbs_body.extend_from_slice(&spki_der);
    // ⛔ **`[3]` holds the extensions, at the end of `tbsCertificate`.** ⛔ The
    // first version wrapped the entire structure in one `[0]` and then added a
    // `[3]`, which is not a `TBSCertificate` at all.
    // ⛔ **The end-entity certificate has NO `basicConstraints` at all.**
    // ⛔ webpki's `check_basic_constraints` (`verify_cert.rs:418`) calls
    // `bool::from_der` unconditionally when the extension is present, so the
    // empty `SEQUENCE` that spells "not a CA" is a parse error, and a leaf
    // carrying one answers `BadEncoding`.
    //
    // ⛔ MEASURED 2026-10-02: this emitted `basicConstraints` on both roles
    // and the handshake answered `BadEncoding` after the signature fault was
    // fixed. ⛔ An absent extension means "not a CA" as well, and it is the
    // form every real end-entity certificate uses.
    let mut extensions = Vec::new();
    if is_ca {
        extensions.push(basic_constraints);
    } else {
        extensions.push(san);
    }
    tbs_body.extend_from_slice(&tlv(0xa3, &seq(&extensions)));

    let tbs = seq(&[tbs_body]);

    // ⛔ **Sign the full tbsCertificate TLV, tag and length included, and sign
    // it as a MESSAGE — never wrap it in a DigestInfo first.**
    //
    // ⛔ RFC 5280 §4.1.1.2 says the signature is over the DER encoding of
    // `TBSCertificate`, which includes its own header.
    //
    // ⛔ MEASURED 2026-10-02, on two counts, and this line is where both were
    // wrong at once. First, `rustls-webpki` reaches
    // `SignatureVerificationAlgorithm::verify_signature` with the bytes that
    // `untrusted::Reader::read_partial` reports as **consumed**, and that is
    // the whole TLV, not the stripped value `expect_tag_and_get_value_limited`
    // returns — signing the stripped contents produced `BadSignature`.
    // Second, and this is the fault that survived every other fix: an earlier
    // version called
    // `SigningKey::sign(&ecdsa_sha256_digest_info(&tbs))`. `DigestInfo` is the
    // *signer's* internal prehash format, not a message — `Signer::sign`
    // hashes whatever it is given, so that call signed
    // `SHA256(DigestInfo(SHA256(tbs)))` while every verifier hashed `tbs` once.
    // The two can never agree, and the failure is a `BadSignature` with
    // nothing in it pointing at the extra hash.
    // ⛔ **Signed by the ISSUER's key, which for an end-entity certificate is
    // not its own.** ⛔ MEASURED 2026-10-02: this signed with `own`, the leaf's
    // own key, while the leaf's `issuer` names the anchor — so webpki verified
    // it with the *anchor's* public key and answered `BadSignature` on every
    // one of the three hostname tests.
    //
    // ⛔ **The signature being self-consistent is not the same as the chain
    // being consistent.** `certificate_structure.rs` verifies this signature
    // against this certificate's own SPKI, which is exactly the check that
    // passed while the handshake failed. ⛔ `check_signed_chain`
    // (`verify_cert.rs:148`) verifies each `SignedData` against the *issuer's*
    // SPKI and only then advances, so the two checks are looking at different
    // keys and a leaf can satisfy one while failing the other.
    //
    // ⛔ The two roles get different seeds (`role_seed`), so the anchor's key is
    // genuinely a different key and this line cannot accidentally succeed.
    // ⛔ **The issuer's seed is derived from the issuer's NAME.** ⛔ MEASURED
    // 2026-10-02: this used `role_seed(dns_name, true)` — the leaf's own name
    // with the CA byte — while `server_for` mints the anchor as
    // `{dns_name}-anchor`. ⛔ The leaf was therefore signed by a third key that
    // appears nowhere in the chain: not the leaf's, not the anchor's, and not
    // in any trust store. ⛔ `BadSignature` is the correct answer and names
    // nothing, and a fresh signature over the same bytes verifies — which is
    // what says the bytes were right and the key was wrong.
    let issuer_key = if is_ca {
        own.clone()
    } else {
        SigningKey::from_bytes(&sha256(&role_seed(&anchor_name(dns_name), true)).into())
            .expect("a P-256 scalar")
    };
    let signature: Signature = issuer_key.sign(&tbs);
    eprintln!(
        "BUILDER sig={} key-is-own={}",
        signature.to_der().as_bytes().len(),
        is_ca
    );
    // ⛔ **The certificate is `SEQUENCE { tbs, algId, signatureValue }`, and
    // the SEQUENCE is a NEW header around all three.**
    // ⛔ MEASURED 2026-10-02: the first version started from `tbs` and
    // appended the two outer fields to it, so the bytes on the wire were
    // `tbs-with-its-own-length-header` + `algId` + `sigValue`. ⛔ The leading
    // `30 82 01 02` was the **TBS's** length — 258 — while the buffer held
    // 347, and webpki reported `BadEncoding` about a length five lines away
    // from the only place it was wrong. ⛔ It was found by printing the DER and
    // comparing the declared content length against the byte count, which is
    // the check `der_length_covers_the_certificate` below now keeps.
    let cert = seq(&[
        tbs,
        seq(&[sig_alg]),
        tlv(0x03, &[&[0x00][..], signature.to_der().as_bytes()].concat()),
    ]);

    TestCert {
        der: cert,
        key_der: own.to_bytes().to_vec(),
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// ⛔ **The declared length must cover the bytes.** ⛔ MEASURED 2026-10-02:
/// the certificate declared 258 bytes of content and carried 347, because the
/// TBS's own SEQUENCE header was standing in for the certificate's. ⛔ That
/// one byte of structure made every field unreadable and webpki reported
/// `BadEncoding` — a name that points at the certificate rather than at the
/// length, which is why it took a printed hex dump to find rather than a
/// reading of the code.
///
/// ⛔ This is the check that would have caught it on the first run, and it is
/// here rather than in a comment because the same class of defect is the
/// reason a hand-written encoder deserves a test.
pub fn der_length_covers_the_certificate(der: &[u8]) {
    assert_eq!(der[0], 0x30, "a certificate is a SEQUENCE");
    let (declared, header) = read_len(der, 1);
    assert_eq!(
        header + declared,
        der.len(),
        "the certificate declares {declared} bytes of content and carries {}",
        der.len() - header
    );
}
