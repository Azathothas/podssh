//! The little DER that the road needs (X.690), by hand, as podssh reads a
//! certificate's dates elsewhere: the public key of a certificate, to pin
//! the endpoint's; a P-256 key as a SubjectPublicKeyInfo, which the API
//! enrols; and the device's certificate, self-signed, as usque makes it
//! with Go's `x509.CreateCertificate` and an empty template (its
//! `internal/utils.go`, `GenerateCert`): version 3, serial 0, an empty
//! issuer and subject, a day of validity, no extension, ECDSA with SHA-256.

/// The tags of the elements written or read here.
pub const SEQUENCE: u8 = 0x30;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const VERSION_TAG: u8 = 0xa0;

/// The contents of the AlgorithmIdentifier of a P-256 key: id-ecPublicKey
/// (1.2.840.10045.2.1) and prime256v1 (1.2.840.10045.3.1.7); rustls's
/// `alg_id::ECDSA_P256` holds the same bytes (a test reads it).
pub const EC_P256_ALG: [u8; 19] = [
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];
/// The contents of the AlgorithmIdentifier of ecdsa-with-SHA256
/// (1.2.840.10045.4.3.2), with no parameters (RFC 5758, section 3.2).
pub const ECDSA_SHA256_ALG: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// An element at the start of `der`: its tag, its contents, and the rest. A
/// length of more than four bytes, or one past the end, is no element.
pub fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..0x80 => (first as usize, rest),
        0x81..=0x84 => {
            let n = (first & 0x7f) as usize;
            let bytes = rest.get(..n)?;
            (bytes.iter().fold(0usize, |len, byte| (len << 8) | *byte as usize), &rest[n..])
        }
        _ => return None,
    };
    let contents = rest.get(..len)?;
    Some((tag, contents, &rest[len..]))
}

/// The whole encoding of the element at the start of `der`, its tag and
/// length included, and the rest.
pub fn whole(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_, _, rest) = element(der)?;
    Some((&der[..der.len() - rest.len()], rest))
}

/// The TBSCertificate's elements up to the subject's public key: past the
/// version, when there is one, the serial, the signature's algorithm, the
/// issuer, the validity and the subject (RFC 5280, section 4.1).
fn tbs_fields(cert: &[u8]) -> Option<[&[u8]; 6]> {
    let (SEQUENCE, certificate, _) = element(cert)? else { return None };
    let (SEQUENCE, mut tbs, _) = element(certificate)? else { return None };
    if element(tbs)?.0 == VERSION_TAG {
        tbs = element(tbs)?.2;
    }
    let mut fields = [&[][..]; 6];
    for field in &mut fields {
        let (encoded, rest) = whole(tbs)?;
        *field = encoded;
        tbs = rest;
    }
    Some(fields)
}

/// A certificate's SubjectPublicKeyInfo, whole.
pub fn spki_of_certificate(cert: &[u8]) -> Option<&[u8]> {
    let [.., spki] = tbs_fields(cert)?;
    (element(spki)?.0 == SEQUENCE).then_some(spki)
}

/// The point of a P-256 key in its SubjectPublicKeyInfo, as SEC1 encodes
/// it; `None` for a key of another kind.
pub fn p256_point(spki: &[u8]) -> Option<&[u8]> {
    let (SEQUENCE, contents, _) = element(spki)? else { return None };
    let (SEQUENCE, algorithm, rest) = element(contents)? else { return None };
    let (BIT_STRING, bits, _) = element(rest)? else { return None };
    let (&unused, point) = bits.split_first()?;
    (algorithm == &EC_P256_ALG[..] && unused == 0).then_some(point)
}

/// A tag, its length and its contents.
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    match len {
        0..0x80 => out.push(len as u8),
        0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
        _ => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(contents);
    out
}

/// The SubjectPublicKeyInfo of a P-256 key, from its SEC1 point.
pub fn spki_p256(point: &[u8]) -> Vec<u8> {
    let algorithm = tlv(SEQUENCE, &EC_P256_ALG);
    let key = tlv(BIT_STRING, &[&[0u8][..], point].concat());
    tlv(SEQUENCE, &[algorithm, key].concat())
}

/// A time as X.509 writes it: UTCTime through 2049, GeneralizedTime after
/// (RFC 5280, section 4.1.2.5), from seconds since the Unix epoch.
pub fn time(secs: i64) -> Vec<u8> {
    let (y, m, d) = podssh_ws::clock::civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    let clock = format!("{m:02}{d:02}{:02}{:02}{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60);
    if (1950..2050).contains(&y) {
        tlv(UTC_TIME, format!("{:02}{clock}", y % 100).as_bytes())
    } else {
        tlv(GENERALIZED_TIME, format!("{y:04}{clock}").as_bytes())
    }
}

/// The device's certificate over `spki`, valid from `not_before` to
/// `not_after`, signed by `sign` (ECDSA with SHA-256, in DER) over its
/// TBSCertificate.
pub fn self_signed(spki: &[u8], not_before: i64, not_after: i64, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let algorithm = tlv(SEQUENCE, &ECDSA_SHA256_ALG);
    let tbs = tlv(
        SEQUENCE,
        &[
            tlv(VERSION_TAG, &tlv(INTEGER, &[2])),
            tlv(INTEGER, &[0]),
            algorithm.clone(),
            tlv(SEQUENCE, &[]),
            tlv(SEQUENCE, &[time(not_before), time(not_after)].concat()),
            tlv(SEQUENCE, &[]),
            spki.to_vec(),
        ]
        .concat(),
    );
    let signature = tlv(BIT_STRING, &[&[0u8][..], &sign(&tbs)].concat());
    tlv(SEQUENCE, &[tbs, algorithm, signature].concat())
}

/// The issuer of a certificate in a few words, for a line that names a
/// proxy which re-terminates TLS: its common name and organization, as
/// text safe for a terminal; "an unnamed issuer" when it has neither.
pub fn issuer_words(cert: &[u8]) -> String {
    let words = tbs_fields(cert).map(|[_, _, issuer, ..]| name_words(issuer)).unwrap_or_default();
    if words.is_empty() {
        "an unnamed issuer".to_string()
    } else {
        podssh_ws::text::one_line(&words)
    }
}

/// `CN=..., O=...` of a Name: each attribute of the two types, in order.
fn name_words(name: &[u8]) -> String {
    const CN: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];
    const O: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x0a];
    let Some((SEQUENCE, mut sets, _)) = element(name) else { return String::new() };
    let mut words = Vec::new();
    while let Some((_, set, rest)) = element(sets) {
        sets = rest;
        let Some((SEQUENCE, pair, _)) = element(set) else { continue };
        let Some((oid, rest)) = whole(pair) else { continue };
        let Some((_, value, _)) = element(rest) else { continue };
        let label = if oid == &CN[..] {
            "CN"
        } else if oid == &O[..] {
            "O"
        } else {
            continue;
        };
        words.push(format!("{label}={}", String::from_utf8_lossy(value)));
    }
    words.join(", ")
}

/// DER as PEM with `label`, in lines of 64 characters.
pub fn pem(der: &[u8], label: &str) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in text.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The DER of the first PEM block of `label` in `text`.
pub fn from_pem(text: &str, label: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let (_, after) = text.split_once(&begin)?;
    let (body, _) = after.split_once(&end)?;
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two algorithms are the bytes of rustls's own identifiers.
    #[test]
    fn the_algorithms_are_rustls_s() {
        assert_eq!(EC_P256_ALG.as_slice(), rustls_pki_types::alg_id::ECDSA_P256.as_ref());
        assert_eq!(ECDSA_SHA256_ALG.as_slice(), rustls_pki_types::alg_id::ECDSA_SHA256.as_ref());
    }

    /// Lengths of one, two and three bytes, each read back.
    #[test]
    fn each_length_reads_back() {
        for len in [0usize, 1, 127, 128, 255, 256, 1000, 65_535] {
            let encoded = tlv(SEQUENCE, &vec![7u8; len]);
            let (tag, contents, rest) = element(&encoded).unwrap();
            assert_eq!((tag, contents.len(), rest.len()), (SEQUENCE, len, 0), "{len}");
        }
        assert_eq!(element(&[0x30, 0x05, 1, 2]), None, "past the end");
        assert_eq!(element(&[0x30, 0x85, 0, 0, 0, 0, 1]), None, "five bytes of length");
    }

    /// The dates of RFC 5280's two forms: UTCTime through 2049.
    #[test]
    fn times_take_rfc_5280_s_two_forms() {
        assert_eq!(time(1_791_440_989), tlv(UTC_TIME, b"261008062949Z"));
        assert_eq!(time(0), tlv(UTC_TIME, b"700101000000Z"));
        // 2050-01-01T00:00:00Z.
        assert_eq!(time(2_524_608_000), tlv(GENERALIZED_TIME, b"20500101000000Z"));
    }

    /// A PEM block reads back, with its lines of 64.
    #[test]
    fn pem_reads_back() {
        let der: Vec<u8> = (0..100u8).collect();
        let text = pem(&der, "PUBLIC KEY");
        assert!(text.lines().all(|l| l.len() <= 64), "{text}");
        assert_eq!(from_pem(&format!("junk\n{text}junk"), "PUBLIC KEY"), Some(der));
        assert_eq!(from_pem(&text, "CERTIFICATE"), None);
    }
}
