//! The signature of a release's `SHA256SUMS` (T-375), as cosign made it in
//! the release workflow (T-211): a Sigstore bundle whose leaf certificate
//! Fulcio gave this repository's release workflow at the tag, and whose
//! signature Rekor logged. Checked here, with no network and no C: the
//! digest, the leaf's signature of the file, the leaf's chain to Fulcio's
//! root at the time that Rekor gives, the leaf's identity, Rekor's promise
//! of the entry (its signed entry timestamp), and the entry's body against
//! the file, the signature and the leaf. The roots are those of Sigstore's
//! trusted root, compiled in (`trust/`), as podssh's TLS roots are.

use base64::Engine as _;
use rustls::pki_types::SignatureVerificationAlgorithm;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// The issuer of the release workflow's token, which Fulcio writes in the
/// leaf.
pub const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Who signed: the release workflow of `repo` at the tag `tag`.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    pub repo: &'a str,
    pub tag: &'a str,
}

impl Identity<'_> {
    /// The leaf's URI, as Fulcio writes it for a workflow of GitHub Actions.
    pub fn uri(&self) -> String {
        format!("https://github.com/{}/.github/workflows/release.yml@refs/tags/{}", self.repo, self.tag)
    }
}

const FULCIO: &str = include_str!("trust/fulcio.pem");
const REKOR: &str = include_str!("trust/rekor.pem");

/// What a bundle is checked against: Fulcio's chain, from the leaf's issuer
/// to its root, each in DER, and Rekor's key (a SubjectPublicKeyInfo in DER).
#[derive(Debug, Clone)]
pub struct Roots {
    pub fulcio: Vec<Vec<u8>>,
    pub rekor: Vec<u8>,
}

impl Roots {
    /// Sigstore's, compiled in: the only roots of `podssh update`.
    pub fn sigstore() -> Roots {
        Roots::from_pem(FULCIO, REKOR)
    }

    /// The chain's certificates and Rekor's key, from PEM text.
    pub fn from_pem(fulcio: &str, rekor: &str) -> Roots {
        Roots { fulcio: pem_ders(fulcio), rekor: pem_ders(rekor).into_iter().next().unwrap_or_default() }
    }
}

/// What Rekor said of a bundle that verified: when it logged the entry, and
/// its index in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Logged {
    pub time: i64,
    pub index: i64,
}
/// The extension of Fulcio's leaf that names the token's issuer: the second
/// form, a UTF8String, and the first, the raw text.
const ISSUER_V2: &str = "1.3.6.1.4.1.57264.1.8";
const ISSUER_V1: &str = "1.3.6.1.4.1.57264.1.1";

fn b64(text: &str, what: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD.decode(text.trim()).map_err(|e| format!("{what} is not base64: {e}"))
}

fn text<'a>(v: &'a serde_json::Value, path: &[&str]) -> Result<&'a str, String> {
    let mut at = v;
    for key in path {
        at = at.get(*key).ok_or_else(|| format!("the bundle has no {}", path.join(".")))?;
    }
    at.as_str().ok_or_else(|| format!("{} is not a string", path.join(".")))
}

/// The DER of each block of a PEM text.
fn pem_ders(pem: &str) -> Vec<Vec<u8>> {
    x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()).filter_map(Result::ok).map(|p| p.contents).collect()
}

/// `signature` of `message` by the key of `key_info`, with the digest that
/// `algorithm` (an OID of `ecdsa-with-SHA*`) names.
fn ecdsa(key_info: &SubjectPublicKeyInfo<'_>, algorithm: &str, message: &[u8], signature: &[u8]) -> Result<(), String> {
    use podssh_ws::crypto::sign::{EcdsaP256Sha256, EcdsaP256Sha384, EcdsaP384Sha256, EcdsaP384Sha384};
    let curve = key_info.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok()).map(|o| o.to_id_string());
    let key = &key_info.subject_public_key.data;
    let verifier: &dyn SignatureVerificationAlgorithm = match (curve.as_deref(), algorithm) {
        (Some("1.2.840.10045.3.1.7"), "1.2.840.10045.4.3.2") => &EcdsaP256Sha256,
        (Some("1.2.840.10045.3.1.7"), "1.2.840.10045.4.3.3") => &EcdsaP256Sha384,
        (Some("1.3.132.0.34"), "1.2.840.10045.4.3.2") => &EcdsaP384Sha256,
        (Some("1.3.132.0.34"), "1.2.840.10045.4.3.3") => &EcdsaP384Sha384,
        (curve, algorithm) => return Err(format!("a key of curve {curve:?} and the algorithm {algorithm}")),
    };
    verifier.verify_signature(key, message, signature).map_err(|_| "the signature does not verify".to_string())
}

/// `cert` was signed by `issuer`, and both hold at `time`.
fn signed_by(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>, time: i64) -> Result<(), String> {
    if cert.issuer() != issuer.subject() {
        return Err(format!("{} was not issued by {}", cert.subject(), issuer.subject()));
    }
    let algorithm = cert.signature_algorithm.algorithm.to_id_string();
    ecdsa(issuer.public_key(), &algorithm, cert.tbs_certificate.as_ref(), &cert.signature_value.data)
        .map_err(|why| format!("{}'s signature by {}: {why}", cert.subject(), issuer.subject()))?;
    for c in [cert, issuer] {
        let (from, to) = (c.validity().not_before.timestamp(), c.validity().not_after.timestamp());
        if time < from || time > to {
            return Err(format!("{} did not hold when the entry was logged", c.subject()));
        }
    }
    Ok(())
}

/// The leaf's identity: code signing, its URI, and its token's issuer.
fn identity(leaf: &X509Certificate<'_>, who: &Identity<'_>) -> Result<(), String> {
    let signs = leaf.extended_key_usage().ok().flatten().is_some_and(|e| e.value.code_signing);
    if !signs {
        return Err("the leaf is not for code signing".into());
    }
    let uris: Vec<&str> = match leaf.subject_alternative_name().ok().flatten() {
        Some(san) => san
            .value
            .general_names
            .iter()
            .filter_map(|n| if let GeneralName::URI(u) = n { Some(*u) } else { None })
            .collect(),
        None => Vec::new(),
    };
    if !uris.contains(&who.uri().as_str()) {
        return Err(format!("the leaf names {uris:?}, not {}", who.uri()));
    }
    let issuer = leaf.extensions().iter().find_map(|e| match e.oid.to_id_string().as_str() {
        // A UTF8String: its tag, a length of one byte, the text.
        ISSUER_V2 if e.value.len() > 2 && e.value[0] == 0x0c => {
            Some(String::from_utf8_lossy(&e.value[2..]).into_owned())
        }
        ISSUER_V1 => Some(String::from_utf8_lossy(e.value).into_owned()),
        _ => None,
    });
    match issuer.as_deref() {
        Some(ISSUER) => Ok(()),
        other => Err(format!("the leaf's token came from {other:?}, not {ISSUER}")),
    }
}

/// Rekor's promise of the entry, checked with its key, and the entry's
/// time: its signed entry timestamp over the entry's canonical JSON.
fn rekor(entry: &serde_json::Value, key_der: &[u8]) -> Result<(Logged, serde_json::Value), String> {
    let (_, key) = SubjectPublicKeyInfo::from_der(key_der).map_err(|e| format!("Rekor's key: {e}"))?;
    let key_id = Sha256::digest(key_der);
    let log_id = b64(text(entry, &["logId", "keyId"])?, "the entry's log id")?;
    if log_id != key_id.as_slice() {
        return Err("the entry is of a log whose key is not compiled in".into());
    }
    let number = |name: &str| -> Result<i64, String> {
        let v = entry.get(name).ok_or(format!("the entry has no {name}"))?;
        v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).ok_or(format!("the entry's {name} is no number"))
    };
    let (time, index) = (number("integratedTime")?, number("logIndex")?);
    let body = text(entry, &["canonicalizedBody"])?;
    // Rekor signs the entry's JSON with its keys sorted and no spaces.
    let canonical = serde_json::json!({
        "body": body, "integratedTime": time, "logID": hex(&log_id), "logIndex": index,
    });
    let promise = b64(text(entry, &["inclusionPromise", "signedEntryTimestamp"])?, "the entry's promise")?;
    ecdsa(&key, "1.2.840.10045.4.3.2", canonical.to_string().as_bytes(), &promise)
        .map_err(|why| format!("Rekor's promise of the entry: {why}"))?;
    let body = serde_json::from_slice(&b64(body, "the entry's body")?).map_err(|e| format!("the entry's body: {e}"))?;
    Ok((Logged { time, index }, body))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `bundle` signs `artifact`, as the release workflow of `who`, by
/// Sigstore's roots.
pub fn verify(bundle: &[u8], artifact: &[u8], who: &Identity<'_>) -> Result<Logged, String> {
    verify_with(bundle, artifact, who, &Roots::sigstore())
}

/// [`verify`] by `roots`.
pub fn verify_with(bundle: &[u8], artifact: &[u8], who: &Identity<'_>, roots: &Roots) -> Result<Logged, String> {
    let b: serde_json::Value = serde_json::from_slice(bundle).map_err(|e| format!("the bundle is not JSON: {e}"))?;
    if !text(&b, &["mediaType"])?.starts_with("application/vnd.dev.sigstore.bundle") {
        return Err("not a Sigstore bundle".into());
    }
    let digest = Sha256::digest(artifact);
    // The bundle names its digest as the protobuf enum SHA2_256 does.
    if !text(&b, &["messageSignature", "messageDigest", "algorithm"])?.eq_ignore_ascii_case("sha2_256")
        || b64(text(&b, &["messageSignature", "messageDigest", "digest"])?, "the digest")? != digest.as_slice()
    {
        return Err("the bundle signs another file".into());
    }
    let signature = b64(text(&b, &["messageSignature", "signature"])?, "the signature")?;
    let material = &b["verificationMaterial"];
    let leaf_b64 = text(material, &["certificate", "rawBytes"])
        .or_else(|_| material["x509CertificateChain"]["certificates"][0]["rawBytes"].as_str().ok_or_else(String::new))
        .map_err(|_| "the bundle has no leaf certificate".to_string())?;
    let leaf_der = b64(leaf_b64, "the leaf")?;
    let (_, leaf) = X509Certificate::from_der(&leaf_der).map_err(|e| format!("the leaf: {e}"))?;
    let algorithm = if leaf
        .public_key()
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| o.to_id_string())
        .as_deref()
        == Some("1.3.132.0.34")
    {
        "1.2.840.10045.4.3.3"
    } else {
        "1.2.840.10045.4.3.2"
    };
    ecdsa(leaf.public_key(), algorithm, artifact, &signature).map_err(|why| format!("the file's signature: {why}"))?;
    let entries = material["tlogEntries"].as_array().ok_or("the bundle has no entry of Rekor")?;
    let (logged, body) = entries.iter().find_map(|e| rekor(e, &roots.rekor).ok()).map_or_else(
        || Err(entries.iter().map(|e| rekor(e, &roots.rekor).err().unwrap_or_default()).collect::<Vec<_>>().join("; ")),
        Ok,
    )?;
    let chain: Vec<X509Certificate<'_>> = roots
        .fulcio
        .iter()
        .map(|der| X509Certificate::from_der(der).map(|(_, c)| c))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("Fulcio's chain: {e}"))?;
    let Some(root) = chain.last() else { return Err("no chain of Fulcio to check the leaf by".into()) };
    // Each certificate by the next, the leaf first; the root by itself.
    let mut cert = &leaf;
    for issuer in &chain {
        signed_by(cert, issuer, logged.time)?;
        cert = issuer;
    }
    signed_by(root, root, logged.time)?;
    identity(&leaf, who)?;
    // The entry logged this file, this signature and this leaf.
    let spec = &body["spec"];
    let logged_leaf = pem_ders(&String::from_utf8_lossy(&b64(
        text(spec, &["signature", "publicKey", "content"])?,
        "the logged key",
    )?));
    if text(spec, &["data", "hash", "value"])? != hex(&digest)
        || b64(text(spec, &["signature", "content"])?, "the logged signature")? != signature
        || logged_leaf.first() != Some(&leaf_der)
    {
        return Err("Rekor's entry is of another file, signature or leaf".into());
    }
    Ok(logged)
}

#[cfg(test)]
#[path = "sigstore_tests.rs"]
mod tests;
