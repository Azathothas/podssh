//! AWS Signature Version 4 in a query string (a presigned URL), for the
//! WebSocket of EC2 Instance Connect Endpoint (T-351), as botocore's
//! `SigV4QueryAuth` signs one (`botocore/auth.py`, read on 2026-10-31): the
//! request's own parameters, then `X-Amz-Algorithm`, `X-Amz-Credential`,
//! `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders` and, for a
//! temporary credential, `X-Amz-Security-Token`, each name and value
//! escaped but for RFC 3986's unreserved characters; the canonical request
//! sorts them, signs `host` alone, and takes the hash of an empty body; the
//! signature goes last, as `X-Amz-Signature`. No I/O, and no clock: the time
//! is the caller's.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The hash of an empty body.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// What a presigned URL signs.
pub struct Presign<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    /// A temporary credential's token, which goes in the query too.
    pub session_token: Option<&'a str>,
    pub region: &'a str,
    pub service: &'a str,
    /// The `Host`, the one header that is signed.
    pub host: &'a str,
    pub path: &'a str,
    /// The request's own parameters, in their order in the URL.
    pub params: &'a [(&'a str, String)],
    /// When it is signed: `YYYYMMDDTHHMMSSZ`, as [`amz_date`] writes it.
    pub amz_date: &'a str,
    /// How long the URL is good for, in seconds.
    pub expires: u32,
}

/// `text` escaped as AWS escapes a name or a value: RFC 3986's unreserved
/// characters as they are, each other byte as `%XX`.
pub fn escape(text: &str) -> String {
    // Room for each byte escaped: no copy of a secret is left behind.
    let mut out = String::with_capacity(text.len() * 3);
    for &b in text.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `secs` since the Unix epoch as `YYYYMMDDTHHMMSSZ`.
pub fn amz_date(secs: i64) -> String {
    let (y, m, d) = crate::clock::civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

impl Presign<'_> {
    /// The date of the scope: the first eight characters of the time.
    fn date(&self) -> &str {
        self.amz_date.get(..8).unwrap_or(self.amz_date)
    }

    fn scope(&self) -> String {
        format!("{}/{}/{}/aws4_request", self.date(), self.region, self.service)
    }

    /// Each parameter of the URL but the signature, escaped: the request's
    /// own, then the signature's. They hold the credential's id and its
    /// token, so they live in memory that is wiped.
    fn pairs(&self) -> Vec<(String, Zeroizing<String>)> {
        let mut pairs: Vec<(String, Zeroizing<String>)> =
            self.params.iter().map(|(name, value)| (escape(name), Zeroizing::new(escape(value)))).collect();
        let credential = Zeroizing::new(format!("{}/{}", self.access_key_id, self.scope()));
        let mut own = vec![
            ("X-Amz-Algorithm", Zeroizing::new(ALGORITHM.to_string())),
            ("X-Amz-Credential", credential),
            ("X-Amz-Date", Zeroizing::new(self.amz_date.to_string())),
            ("X-Amz-Expires", Zeroizing::new(self.expires.to_string())),
            ("X-Amz-SignedHeaders", Zeroizing::new("host".to_string())),
        ];
        if let Some(token) = self.session_token {
            own.push(("X-Amz-Security-Token", Zeroizing::new(token.to_string())));
        }
        pairs.extend(own.into_iter().map(|(name, value)| (escape(name), Zeroizing::new(escape(&value)))));
        pairs
    }

    /// The canonical request: the method, the path, the sorted query, the
    /// one header, its name, and the hash of an empty body.
    pub fn canonical_request(&self) -> Zeroizing<String> {
        let mut pairs = self.pairs();
        pairs.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
        let query: Vec<String> = pairs.iter().map(|(name, value)| format!("{name}={}", value.as_str())).collect();
        let query = Zeroizing::new(query.join("&"));
        Zeroizing::new(format!(
            "GET\n{}\n{}\nhost:{}\n\nhost\n{EMPTY_SHA256}",
            self.path,
            query.as_str(),
            self.host.trim().to_ascii_lowercase()
        ))
    }

    /// The string to sign: the algorithm, the time, the scope, and the hash
    /// of the canonical request.
    pub fn string_to_sign(&self) -> String {
        let hash = hex(&Sha256::digest(self.canonical_request().as_bytes()));
        format!("{ALGORITHM}\n{}\n{}\n{hash}", self.amz_date, self.scope())
    }

    /// The signature, in hex: the key derived from the secret for the date,
    /// the region, the service and `aws4_request`, over the string to sign.
    pub fn signature(&self) -> String {
        let secret = Zeroizing::new(format!("AWS4{}", self.secret_access_key));
        let mut key = Zeroizing::new(hmac(secret.as_bytes(), self.date().as_bytes()));
        for part in [self.region, self.service, "aws4_request"] {
            key = Zeroizing::new(hmac(&key, part.as_bytes()));
        }
        hex(&hmac(&key, self.string_to_sign().as_bytes()))
    }

    /// The query of the presigned URL, in the order of botocore's: the
    /// request's parameters, the signature's, then the signature. It
    /// carries the credential: it is never shown.
    pub fn query(&self) -> Zeroizing<String> {
        let signature = self.signature();
        let pairs = self.pairs();
        let size = 32 + signature.len() + pairs.iter().map(|(name, value)| name.len() + value.len() + 2).sum::<usize>();
        let mut out = Zeroizing::new(String::with_capacity(size));
        for (name, value) in pairs {
            out.push_str(&name);
            out.push('=');
            out.push_str(&value);
            out.push('&');
        }
        out.push_str("X-Amz-Signature=");
        out.push_str(&signature);
        out
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
