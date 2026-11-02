//! The account's key and its signatures (RFC 8555, section 6.2; RFC 7515):
//! ES256 with a P-256 key of aws-lc-rs, the JWK of its public half, and its
//! thumbprint (RFC 7638), which each key authorization ends with.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::Digest as _;
use zeroize::Zeroizing;

/// The account's key: a P-256 key that signs each request to the CA.
pub struct Account {
    pkcs8: Zeroizing<Vec<u8>>,
    /// Signs in the fixed form of JWS, r and s of 32 bytes each.
    pair: EcdsaKeyPair,
    x: String,
    y: String,
}

/// Base64url with no padding, as JOSE writes each part.
pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

impl Account {
    /// A new key, from the system's source of randomness.
    pub fn generate() -> Result<Account, String> {
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .map_err(|_| "no P-256 key could be made for the account".to_string())?;
        Account::from_pkcs8(document.as_ref())
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<Account, String> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
            .map_err(|e| format!("the account's key is not a P-256 key in PKCS #8: {e}"))?;
        // The uncompressed point: 0x04, then x and y of 32 bytes each.
        let point = pair.public_key().as_ref().to_vec();
        if point.len() != 65 || point[0] != 0x04 {
            return Err("the account's public key is not an uncompressed P-256 point".into());
        }
        let (x, y) = (b64url(&point[1..33]), b64url(&point[33..]));
        Ok(Account { pkcs8: Zeroizing::new(der.to_vec()), pair, x, y })
    }

    /// The key as PEM, as `account.key` keeps it.
    pub fn pem(&self) -> Zeroizing<String> {
        Zeroizing::new(super::certs::pem("PRIVATE KEY", &self.pkcs8))
    }

    /// The JWK of the public key.
    pub fn jwk(&self) -> Value {
        json!({"crv": "P-256", "kty": "EC", "x": self.x, "y": self.y})
    }

    /// The thumbprint of the JWK (RFC 7638).
    pub fn thumbprint(&self) -> String {
        thumbprint(&self.x, &self.y)
    }

    /// The key authorization of a challenge's `token` (RFC 8555, section 8.1).
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }

    /// A request's body in JWS's flattened JSON (RFC 8555, section 6.2):
    /// its key named by `kid`, the account's URL, or else given whole as a
    /// JWK, as only newAccount takes it. A `payload` of `None` is the empty
    /// one of a POST-as-GET.
    pub fn sign(&self, kid: Option<&str>, nonce: &str, url: &str, payload: Option<&Value>) -> Result<String, String> {
        let mut protected = json!({"alg": "ES256", "nonce": nonce, "url": url});
        match kid {
            Some(kid) => protected["kid"] = Value::from(kid),
            None => protected["jwk"] = self.jwk(),
        }
        let protected = b64url(protected.to_string().as_bytes());
        let payload = payload.map(|p| b64url(p.to_string().as_bytes())).unwrap_or_default();
        let signed = format!("{protected}.{payload}");
        let signature = self
            .pair
            .sign(&SystemRandom::new(), signed.as_bytes())
            .map_err(|_| "the account's key could not sign".to_string())?;
        Ok(json!({"protected": protected, "payload": payload, "signature": b64url(signature.as_ref())}).to_string())
    }
}

/// RFC 7638's thumbprint of a P-256 JWK: the SHA-256 of its required
/// members in the order of their names, with no space.
pub fn thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    b64url(&sha2::Sha256::digest(canonical.as_bytes())[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;

    fn b64url_decode(text: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text).expect("base64url")
    }

    /// The EC key of RFC 7517, appendix A.1, whose thumbprint other JOSE
    /// libraries give as this one.
    #[test]
    fn the_thumbprint_of_rfc_7517s_key_is_the_one_jose_gives() {
        let x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
        let y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
        assert_eq!(thumbprint(x, y), "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s");
    }

    /// The parts of a JWS body: its protected header and its payload,
    /// decoded, and whether the signature verifies under p256.
    fn open(body: &str, account: &Account) -> (Value, Vec<u8>, bool) {
        let jws: Value = serde_json::from_str(body).unwrap();
        let (protected, payload, signature) =
            (jws["protected"].as_str().unwrap(), jws["payload"].as_str().unwrap(), jws["signature"].as_str().unwrap());
        let header: Value = serde_json::from_slice(&b64url_decode(protected)).unwrap();
        let jwk = account.jwk();
        let mut point = vec![0x04];
        point.extend(b64url_decode(jwk["x"].as_str().unwrap()));
        point.extend(b64url_decode(jwk["y"].as_str().unwrap()));
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
        let signature = p256::ecdsa::Signature::from_slice(&b64url_decode(signature)).expect("r and s, 64 bytes");
        let good = key.verify(format!("{protected}.{payload}").as_bytes(), &signature).is_ok();
        (header, b64url_decode(payload), good)
    }

    #[test]
    fn a_request_is_signed_es256_with_its_nonce_url_and_key() {
        let account = Account::generate().unwrap();
        let url = "https://127.0.0.1:14000/sign-me-up";
        let body = account.sign(None, "nonce-1", url, Some(&json!({"termsOfServiceAgreed": true}))).unwrap();
        let (header, payload, good) = open(&body, &account);
        assert!(good, "p256 verifies the signature");
        let fields = (header["alg"].as_str(), header["nonce"].as_str(), header["url"].as_str());
        assert_eq!(fields, (Some("ES256"), Some("nonce-1"), Some(url)));
        assert_eq!(header["jwk"], account.jwk());
        assert!(header.get("kid").is_none(), "jwk or kid, never both");
        assert_eq!(serde_json::from_slice::<Value>(&payload).unwrap(), json!({"termsOfServiceAgreed": true}));

        // After newAccount, the account's URL names the key; a POST-as-GET
        // has an empty payload.
        let body = account.sign(Some("https://ca.test/acct/1"), "nonce-2", url, None).unwrap();
        let (header, payload, good) = open(&body, &account);
        assert!(good);
        assert_eq!(header["kid"].as_str(), Some("https://ca.test/acct/1"));
        assert!(header.get("jwk").is_none());
        assert!(payload.is_empty());
    }

    #[test]
    fn a_key_authorization_is_the_token_and_the_thumbprint_of_the_key() {
        let account = Account::generate().unwrap();
        let again = Account::from_pkcs8(&account.pkcs8).unwrap();
        assert_eq!(account.thumbprint(), again.thumbprint(), "the kept key is the same account");
        let jwk = account.jwk();
        let want = thumbprint(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap());
        assert_eq!(account.key_authorization("tok-en_1"), format!("tok-en_1.{want}"));
    }
}
