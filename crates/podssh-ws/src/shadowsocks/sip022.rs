//! Shadowsocks 2022 (SIP022, shadowsocks.org's `sip022.html`; T-492): what
//! its streams carry beside the AEAD form's chunks. The key is a pre-shared
//! key of the method's length in base64; each stream's key is BLAKE3's
//! `derive_key` with the context "shadowsocks 2022 session subkey" over the
//! key and the stream's salt. A request opens with a fixed header (its type,
//! a timestamp, the length of the next) and a variable one (the target's
//! address, then padding, as no payload goes with it); the response opens
//! with its fixed header (its type, a timestamp, the request's salt, the
//! length of its first payload). A timestamp more than 30 s from this host's
//! clock is a replay to each side, so a refusal for it names this clock.
//!
//! A key of several users (SIP023, `iPSK:uPSK`) is refused by its name: it
//! asks for identity headers that this client does not make.

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::codec::ChunkError;
use super::Method;

/// BLAKE3's context for each stream's key, as SIP022 fixes it.
pub const CONTEXT: &str = "shadowsocks 2022 session subkey";
/// The type of a request's fixed header.
pub const REQUEST: u8 = 0;
/// The type of a response's fixed header.
pub const RESPONSE: u8 = 1;
/// The most seconds between a header's timestamp and the clock of its
/// reader.
pub const WINDOW_SECS: u64 = 30;
/// The most bytes of a request's padding, as shadowsocks-rust sends it.
pub const MAX_PADDING: usize = 900;
/// The bytes of a request's fixed header: its type, the timestamp and the
/// length of the variable header.
pub const REQUEST_FIXED: usize = 1 + 8 + 2;

/// The key of one stream: BLAKE3's `derive_key` of the pre-shared key and
/// the salt, as long as the key. BLAKE3's output is a stream, so the first
/// 16 bytes of its 32 are the 16 that a key of AES-128 takes.
pub fn session_key(psk: &[u8], salt: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut material = Zeroizing::new(Vec::with_capacity(psk.len() + salt.len()));
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let full = Zeroizing::new(blake3::derive_key(CONTEXT, &material));
    Zeroizing::new(full[..psk.len().min(32)].to_vec())
}

/// The pre-shared key of `text` for `method`: base64, padded or not, of
/// exactly the method's length. No message holds a byte of it.
pub fn psk(text: &str, method: Method) -> Result<Zeroizing<Vec<u8>>, String> {
    use base64::Engine as _;
    let name = method.name();
    if text.contains(':') {
        return Err(format!(
            "its key is one of several users (iPSK:uPSK, SIP023), which podssh does not speak; ask the server's \
             operator for a key of one user of {name}"
        ));
    }
    let text = text.trim();
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    let decoded = engines.iter().find_map(|engine| engine.decode(text).ok()).map(Zeroizing::new);
    let len = method.key_len();
    match decoded {
        Some(key) if key.len() == len => Ok(key),
        _ => Err(format!(
            "its key is not the base64 of {len} bytes, as {name} takes (a pre-shared key, such as ssservice genkey \
             makes, not a password)"
        )),
    }
}

/// This host's clock, in seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A request's fixed header: its type, the timestamp `now`, and the length
/// of the variable header that follows it.
pub fn request_fixed(variable_len: u16, now: u64) -> [u8; REQUEST_FIXED] {
    let mut out = [0u8; REQUEST_FIXED];
    out[0] = REQUEST;
    out[1..9].copy_from_slice(&now.to_be_bytes());
    out[9..].copy_from_slice(&variable_len.to_be_bytes());
    out
}

/// A request's variable header with no payload: the target's `address`,
/// then `padding`'s length and itself, which SIP022 asks for when no
/// payload goes with the header.
pub fn request_variable(address: &[u8], padding: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(address.len() + 2 + padding.len());
    out.extend_from_slice(address);
    out.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    out.extend_from_slice(padding);
    out
}

/// Random padding of 1 to [`MAX_PADDING`] bytes, so that the length of a
/// request's first bytes tells nothing of its target.
pub fn padding() -> Result<Vec<u8>, ChunkError> {
    use rustls::crypto::SecureRandom as _;
    let mut len = [0u8; 2];
    crate::crypto::random::OsRandom.fill(&mut len).map_err(|_| ChunkError::Random)?;
    let n = 1 + usize::from(u16::from_be_bytes(len)) % MAX_PADDING;
    let mut out = vec![0u8; n];
    crate::crypto::random::OsRandom.fill(&mut out).map_err(|_| ChunkError::Random)?;
    Ok(out)
}

/// The bytes of a response's fixed header for a salt of `salt_len`.
pub fn response_fixed_len(salt_len: usize) -> usize {
    1 + 8 + salt_len + 2
}

/// A response's fixed header, read: its type, its timestamp, the request's
/// salt that it names, and the length of its first payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub kind: u8,
    pub timestamp: u64,
    pub request_salt: Vec<u8>,
    pub length: u16,
}

/// A response's fixed header from its plaintext; `None` when it is not as
/// long as a salt of `salt_len` makes it.
pub fn parse_response(plain: &[u8], salt_len: usize) -> Option<Response> {
    if plain.len() != response_fixed_len(salt_len) {
        return None;
    }
    let timestamp = u64::from_be_bytes(plain[1..9].try_into().ok()?);
    let request_salt = plain[9..9 + salt_len].to_vec();
    let length = u16::from_be_bytes([plain[9 + salt_len], plain[10 + salt_len]]);
    Some(Response { kind: plain[0], timestamp, request_salt, length })
}

/// Whether `response` answers the request of `request_salt` at `now`: its
/// type, its timestamp within the window, and the request's salt.
pub fn check(response: &Response, request_salt: &[u8], now: u64) -> Result<(), ChunkError> {
    if response.kind != RESPONSE {
        return Err(ChunkError::Kind(response.kind));
    }
    if response.timestamp.abs_diff(now) > WINDOW_SECS {
        let skew = response.timestamp as i64 - now as i64;
        return Err(ChunkError::Clock { skew, now: now as i64 });
    }
    if response.request_salt != request_salt {
        return Err(ChunkError::Salt);
    }
    Ok(())
}

/// A response's fixed header as a server makes it: the server's side, for
/// the tests.
pub fn response_fixed(request_salt: &[u8], length: u16, now: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(response_fixed_len(request_salt.len()));
    out.push(RESPONSE);
    out.extend_from_slice(&now.to_be_bytes());
    out.extend_from_slice(request_salt);
    out.extend_from_slice(&length.to_be_bytes());
    out
}

/// A request's fixed header from its plaintext: its type, its timestamp
/// and the length of the variable header. The server's side, for the tests.
pub fn parse_request(plain: &[u8]) -> Option<(u8, u64, u16)> {
    if plain.len() != REQUEST_FIXED {
        return None;
    }
    let timestamp = u64::from_be_bytes(plain[1..9].try_into().ok()?);
    Some((plain[0], timestamp, u16::from_be_bytes([plain[9], plain[10]])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_of_16_bytes_is_the_first_16_of_blake3_s_32() {
        let psk = [1u8; 32];
        let salt = [2u8; 32];
        let long = session_key(&psk, &salt);
        let mut material = psk.to_vec();
        material.extend_from_slice(&salt);
        assert_eq!(long.as_slice(), blake3::derive_key(CONTEXT, &material).as_slice());
        let short = session_key(&[1u8; 16], &[2u8; 16]);
        let mut hasher = blake3::Hasher::new_derive_key(CONTEXT);
        hasher.update(&[1u8; 16]).update(&[2u8; 16]);
        let mut xof = [0u8; 16];
        hasher.finalize_xof().fill(&mut xof);
        assert_eq!(short.as_slice(), &xof, "as shadowsocks-rust fills a key of 16 from BLAKE3's stream");
    }

    #[test]
    fn a_key_is_base64_of_the_method_s_length_and_several_users_are_refused() {
        let k32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        assert_eq!(psk(k32, Method::Blake3Aes256Gcm).unwrap().len(), 32);
        assert_eq!(psk(k32.trim_end_matches('='), Method::Blake3Chacha20Poly1305).unwrap().len(), 32);
        let short = psk(k32, Method::Blake3Aes128Gcm).unwrap_err();
        assert!(short.contains("base64 of 16 bytes") && !short.contains("AAEC"), "{short}");
        let password = psk("a password, not a key", Method::Blake3Aes256Gcm).unwrap_err();
        assert!(password.contains("not a password") && !password.contains("a password,"), "{password}");
        let users = psk(&format!("{k32}:{k32}"), Method::Blake3Aes256Gcm).unwrap_err();
        assert!(users.contains("SIP023") && !users.contains("AAEC"), "{users}");
    }

    #[test]
    fn a_response_is_checked_for_its_type_its_clock_and_the_request_s_salt() {
        let salt = vec![5u8; 16];
        let plain = response_fixed(&salt, 300, 1_000);
        let read = parse_response(&plain, 16).unwrap();
        assert_eq!((read.kind, read.timestamp, read.length), (RESPONSE, 1_000, 300));
        assert_eq!(check(&read, &salt, 1_020), Ok(()));
        assert_eq!(check(&read, &salt, 1_031), Err(ChunkError::Clock { skew: -31, now: 1_031 }));
        assert_eq!(check(&read, &[6u8; 16], 1_000), Err(ChunkError::Salt));
        let request = Response { kind: REQUEST, ..read };
        assert_eq!(check(&request, &salt, 1_000), Err(ChunkError::Kind(REQUEST)));
        assert_eq!(parse_response(&plain[1..], 16), None);
    }

    #[test]
    fn a_request_s_headers_are_as_sip022_lays_them_out() {
        let fixed = request_fixed(300, 0x0102_0304_0506_0708);
        assert_eq!(fixed, [0, 1, 2, 3, 4, 5, 6, 7, 8, 0x01, 0x2c]);
        assert_eq!(parse_request(&fixed), Some((REQUEST, 0x0102_0304_0506_0708, 300)));
        let variable = request_variable(&[1, 10, 0, 0, 2, 0, 22], &[9, 9, 9]);
        assert_eq!(variable, [1, 10, 0, 0, 2, 0, 22, 0, 3, 9, 9, 9]);
        for _ in 0..50 {
            let pad = padding().unwrap();
            assert!((1..=MAX_PADDING).contains(&pad.len()), "{}", pad.len());
        }
    }
}
