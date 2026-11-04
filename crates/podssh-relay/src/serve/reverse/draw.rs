//! What a pair draws, and how its tokens are compared: the names and tokens
//! of the role's pairs from the system's randomness, and each token kept and
//! compared by its SHA-256, in constant time. Apart from `pairs.rs`, so that
//! it stays within 500 lines (T-630).

use sha2::{Digest, Sha256};

pub fn digest(token: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(token.as_bytes()));
    out
}

/// Equal in constant time: a digest's first bytes are not given away.
pub fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `n` bytes of the system's randomness.
pub fn random(n: usize) -> Result<Vec<u8>, String> {
    use rand::TryRng;
    let mut out = vec![0u8; n];
    rand::rngs::SysRng.try_fill_bytes(&mut out).map_err(|e| format!("no randomness for a pair: {e}"))?;
    Ok(out)
}

/// `n` characters of `[0-9a-z]`, the shape of the default relay's tokens
/// (measured 2026-10-09); a byte of 252 or more is drawn again, so that each
/// character is as likely.
pub fn base36(n: usize) -> Result<String, String> {
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = String::with_capacity(n);
    while out.len() < n {
        for byte in random(n)? {
            if byte < 252 && out.len() < n {
                out.push(char::from(ALPHABET[usize::from(byte % 36)]));
            }
        }
    }
    Ok(out)
}
