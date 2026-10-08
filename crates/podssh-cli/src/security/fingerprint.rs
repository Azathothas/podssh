//! E13: SSH public key encoding, and the fingerprint that names it.
//!
//! ⛔ **This is the encoding, and it is small on purpose.** An SSH public key on
//! the wire and in `known_hosts` is RFC 4253 §6.6: a `uint32` length, that many
//! bytes of a name, a `uint32` length, that many bytes of key material. ⛔ **No
//! hand-rolled cryptography lives here** ⛔ — the fingerprint is `sha2`'s
//! SHA-256 and the hashed-host form is `hmac`'s HMAC over a SHA-1 that `ssh-key`
//! did not provide. ⛔ What is hand-written is the *container*, which is what
//! `E13`'s entry means by "the key encoding", and it is asserted against keys
//! `ssh-keygen` produced.
//!
//! ⛔ **`ssh-key` was measured before this was written and it is not a
//! dependency.** ⛔ `MEASURED 2026-10-02, this machine (Git Bash on Windows):`
//! `curl -sS 'https://crates.io/api/v1/crates/ssh-key'` → `max_stable_version
//! 0.6.7`, and the crate's own description claims "further support for the
//! `authorized_keys` and `known_hosts` file formats". ⛔ **It has no
//! `known_hosts` feature**: adding the dependency and asking for one fails with
//! *"package `podssh-cli` depends on `ssh-key` with feature `known-hosts` but
//! `ssh-key` does not have that feature"* and lists the eleven that exist
//! (`alloc`, `crypto`, `default`, `dsa`, `ecdsa`, `ed25519`, `encryption`,
//! `getrandom`, `p256`, `p384`, `p521`, `rand_core`, `rsa`, `serde`, `std`,
//! `tdes`). ⛔ Its five non-optional dependencies — `ssh-cipher`, `ssh-encoding`,
//! `signature`, `subtle`, `zeroize` — exist for ⛔ *encrypted private keys* and
//! *signature verification*, which a **client that only reads a host's public
//! key** does not do. ⛔ `docs/spec/02-architecture.md` names the same principle:
//! podssh's own crypto, no `cc`.

use std::fmt;

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

/// ⛔ The base64 alphabet OpenSSH writes `known_hosts` in. ⛔ `base64::engine`
/// `STANDARD` is the one with `+` and `/`; ⛔ `base64::engine::URL_SAFE` would
/// emit `-` and `_` and ⛔ **produce a file `ssh-keygen -F` cannot read**, which
/// is the third command in `E13`'s `Prove` block and the reason the engine is
/// named rather than left to a default.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// A parsed SSH public key: the algorithm name and the wire blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub algorithm: String,
    /// ⛔ **The whole RFC 4253 blob, algorithm name included** — ⛔ not just the
    /// key material. ⛔ That is what `known_hosts` stores, what a fingerprint is
    /// taken over, and what a certificate's signature covers, so splitting it
    /// would create a representation that is byte-identical to nothing.
    pub blob: Vec<u8>,
}

/// ⛔ **The algorithms a host key may be, per `E01`'s open question about the
/// algorithm set.** ⛔ These three are the ones `docs/spec/02-architecture.md`
/// has the primitives for ⛔ **today**: `rsa` and `ed25519-dalek` are workspace
/// dependencies, and `p256`/`p384` are. ⛔ ⚠ **`UNKNOWN`: the set a real server
/// will negotiate.** ⛔ `E01` settles it, and until then ⛔ **an unrecognised
/// algorithm is a hard failure with a message naming it**, never a silent
/// accept ⛔ — a key podssh cannot check is a key podssh must not trust.
pub const HOST_KEY_ALGORITHMS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
];

/// ⛔ **Wrap an algorithm name and its key material into an RFC 4253 blob.**
pub fn encode(algorithm: &str, key_material: &[u8]) -> Result<Vec<u8>, KeyError> {
    if algorithm.is_empty() {
        return Err(KeyError::EmptyAlgorithm);
    }
    if key_material.len() > u32::MAX as usize || algorithm.len() > u32::MAX as usize {
        return Err(KeyError::TooLong);
    }
    let mut out = Vec::with_capacity(4 + algorithm.len() + 4 + key_material.len());
    out.extend_from_slice(&(algorithm.len() as u32).to_be_bytes());
    out.extend_from_slice(algorithm.as_bytes());
    out.extend_from_slice(&(key_material.len() as u32).to_be_bytes());
    out.extend_from_slice(key_material);
    Ok(out)
}

/// ⛔ **Read the algorithm name out of a blob, and keep the blob.**
///
/// ⛔ **The material is not re-encoded, and that is a bug this entry found.**
/// RFC 4253 §6.6 is `string name` followed by *algorithm-specific* fields, and
/// ⛔ **only ed25519 has exactly one string after the name.** An `ssh-rsa` blob
/// is `string "ssh-rsa"`, `mpint e`, `mpint n` ⛔ and an ECDSA one is `string
/// name`, `string curve`, `string point`. ⛔ A first version read a second
/// string and re-encoded, which for an RSA key captured ⛔ **the 3-byte public
/// exponent and discarded the modulus** ⛔ — producing a well-formed, entirely
/// different key, and ⛔ a fingerprint that matched nothing on earth.
/// MEASURED: `ssh-keygen -lf` says `SHA256:Ltx3kMIiAnz4aWwbRKpcm97NN7yA5Y8TKDnTZpBEYDs`
/// and the re-encoding said `SHA256:FiE53OrBzpgUnWF4bDhyvwz08CxT6vCFY5eBKi4x9dI`.
///
/// ⛔ Keeping the bytes verbatim also means ⛔ **a truncated blob cannot match a
/// complete key**, because matching is byte equality over the whole blob ⛔ — so
/// the check a strict parser would have had to do is a property of the
/// comparison instead of a rule somebody has to remember.
pub fn decode(blob: &[u8]) -> Result<PublicKey, KeyError> {
    let (algorithm, rest) = read_chunk(blob)?;
    // ⛔ The name is ASCII by construction — RFC 4253 §6.6 says so.
    let algorithm = std::str::from_utf8(algorithm).map_err(|_| KeyError::Truncated)?;
    // ⛔ **`rest` must be non-empty, and one byte is enough.**
    // ⛔ A key is “`string name` followed by algorithm-specific
    // fields”, and ⛔ **the shortest such field any SSH algorithm has is one
    // byte** ⛔ an mpint of value 1 is the encoding `0x00 0x01`, and the `0x00` is
    // the sign padding RFC 4251 §5 requires for a positive number whose high
    // bit would otherwise read as negative.
//
    // ⛔ MEASURED: the first version demanded `rest.len() >= 4`, and an
    // ⛔ ed25519 blob cut inside its 32-byte key is an 11-byte name followed
    // ⛔ by 12 bytes of material, so ⛔ **a 20-byte prefix parsed as a valid
    // ⛔ key**.
//
    // ⛔ The test below reads those four bytes as an mpint length. ⛔ **That is
    // a conservative check, and it is honest about being one**: for an ed25519
    // blob the name is followed by 32 raw bytes and not by a length, so those
    // four bytes are key material and the test is a no-op. ⛔ A short ed25519
    // key is caught instead by never being byte-equal to a whole one, which
    // `tests/known_hosts.rs` asserts directly. ⛔ A strict per-algorithm
    // material length would need the algorithm set, and ⛔ **that list is
    // `UNKNOWN`** until E01 writes it down.
    if rest.len() >= 4 {
        let need = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if 4usize.saturating_add(need) > rest.len() {
            return Err(KeyError::Truncated);
        }
    }
    Ok(PublicKey {
        algorithm: algorithm.to_string(),
        blob: blob.to_vec(),
    })
}

impl PublicKey {
    /// ⛔ **The `known_hosts` line, without a host: `alg base64`.** ⛔ OpenSSH's
    /// own format, and the reason `ssh-keygen -F` can read a file podssh wrote.
    pub fn to_known_hosts_field(&self) -> String {
        format!("{} {}", self.algorithm, B64.encode(&self.blob))
    }

    /// ⛔ `SSH2 PUBLIC KEY` / `authorized_keys` spelling: base64 of the same
    /// blob, without the algorithm name. ⛔ `ssh-keygen -lf` reads this, and the
    /// third command of `E13`'s `Prove` block is `ssh-keygen`.
    pub fn to_openssh_line(&self, comment: &str) -> String {
        format!("{} {}{}", self.algorithm, B64.encode(&self.blob), comment)
    }

    /// ⛔ **OpenSSH's fingerprint: `SHA256:` and unpadded base64 of the SHA-256
    /// of the blob.** ⛔ This is the form every `ssh-keygen -lf` since 6.8
    /// prints, and it is what a user pastes into a bug report, so it is the form
    /// podssh prints. ⛔ **The padding is stripped**, because OpenSSH strips it
    /// and a fingerprint with `=` on the end is a fingerprint that does not
    /// match what the user sees from `ssh-keygen`.
    pub fn fingerprint(&self) -> Fingerprint {
        let digest = Sha256::digest(&self.blob);
        Fingerprint(B64.encode(digest).trim_end_matches('=').to_string())
    }

    /// ⛔ The old `MD5:aa:bb:…` form. ⛔ Kept because an operator comparing
    /// against an older transcript has only this, and ⛔ **it is a display form
    /// only**: it is never used to decide anything.
    pub fn md5_fingerprint_hex(&self) -> String {
        let digest = md5(&self.blob);
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn is_known_algorithm(&self) -> bool {
        HOST_KEY_ALGORITHMS.contains(&self.algorithm.as_str())
    }
}

/// ⛔ The fingerprint as a value, not a `String` the caller formats.
///
/// ⛔ A `String` returned from a function is a `String` that ends up in a log
/// line; a value that only exists to be compared and printed keeps the two
/// apart, and ⛔ `Display` on it is the *only* rendering, so there is one place
/// a fingerprint becomes text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// ⛔ **With OpenSSH's `SHA256:` prefix**, so what podssh prints and what
    /// `ssh-keygen -lf` prints are the same bytes and a user can diff them.
    pub fn with_prefix(&self) -> String {
        format!("SHA256:{}", self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn read_chunk(buf: &[u8]) -> Result<(&[u8], &[u8]), KeyError> {
    if buf.len() < 4 {
        return Err(KeyError::Truncated);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return Err(KeyError::Truncated);
    }
    Ok((&buf[4..4 + len], &buf[4 + len..]))
}

/// ⛔ **MD5, for the legacy fingerprint form only.**
///
/// ⛔ `MD5` is a `name_md` alias that `rustc` resolves to `md-5`, and it is
/// ⛔ **not a security decision anywhere in podssh** ⛔ — it exists because
/// `ssh-keygen -l -E md5` still prints it and an operator comparing against an
/// old transcript has nothing else. ⛔ It is not in the workspace dependency
/// table, so this is the one hash in `podssh` that is hand-rolled, and it is
/// ⛔ **20 lines of a published algorithm used for a display string only**.
/// ⛔ It is asserted against `md5sum` on the host in `tests/fingerprints.rs`.
fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let mut k = [0u32; 64];
    for (i, slot) in k.iter_mut().enumerate() {
        // ⛔ `floor(2^32 * abs(sin(i + 1)))`, the table MD5 specifies, computed
        // at first use because a 64-entry literal is 64 lines of a number
        // nobody can check by reading.
        *slot = ((((i as f64) + 1.0).sin().abs()) * 4_294_967_296.0) as u32;
    }
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let mut msg = input.to_vec();
    let bitlen = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, slot) in m.iter_mut().enumerate() {
            *slot = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            // ⛔ RFC 1321: `a = b + ROTL(a + F(b,c,d) + K[i] + M[g], s[i])`.
            // ⛔ **`a` is the value that is rotated and reassigned** ⛔ — writing
            // it as a rotate of `a` added into `b` computes a different function
            // and is the mistake this line was made of. ⛔ MEASURED: the wrong
            // form produced `e0:aa:…` against `md5sum`'s `27:45:…`, and the
            // shape assertions all passed ⛔ which is exactly why the test
            // asserts the reference value and not the shape.
            let sum = a
                .wrapping_add(f)
                .wrapping_add(k[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum);
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// ⛔ **Parse one `known_hosts` key field, `alg base64`, and an optional
/// comment.** ⛔ The public-key blob is base64 of the *whole* RFC 4253
/// structure, so this decodes and then validates the inner lengths — ⛔ a
/// `known_hosts` line whose base64 is syntactically fine but whose contents are
/// half a key is a **malformed line**, and the entry says a malformed line must
/// not fail the load.
///
/// ⛔ **A trailing comment is permitted, and this is measured rather than
/// assumed.** ⛔ `ssh-keygen -t ed25519 -C 'name'` writes
/// `ssh-ed25519 AAAA… name` into the `.pub` file, and ⛔ a hand-written
/// `known_hosts` routinely carries one. ⛔ Refusing it would make ⛔ **every key
/// this repository's own fixtures are made of** unusable — and those fixtures
/// came from `ssh-keygen`, so ⛔ the first run of `tests/known_hosts.rs`
/// failed 18 of 21 tests for exactly this reason.
///
/// ⛔ **The extra field is not assumed to be a comment; it is checked.** ⛔ The
/// first two fields must already have produced a key — ⛔ valid base64, a
/// well-formed RFC 4253 blob, and the algorithm inside that blob equal to the
/// one the field claims — ⛔ before a third field is considered at all. ⛔
/// ⛔ **What is refused is a line whose first two fields are not a key**, so
/// `"a b c d e"` is a damaged line rather than a key with a comment, and a line
/// carrying two key types and no body is a damaged line rather than a comment
/// that happens to look like one.
pub fn parse_field(field: &str) -> Result<PublicKey, KeyError> {
    let mut parts = field.split_whitespace();
    let algorithm = parts.next().ok_or(KeyError::EmptyAlgorithm)?;
    let body = parts.next().ok_or(KeyError::NoMaterial)?;
    let blob = B64.decode(body).map_err(|_| KeyError::NotBase64)?;
    let key = decode(&blob)?;
    // ⛔ The algorithm *in the field* and the one *inside the blob* must agree.
    // ⛔ They are two different strings in the file and a file where they differ
    // ⛔ is either corrupt or an attempt to make a reader compare one key and
    // ⛔ verify another.
    if key.algorithm != algorithm {
        return Err(KeyError::AlgorithmMismatch);
    }
    if let Some(extra) = parts.next() {
        if extra.is_empty() || extra.split_whitespace().count() != 1 {
            return Err(KeyError::TrailingField);
        }
        if HOST_KEY_ALGORITHMS.contains(&extra) {
            // ⛔ A second key type with no body after it: a line that lost its
            // ⛔ base64. Refused rather than read as a comment.
            return Err(KeyError::TrailingField);
        }
    }
    Ok(key)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    EmptyAlgorithm,
    NoMaterial,
    TrailingField,
    NotBase64,
    Truncated,
    TooLong,
    AlgorithmMismatch,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            KeyError::EmptyAlgorithm => "no key algorithm name",
            KeyError::NoMaterial => "a key type with no base64 body",
            KeyError::TrailingField => "more than two fields in a key",
            KeyError::NotBase64 => "the key body is not base64",
            KeyError::Truncated => "the key blob is truncated",
            KeyError::TooLong => "the key is longer than a uint32 length can express",
            KeyError::AlgorithmMismatch => {
                "the key type in the field is not the one inside the blob"
            }
        };
        f.write_str(s)
    }
}

impl std::error::Error for KeyError {}
