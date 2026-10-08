//! KEXINIT (RFC 4253 §7.1) and algorithm selection.
//!
//! ⛔ podssh's offer is closed: exactly the entry's decided set, in this
//! order. A name the server offers that is not in the set is never selected,
//! and a group with no overlap is `UnsupportedAlgorithm` naming the server's
//! head — never a silent fallback to a weaker primitive.

use crate::ssh::types::{Reader, TypeError, put_namelist, put_string, put_u32};

/// What podssh offers, in preference order. One kex, two host keys, two
/// AEAD ciphers, one filler MAC (ignored under AEAD per RFC 4253 §7.1 —
/// offered because the field is mandatory, never selected past AEAD), no
/// compression, no languages.
pub const OUR_KEX: &[&str] = &["curve25519-sha256"];
pub const OUR_HOSTKEY: &[&str] = &["ssh-ed25519", "rsa-sha2-256"];
pub const OUR_CIPHER: &[&str] = &["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com"];
pub const OUR_MAC: &[&str] = &["hmac-sha2-256"];
pub const OUR_COMP: &[&str] = &["none"];

/// A parsed KEXINIT payload (message byte already consumed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexInit {
    pub cookie: [u8; 16],
    pub kex: Vec<String>,
    pub hostkey: Vec<String>,
    pub cipher_c2s: Vec<String>,
    pub cipher_s2c: Vec<String>,
    pub mac_c2s: Vec<String>,
    pub mac_s2c: Vec<String>,
    pub comp_c2s: Vec<String>,
    pub comp_s2c: Vec<String>,
    pub lang_c2s: Vec<String>,
    pub lang_s2c: Vec<String>,
    pub first_kex_follows: bool,
}

/// Why a KEXINIT is not an agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KexError {
    Types(TypeError),
    /// Trailing bytes after the fixed fields (strict — see `Reader::rest`).
    TrailingBytes { bytes: usize },
    /// No overlap in one group. Names the group and the server's head, so a
    /// log says what the peer wanted rather than "negotiation failed".
    UnsupportedAlgorithm { group: &'static str, server_head: String },
}

impl std::fmt::Display for KexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Types(e) => write!(f, "{e}"),
            Self::TrailingBytes { bytes } => write!(f, "KEXINIT has {bytes} trailing bytes"),
            Self::UnsupportedAlgorithm { group, server_head } => write!(
                f,
                "no overlap in {group}; server leads with {server_head:?}"
            ),
        }
    }
}

impl std::error::Error for KexError {}

impl From<TypeError> for KexError {
    fn from(e: TypeError) -> Self {
        Self::Types(e)
    }
}

fn read_list(r: &mut Reader<'_>) -> Result<Vec<String>, KexError> {
    Ok(r.namelist()?)
}

/// Parse a KEXINIT payload (the leading message byte 20 already consumed).
pub fn decode_kexinit(payload: &[u8]) -> Result<KexInit, KexError> {
    let mut r = Reader::new(payload);
    let raw_cookie = r.bytes(16)?;
    let mut cookie = [0u8; 16];
    cookie.copy_from_slice(raw_cookie);
    let k = KexInit {
        cookie,
        kex: read_list(&mut r)?,
        hostkey: read_list(&mut r)?,
        cipher_c2s: read_list(&mut r)?,
        cipher_s2c: read_list(&mut r)?,
        mac_c2s: read_list(&mut r)?,
        mac_s2c: read_list(&mut r)?,
        comp_c2s: read_list(&mut r)?,
        comp_s2c: read_list(&mut r)?,
        lang_c2s: read_list(&mut r)?,
        lang_s2c: read_list(&mut r)?,
        first_kex_follows: {
            // uint32 reserved (RFC 4253 §7.1: "MUST be 0") — read and
            // ignored, never interpreted. A nonzero reserved is not our
            // business to refuse; the boolean after it is.
            let _reserved = r.u32()?;
            r.boolean()?
        },
    };
    if !r.rest().is_empty() {
        return Err(KexError::TrailingBytes { bytes: r.rest().len() });
    }
    Ok(k)
}

/// Build our KEXINIT payload (message byte included; the caller frames it).
pub fn our_kexinit() -> Vec<u8> {
    use rand::RngCore;
    let mut cookie = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut cookie);
    let mut out = vec![crate::ssh::packet::MsgId::KexInit as u8];
    out.extend_from_slice(&cookie);
    put_namelist(&mut out, OUR_KEX);
    put_namelist(&mut out, OUR_HOSTKEY);
    put_namelist(&mut out, OUR_CIPHER);
    put_namelist(&mut out, OUR_CIPHER);
    put_namelist(&mut out, OUR_MAC);
    put_namelist(&mut out, OUR_MAC);
    put_namelist(&mut out, OUR_COMP);
    put_namelist(&mut out, OUR_COMP);
    put_string(&mut out, &[]);
    put_string(&mut out, &[]);
    put_u32(&mut out, 0);
    out.push(0);
    out
}

/// What both sides agreed on. Every field is a name from our closed set —
/// selection cannot produce an algorithm we did not offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    pub kex: String,
    pub hostkey: String,
    pub cipher_c2s: String,
    pub cipher_s2c: String,
    pub mac_c2s: String,
    pub mac_s2c: String,
    pub comp_c2s: String,
    pub comp_s2c: String,
}

fn pick(group: &'static str, ours: &[&str], theirs: &[String]) -> Result<String, KexError> {
    // ⛔ Server order wins: the first name THEY list that we also offer.
    // Ours is a closed set, so the result is always one of ours — the rule
    // is whose preference orders the overlap, and the answer is theirs.
    for name in theirs {
        if ours.contains(&name.as_str()) {
            return Ok(name.clone());
        }
    }
    Err(KexError::UnsupportedAlgorithm {
        group,
        server_head: theirs.first().cloned().unwrap_or_default(),
    })
}

/// Select against the server's KEXINIT. Compression and language groups are
/// not negotiated (we offer `none`/empty only — a server offering anything
/// else still lands on `none`, because offering one thing is not a
/// negotiation).
pub fn select(theirs: &KexInit) -> Result<Selected, KexError> {
    Ok(Selected {
        kex: pick("kex", OUR_KEX, &theirs.kex)?,
        hostkey: pick("hostkey", OUR_HOSTKEY, &theirs.hostkey)?,
        cipher_c2s: pick("cipher_c2s", OUR_CIPHER, &theirs.cipher_c2s)?,
        cipher_s2c: pick("cipher_s2c", OUR_CIPHER, &theirs.cipher_s2c)?,
        mac_c2s: pick("mac_c2s", OUR_MAC, &theirs.mac_c2s)?,
        mac_s2c: pick("mac_s2c", OUR_MAC, &theirs.mac_s2c)?,
        comp_c2s: "none".to_string(),
        comp_s2c: "none".to_string(),
    })
}

/// Whether the server's `first_kex_follows` guess missed: true when it
/// guessed (flag set) and its head kex is not what we selected — the next
/// packet from them is a wrong guess to ignore, not a message to parse.
pub fn must_ignore_next(theirs: &KexInit, selected: &Selected) -> bool {
    theirs.first_kex_follows && theirs.kex.first() != Some(&selected.kex)
}
