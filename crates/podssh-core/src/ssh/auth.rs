//! Authentication: publickey first, then the refusal (RFC 4252).
//!
//! ⛔ No crypto is implemented here. `ed25519-dalek` signs; this file builds
//! the exact bytes RFC 4252 §7 names and parses the exact replies §5 names.
//! The signed data is `session_id || body`, where `body` is the request
//! WITHOUT the signature field — signing a body that already contains a
//! signature slot is the classic way to verify nothing.
//!
//! ⛔ v1 has no password path: `next_method` REFUSES with `PasswordRefused`
//! naming the gap, never silently skips to it and never prompts. A secret
//! prompt inside a library that owns no I/O would be a lie anyway, and E33
//! forbids non-interactive secrets. The refusal is the feature.
//!
//! ⛔ The private-key parser takes `id_ed25519` with cipher `none` only. An
//! encrypted key is `EncryptedKey` naming the cipher — v1 has no passphrase
//! prompt to offer, so accepting the file and failing later would strand the
//! user. Passphrase support is a named gap, not a stub.

use crate::ssh::types::{Reader, TypeError, put_string};

pub const MSG_SERVICE_REQUEST: u8 = 5;
pub const MSG_SERVICE_ACCEPT: u8 = 6;
pub const MSG_USERAUTH_REQUEST: u8 = 50;
pub const MSG_USERAUTH_FAILURE: u8 = 51;
pub const MSG_USERAUTH_SUCCESS: u8 = 52;
pub const MSG_USERAUTH_BANNER: u8 = 53;
pub const MSG_USERAUTH_PK_OK: u8 = 60;

pub const SERVICE_USERAUTH: &str = "ssh-userauth";
pub const SERVICE_CONNECTION: &str = "ssh-connection";
pub const METHOD_PUBLICKEY: &str = "publickey";
pub const METHOD_PASSWORD: &str = "password";

/// Why an authentication is not an agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Types(TypeError),
    /// The peer answered a different service, or accepted one we did not ask
    /// for — a mixup, never an ok.
    ServiceMismatch { expected: String, got: String },
    /// A server message outside 51/52/53/60 (or a truncated one): the peer is
    /// not speaking userauth, and guessing which is how downgrades happen.
    UnexpectedMessage { byte: Option<u8> },
    /// FAILURE arrived with no methods left: the server will accept nothing
    /// more from us on this connection.
    Exhausted { tried: Vec<String> },
    /// The server only offers methods v1 does not implement. Refusal names
    /// every offered method, so the user knows it is the client's gap.
    UnsupportedMethods { offered: Vec<String> },
    /// The next step would be a password prompt. v1 has no prompt (E33
    /// forbids non-interactive secrets), so this is an error naming the knob
    /// that does not exist — never a silent skip, never a hang.
    PasswordRefused,
    /// A `partial success` that names no further methods is a server telling
    /// us to continue with nothing to continue with.
    PartialWithNoMethods,
    /// The PK_OK echo does not match the key we offered: a substitution, not
    /// an acceptance. The connection MUST NOT proceed to the signed request.
    PkOkMismatch,
    /// The armor is not an OpenSSH private key.
    BadArmor,
    /// The decoded key is not `openssh-key-v1`.
    BadMagic,
    /// The key is encrypted and v1 takes no passphrase. Names the cipher so
    /// the user knows it is their key's protection, not our parsing.
    EncryptedKey { cipher: String },
    /// The KDF is not `none`.
    UnsupportedKdf { kdf: String },
    /// v1 reads one key per file.
    MultiKey { nkeys: u32 },
    /// The private section's checkints disagree: wrong passphrase on an
    /// encrypted key, or a corrupt file on an unencrypted one.
    BadCheckint,
    /// The embedded public half disagrees with the public section, or the
    /// private half's trailing public disagrees with its seed: the file is
    /// corrupt, not-a-key, never half-trusted.
    KeyMismatch,
    /// A key part is not its required length.
    BadKeyLength { part: &'static str, bytes: usize },
    /// Padding after the comment is not 1, 2, 3, ... — trailing garbage is
    /// refused, not ignored.
    BadPadding,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Types(e) => write!(f, "{e}"),
            Self::ServiceMismatch { expected, got } => {
                write!(f, "service {got:?} accepted, {expected:?} requested")
            }
            Self::UnexpectedMessage { byte } => {
                write!(f, "not a userauth message: {byte:?}")
            }
            Self::Exhausted { tried } => {
                write!(f, "server refused every method (tried {})", tried.join(","))
            }
            Self::UnsupportedMethods { offered } => {
                write!(f, "server offers only unsupported methods: {}", offered.join(","))
            }
            Self::PasswordRefused => write!(
                f,
                "the server wants a password, and podssh has no password authentication yet"
            ),
            Self::PartialWithNoMethods => {
                write!(f, "partial success with no further methods")
            }
            Self::PkOkMismatch => {
                write!(f, "server accepted a key we did not offer")
            }
            Self::BadArmor => write!(f, "not an OpenSSH private key"),
            Self::BadMagic => write!(f, "private key is not openssh-key-v1"),
            Self::EncryptedKey { cipher } => write!(
                f,
                "private key uses cipher {cipher:?} and v1 takes no passphrase"
            ),
            Self::UnsupportedKdf { kdf } => write!(f, "private key KDF {kdf:?} is not none"),
            Self::MultiKey { nkeys } => write!(f, "key file holds {nkeys} keys, v1 reads one"),
            Self::BadCheckint => write!(f, "private key checkints disagree (corrupt file)"),
            Self::KeyMismatch => write!(f, "private key halves disagree (corrupt file)"),
            Self::BadKeyLength { part, bytes } => {
                write!(f, "{part} is {bytes} bytes")
            }
            Self::BadPadding => write!(f, "private key padding is not 1,2,3,..."),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<TypeError> for AuthError {
    fn from(e: TypeError) -> Self {
        Self::Types(e)
    }
}

/// `SSH_MSG_SERVICE_REQUEST` for `ssh-userauth` (RFC 4253 §10). Payload only —
/// framing is the caller's (`packet` pre-kex, `cipher` after; auth runs after
/// NEWKEYS either way, so the caller decides).
pub fn service_request() -> Vec<u8> {
    let mut out = vec![MSG_SERVICE_REQUEST];
    put_string(&mut out, SERVICE_USERAUTH.as_bytes());
    out
}

/// Parse `SSH_MSG_SERVICE_ACCEPT`: must accept the service we asked for.
pub fn parse_service_accept(payload: &[u8]) -> Result<(), AuthError> {
    let mut r = Reader::new(payload);
    if r.u8()? != MSG_SERVICE_ACCEPT {
        return Err(AuthError::UnexpectedMessage { byte: payload.first().copied() });
    }
    let got = std::str::from_utf8(r.string()?)
        .map_err(|_| AuthError::ServiceMismatch {
            expected: SERVICE_USERAUTH.to_string(),
            got: format!("{:?}", r.rest()),
        })?
        .to_string();
    if got != SERVICE_USERAUTH {
        return Err(AuthError::ServiceMismatch {
            expected: SERVICE_USERAUTH.to_string(),
            got,
        });
    }
    Ok(())
}

/// The unsigned publickey query (RFC 4252 §7, boolean FALSE): asks whether
/// the server would accept this key, without spending a signature. Servers
/// answer PK_OK (60) or FAILURE — never SUCCESS, and treating anything else
/// as acceptance is the plant this module carries.
pub fn userauth_query(user: &str, key: &UserKey) -> Vec<u8> {
    let mut out = vec![MSG_USERAUTH_REQUEST];
    put_string(&mut out, user.as_bytes());
    put_string(&mut out, SERVICE_CONNECTION.as_bytes());
    put_string(&mut out, METHOD_PUBLICKEY.as_bytes());
    out.push(0);
    put_string(&mut out, key.alg.as_bytes());
    put_string(&mut out, &key.blob);
    out
}

/// The exact bytes signed for a publickey request (RFC 4252 §7):
/// `session_id || byte 50 || user || service || "publickey" || TRUE || alg ||
/// blob`. The signature field is NOT part of the input — there is nothing to
/// put there yet, and hashing a placeholder would verify a different message
/// than the server checks.
pub fn sign_data(session_id: &[u8], user: &str, key: &UserKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(session_id.len() + 64 + key.blob.len());
    out.extend_from_slice(session_id);
    out.push(MSG_USERAUTH_REQUEST);
    put_string(&mut out, user.as_bytes());
    put_string(&mut out, SERVICE_CONNECTION.as_bytes());
    put_string(&mut out, METHOD_PUBLICKEY.as_bytes());
    out.push(1);
    put_string(&mut out, key.alg.as_bytes());
    put_string(&mut out, &key.blob);
    out
}

/// A public key as offered: algorithm name plus its wire blob. Only
/// `ssh-ed25519` signs in v1 — anything else is refused at construction, so
/// no caller can build a signed request the verifier half-guesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserKey {
    pub alg: String,
    pub blob: Vec<u8>,
}

impl UserKey {
    pub fn ed25519(public_bytes: &[u8; 32]) -> Self {
        Self { alg: "ssh-ed25519".to_string(), blob: crate::ssh::keys::ed25519_blob(public_bytes) }
    }
}

/// The signed publickey request (RFC 4252 §7): the query shape with boolean
/// TRUE plus `string alg || string sig` over `sign_data`.
pub fn userauth_signed(
    session_id: &[u8],
    user: &str,
    key: &UserKey,
    signing: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    assert_eq!(key.alg, "ssh-ed25519", "v1 signs ssh-ed25519 only");
    let data = sign_data(session_id, user, key);
    let sig = signing.sign(&data);
    let mut out = Vec::with_capacity(data.len() - session_id.len() + 64 + 16);
    out.extend_from_slice(&data[session_id.len()..]);
    put_string(&mut out, key.alg.as_bytes());
    put_string(&mut out, &sig.to_bytes());
    out
}

/// What a server said, parsed and nothing more. Interpreting FAILURE (what to
/// try next) is `AuthProgress`'s job — parsing never decides, deciding never
/// parses, and conflating them is how FAILURE becomes success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Success,
    Failure { methods: Vec<String>, partial: bool },
    Banner { message: String, language: String },
    PkOk { alg: String, blob: Vec<u8> },
}

pub fn parse_server_message(payload: &[u8]) -> Result<AuthOutcome, AuthError> {
    let mut r = Reader::new(payload);
    match r.u8()? {
        MSG_USERAUTH_SUCCESS => Ok(AuthOutcome::Success),
        MSG_USERAUTH_FAILURE => {
            let methods = r.namelist()?;
            let partial = r.boolean()?;
            if partial && methods.is_empty() {
                return Err(AuthError::PartialWithNoMethods);
            }
            Ok(AuthOutcome::Failure { methods, partial })
        }
        MSG_USERAUTH_BANNER => {
            let message = String::from_utf8(r.string()?.to_vec())
                .map_err(|_| AuthError::UnexpectedMessage { byte: Some(MSG_USERAUTH_BANNER) })?;
            let language = String::from_utf8(r.string()?.to_vec())
                .map_err(|_| AuthError::UnexpectedMessage { byte: Some(MSG_USERAUTH_BANNER) })?;
            Ok(AuthOutcome::Banner { message, language })
        }
        MSG_USERAUTH_PK_OK => {
            let alg = std::str::from_utf8(r.string()?)
                .map_err(|_| AuthError::UnexpectedMessage { byte: Some(MSG_USERAUTH_PK_OK) })?
                .to_string();
            let blob = r.string()?.to_vec();
            Ok(AuthOutcome::PkOk { alg, blob })
        }
        other => Err(AuthError::UnexpectedMessage { byte: Some(other) }),
    }
}

/// The PK_OK echo MUST equal the key offered: same algorithm, same bytes. A
/// server accepting a different key than the query offered is answering a
/// question nobody asked, and proceeding to sign would bind our signature to
/// their substitution.
pub fn confirm_pk_ok(offered: &UserKey, outcome: &AuthOutcome) -> Result<(), AuthError> {
    match outcome {
        AuthOutcome::PkOk { alg, blob } if *alg == offered.alg && *blob == offered.blob => Ok(()),
        _ => Err(AuthError::PkOkMismatch),
    }
}

/// Where an authentication stands: which methods the server still allows and
/// which we have already spent. One struct, no hidden state — the driver owns
/// this, feeds it each FAILURE, and asks what to try next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProgress {
    tried: Vec<String>,
}

impl AuthProgress {
    pub fn new() -> Self {
        Self { tried: Vec::new() }
    }

    /// Fold a FAILURE into the progress: returns the methods still worth
    /// trying (server-offered, not yet spent). An empty return means the road
    /// ends here — the caller converts that to the right refusal, and the
    /// conversion names what was tried, never a bare "failed".
    pub fn on_failure(&mut self, methods: &[String]) -> Vec<String> {
        methods.iter().filter(|m| !self.tried.contains(m)).cloned().collect()
    }

    /// The next method to try, given what the server still allows. publickey
    /// first while unspent; password is REFUSED (not skipped, not deferred —
    /// a deferred password is a prompt the caller never shows); anything else
    /// is unsupported; nothing left is exhausted.
    pub fn next_method(&mut self, remaining: &[String]) -> Result<&'static str, AuthError> {
        if remaining.iter().any(|m| m == METHOD_PUBLICKEY) && !self.tried.contains(&METHOD_PUBLICKEY.to_string()) {
            self.tried.push(METHOD_PUBLICKEY.to_string());
            return Ok(METHOD_PUBLICKEY);
        }
        if remaining.iter().any(|m| m == METHOD_PASSWORD) {
            return Err(AuthError::PasswordRefused);
        }
        let offered: Vec<String> = remaining.to_vec();
        if offered.is_empty() {
            return Err(AuthError::Exhausted { tried: self.tried.clone() });
        }
        Err(AuthError::UnsupportedMethods { offered })
    }

    pub fn tried(&self) -> &[String] {
        &self.tried
    }
}

impl Default for AuthProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// An `id_ed25519` private key as parsed: the 32-byte seed plus the public
/// half. The seed zeroes on drop — a signing key copied into every core dump
/// is a backup nobody scheduled.
pub struct PrivateKey {
    seed: [u8; 32],
    public: [u8; 32],
    /// The key's comment (`user@host`, usually). Carried, never sent: the
    /// wire protocol has no field for it, and inventing one would leak it.
    pub comment: String,
}

/// Debug is hand-written and redacted: a signing key printed into a log is
/// a backup nobody scheduled (the E12 token precedent, applied to keys).
impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey {{ comment: {:?} }}", self.comment)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seed.zeroize();
    }
}

impl PrivateKey {
    pub fn signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.seed)
    }

    pub fn user_key(&self) -> UserKey {
        UserKey::ed25519(&self.public)
    }
}

const ARMOR_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const ARMOR_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const KEY_MAGIC: &[u8] = b"openssh-key-v1\x00";

/// Parse an OpenSSH-format private key file (`id_ed25519`, cipher `none`).
/// Every redundancy is structural: the public section must equal the private
/// section's embedded public, the private half's trailing public must equal
/// its seed's public, the checkints must agree, the padding must count up.
/// A file failing any one of them is corrupt — never half-trusted.
pub fn parse_openssh_private_key(pem: &str) -> Result<PrivateKey, AuthError> {
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let line = line.trim();
        if line == ARMOR_BEGIN {
            inside = true;
            continue;
        }
        if line == ARMOR_END {
            break;
        }
        if inside && !line.is_empty() {
            body.push_str(line);
        }
    }
    if body.is_empty() {
        return Err(AuthError::BadArmor);
    }
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| AuthError::BadArmor)?;
    let mut r = Reader::new(&raw);
    if r.bytes(KEY_MAGIC.len())? != KEY_MAGIC {
        return Err(AuthError::BadMagic);
    }
    let cipher = std::str::from_utf8(r.string()?).map_err(|_| AuthError::BadMagic)?;
    if cipher != "none" {
        return Err(AuthError::EncryptedKey { cipher: cipher.to_string() });
    }
    let kdf = std::str::from_utf8(r.string()?).map_err(|_| AuthError::BadMagic)?;
    if kdf != "none" {
        return Err(AuthError::UnsupportedKdf { kdf: kdf.to_string() });
    }
    let _kdfopt = r.string()?;
    let nkeys = r.u32()?;
    if nkeys != 1 {
        return Err(AuthError::MultiKey { nkeys });
    }
    // Public section: one string holding `string alg || string key`.
    let pubsec = r.string()?;
    let mut pr = Reader::new(pubsec);
    let pub_alg = std::str::from_utf8(pr.string()?).map_err(|_| AuthError::BadMagic)?;
    if pub_alg != "ssh-ed25519" {
        return Err(AuthError::BadKeyLength { part: "public key type", bytes: pubsec.len() });
    }
    let pubkey: [u8; 32] = pr
        .string()?
        .try_into()
        .map_err(|_| AuthError::BadKeyLength { part: "public key", bytes: pubsec.len() })?;
    // Private section: checkint pair, then keytype, pub, priv(64), comment,
    // padding. Cipher is none, so this reads directly.
    let privsec = r.string()?;
    let mut vr = Reader::new(privsec);
    let c1 = vr.u32()?;
    let c2 = vr.u32()?;
    if c1 != c2 {
        return Err(AuthError::BadCheckint);
    }
    let priv_alg = std::str::from_utf8(vr.string()?).map_err(|_| AuthError::BadMagic)?;
    if priv_alg != "ssh-ed25519" {
        return Err(AuthError::BadKeyLength { part: "private key type", bytes: privsec.len() });
    }
    let embedded_pub: [u8; 32] = vr
        .string()?
        .try_into()
        .map_err(|_| AuthError::BadKeyLength { part: "embedded public key", bytes: privsec.len() })?;
    if embedded_pub != pubkey {
        return Err(AuthError::KeyMismatch);
    }
    let priv64 = vr.string()?;
    if priv64.len() != 64 {
        return Err(AuthError::BadKeyLength { part: "private key", bytes: priv64.len() });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&priv64[..32]);
    // The trailing 32 bytes must be the seed's own public: derived, not
    // trusted from the file. A mismatch is corruption, full stop.
    let derived = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    if derived.as_bytes() != &embedded_pub {
        use zeroize::Zeroize;
        seed.zeroize();
        return Err(AuthError::KeyMismatch);
    }
    if &priv64[32..] != embedded_pub {
        use zeroize::Zeroize;
        seed.zeroize();
        return Err(AuthError::KeyMismatch);
    }
    let comment = String::from_utf8(vr.string()?.to_vec()).map_err(|_| AuthError::BadMagic)?;
    // Padding counts 1, 2, 3, ... to the block edge (block 8 pre-kex has no
    // meaning here; the file pads to 8 regardless).
    let pad = vr.rest();
    for (i, b) in pad.iter().enumerate() {
        if *b != (i as u8) + 1 {
            use zeroize::Zeroize;
            seed.zeroize();
            return Err(AuthError::BadPadding);
        }
    }
    Ok(PrivateKey { seed, public: pubkey, comment })
}
