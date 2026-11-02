//! What podssh offers of each list when no keyword gives one, and what it
//! speaks, which a list may name: russh's own lists for the handshake, as
//! `run_config` offers them, and the key algorithms that podssh signs a
//! login with and checks a CA's signature with.

use russh::keys::Algorithm;
use russh::{cipher, kex, mac, Preferred};

use super::Kind;

/// The names of russh's list of key exchanges that are no exchange but
/// the extensions that a client asks for (RFC 8308, and OpenSSH's strict
/// key exchange): never a name of a list, and always offered.
pub(super) const KEX_EXTENSIONS: [kex::Name; 4] = [
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

/// The key algorithms that podssh signs a login with: its key files and an
/// agent's keys, a security key's among them; `ssh-rsa`, SHA-1, only for
/// an agent's key when the server lists nothing better (T-257).
const USER_KEYS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
];

/// The signatures of a CA that podssh checks on a host certificate (T-027):
/// OpenSSH's `SSH_ALLOWED_CA_SIGALGS` that ssh-key verifies, and `ssh-rsa`,
/// which podssh took before these lists applied.
const CA_SIGNATURES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
];

/// The text of one of russh's names.
fn text<N: AsRef<str> + ?Sized>(name: &N) -> String {
    name.as_ref().to_string()
}

/// podssh's own list of `kind`, in its order.
pub(super) fn own(kind: Kind) -> Vec<String> {
    match kind {
        Kind::Ciphers => Preferred::DEFAULT.cipher.iter().map(text).collect(),
        Kind::Macs => Preferred::DEFAULT.mac.iter().map(text).collect(),
        Kind::Kex => Preferred::DEFAULT.kex.iter().filter(|k| !KEX_EXTENSIONS.contains(*k)).map(text).collect(),
        Kind::HostKey => host_key_names(),
        Kind::Pubkey => USER_KEYS.iter().map(|n| n.to_string()).collect(),
        Kind::CaSignature => CA_SIGNATURES.iter().map(|n| n.to_string()).collect(),
    }
}

/// Each name of `kind` that podssh speaks: none of russh's `none` and
/// `clear`, which carry the bytes in the clear, and no extension.
pub(super) fn spoken(kind: Kind) -> Vec<String> {
    let clear = |name: &String| !matches!(name.as_str(), "none" | "clear");
    match kind {
        Kind::Ciphers => cipher::ALL_CIPHERS.iter().map(|n| text(*n)).filter(clear).collect(),
        Kind::Macs => mac::ALL_MAC_ALGORITHMS.iter().map(|n| text(*n)).filter(clear).collect(),
        Kind::Kex => kex::ALL_KEX_ALGORITHMS
            .iter()
            .filter(|k| !KEX_EXTENSIONS.contains(**k))
            .map(|n| text(*n))
            .filter(clear)
            .collect(),
        Kind::HostKey | Kind::Pubkey | Kind::CaSignature => own(kind),
    }
}

/// The plain host key algorithms that podssh asks for: russh's, in its
/// order.
pub(super) fn host_keys() -> Vec<Algorithm> {
    Preferred::DEFAULT.key.to_vec()
}

/// Whether a host is asked for a certificate of `algorithm` (T-027): not
/// of SHA-1 RSA, nor of an algorithm that ssh-key does not know.
pub(super) fn certified(algorithm: &Algorithm) -> bool {
    !matches!(algorithm, Algorithm::Rsa { hash: None } | Algorithm::Dsa | Algorithm::Other(_))
}

/// The host key algorithms by name, as OpenSSH lists them: the
/// certificates first, then the plain keys.
fn host_key_names() -> Vec<String> {
    let keys = host_keys();
    let certificates = keys.iter().filter(|a| certified(a)).map(Algorithm::to_certificate_type);
    certificates.chain(keys.iter().map(|a| a.as_str().to_string())).collect()
}
