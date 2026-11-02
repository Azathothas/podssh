//! What the lists do to a connection (T-505): the handshake offers russh
//! the lists in place of its own; a key of the user that the lists refuse
//! is not offered; and a host key, or a host certificate, that they refuse
//! ends the connection before the login, as OpenSSH 10.3p1 ends it
//! (`verify_host_key_callback` of its `sshconnect2.c`).

use std::borrow::Cow;
use std::path::PathBuf;

use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{cipher, kex, mac, Preferred};

use super::names::{certified, host_keys, KEX_EXTENSIONS};
use super::{Algorithms, Kind};
use crate::known_hosts::{self, Marker};

/// `preferred` with each list that was given in place of russh's: the
/// ciphers, the MACs, the key exchanges (and the extensions that russh asks
/// for with them), and the plain host key algorithms. The certificates of
/// a host are [`certificates`]'.
pub(crate) fn restrict(preferred: &mut Preferred, chosen: &Algorithms) {
    if let Some(list) = &chosen.ciphers {
        preferred.cipher = Cow::Owned(list.iter().filter_map(|n| cipher::Name::try_from(n.as_str()).ok()).collect());
    }
    if let Some(list) = &chosen.macs {
        preferred.mac = Cow::Owned(list.iter().filter_map(|n| mac::Name::try_from(n.as_str()).ok()).collect());
    }
    if let Some(list) = &chosen.kex {
        let mut names: Vec<kex::Name> = list.iter().filter_map(|n| kex::Name::try_from(n.as_str()).ok()).collect();
        names.extend(KEX_EXTENSIONS);
        preferred.kex = Cow::Owned(names);
    }
    if let Some(list) = &chosen.host_key {
        let keys = host_keys();
        let plain: Vec<Algorithm> =
            list.iter().filter_map(|name| keys.iter().find(|a| a.as_str() == name.as_str())).cloned().collect();
        preferred.key = Cow::Owned(plain);
    }
}

/// The host key algorithms of the list given whose certificate a host that
/// a `@cert-authority` line names is asked for (T-027), in the list's order.
pub(crate) fn certificates(list: &[String]) -> Vec<Algorithm> {
    let keys = host_keys();
    list.iter()
        .filter_map(|name| keys.iter().find(|a| certified(a) && a.to_certificate_type() == *name))
        .cloned()
        .collect()
}

/// The names of RSA's signatures, the strongest first, with their hash.
const RSA: [(&str, Option<HashAlg>); 3] =
    [("rsa-sha2-512", Some(HashAlg::Sha512)), ("rsa-sha2-256", Some(HashAlg::Sha256)), ("ssh-rsa", None)];

/// The bits of an RSA key; `None` for another.
fn rsa_bits(key: &KeyData) -> Option<u32> {
    key.rsa().map(|rsa| rsa.key_size())
}

/// What a key of the user must meet to be offered: its algorithm in
/// `PubkeyAcceptedAlgorithms`, and an RSA key of `RequiredRSASize` at least,
/// as OpenSSH 10.3p1 skips another (`key_type_allowed_by_config`, and
/// `sshkey_check_rsa_length`, of its `sshconnect2.c`).
#[derive(Debug, Clone)]
pub(crate) struct UserKeys {
    accepted: Vec<String>,
    floor: u32,
}

impl UserKeys {
    pub(crate) fn of(chosen: &Algorithms) -> UserKeys {
        UserKeys { accepted: chosen.list(Kind::Pubkey), floor: chosen.rsa_floor() }
    }

    fn accepts(&self, name: &str) -> bool {
        self.accepted.iter().any(|a| a == name)
    }

    /// Why `key` is not offered; `None` when it is.
    pub(crate) fn refuses(&self, key: &PublicKey) -> Option<String> {
        if let Some(bits) = rsa_bits(key.key_data()) {
            // An RSA key goes with any of RSA's signatures, as OpenSSH takes it.
            if !RSA.iter().any(|(name, _)| self.accepts(name)) {
                return Some("PubkeyAcceptedAlgorithms names no signature of RSA".into());
            }
            let floor = self.floor;
            return (bits < floor).then(|| format!("an RSA key of {bits} bits, under RequiredRSASize {floor}"));
        }
        let algorithm = key.algorithm();
        let name = algorithm.as_str();
        (!self.accepts(name)).then(|| format!("{name} is not in PubkeyAcceptedAlgorithms"))
    }

    /// The hash of an RSA signature, from `best`, the best that the server
    /// lists: `best` when the list takes it, else the list's first of RSA.
    /// OpenSSH takes the list's first that the server lists; russh tells
    /// the best alone, and a server that lists one of SHA-2 lists both.
    pub(crate) fn rsa_hash(&self, best: Option<HashAlg>) -> Option<HashAlg> {
        let named = RSA.iter().find(|(_, hash)| *hash == best).map(|(name, _)| *name);
        if named.is_some_and(|name| self.accepts(name)) {
            return best;
        }
        self.accepted.iter().find_map(|a| RSA.iter().find(|(name, _)| name == a)).map_or(best, |(_, hash)| *hash)
    }
}

/// What a host key must meet, as OpenSSH 10.3p1 checks it: an RSA key, and
/// the RSA key of the CA of a certificate, of `RequiredRSASize` at least;
/// and the signature of a CA that a `@cert-authority` line names for the
/// host, one of `CASignatureAlgorithms`.
#[derive(Debug, Clone)]
pub(crate) struct HostLimits {
    floor: u32,
    ca_signatures: Vec<String>,
}

impl Default for HostLimits {
    fn default() -> Self {
        HostLimits::of(&Algorithms::default())
    }
}

impl HostLimits {
    pub(crate) fn of(chosen: &Algorithms) -> HostLimits {
        HostLimits { floor: chosen.rsa_floor(), ca_signatures: chosen.list(Kind::CaSignature) }
    }

    /// Why the host key of `name` that the server offered is refused;
    /// `None` when these limits take it. `files` are the known_hosts files.
    pub(crate) fn refuses(&self, offered: &PublicKeyOrCertificate, files: &[PathBuf], name: &str) -> Option<String> {
        let key = offered.public_key();
        if let Some(bits) = rsa_bits(key.key_data()).filter(|bits| *bits < self.floor) {
            return Some(format!(
                "the host key of '{name}' is an RSA key of {bits} bits, under RequiredRSASize {}. Refusing to connect.",
                self.floor
            ));
        }
        let cert = offered.certificate()?;
        // A certificate is no stronger than the key of the CA that signed it.
        if let Some(bits) = rsa_bits(cert.signature_key()).filter(|bits| *bits < self.floor) {
            return Some(format!(
                "the host certificate of '{name}' is signed by an RSA key of {bits} bits, under RequiredRSASize {}. \
                 Refusing to connect.",
                self.floor
            ));
        }
        let algorithm = cert.signature().algorithm();
        let signed = algorithm.as_str();
        if self.ca_signatures.iter().any(|a| a == signed) {
            return None;
        }
        // The certificate of a CA that no line names is checked as its plain
        // key, as OpenSSH falls back: the list holds for a named CA alone.
        let named = known_hosts::entries_for(files, name)
            .iter()
            .any(|e| e.marker == Some(Marker::CertAuthority) && e.key.key_data() == cert.signature_key());
        named.then(|| {
            format!(
                "the host certificate of '{name}' is signed with {signed}, which CASignatureAlgorithms does not \
                 name. Refusing to connect."
            )
        })
    }
}
