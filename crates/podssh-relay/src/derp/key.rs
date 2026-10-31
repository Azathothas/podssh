//! The keys of DERP, and the boxes of its handshake (tailscale/tailscale:
//! derp/derp_client.go and types/key/node.go at v1.104.4). A key is a
//! Curve25519 key, the address of an end on a server. The client seals its
//! info to the server's key with NaCl's `crypto_box` (X25519, XSalsa20,
//! Poly1305) under a random nonce, and the server seals its own back; a
//! sealed box is the nonce, then the box, whose tag is first, as NaCl writes
//! it. `crypto_box` is pure Rust, so the crate stays free of C.
//!
//! A node's key is derived from the seed of its identity, with a label of
//! its own: its address stays across runs as its identity does, and no key
//! does two jobs (`crate::identity`). A client's is new for each run, so two
//! clients of one user never hold one key on a server, which would take
//! them for one client connected twice.

use std::fmt;

use crypto_box::aead::Aead;
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::frame::NONCE;
use crate::identity::Identity;
use crate::session::secret::{Entropy, NoRandom};

/// The label of a node's DERP key, derived from its seed.
const NODE_LABEL: &[u8] = b"podssh derp key, version 1";
/// The name by which a server may count its clients (`ClientInfo.AppName`).
pub const APP_NAME: &str = "podssh";

/// A key of DERP: the address of an end on a server.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(pub [u8; 32]);

impl Key {
    /// The key in lower-case hex.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The first 8 hex digits, for a line.
    pub fn short(&self) -> String {
        self.hex()[..8].to_string()
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.short())
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({})", self.short())
    }
}

/// An end's secret DERP key, with its public half. It prints as the public
/// half, never as the secret.
pub struct Secret {
    secret: SecretKey,
    public: Key,
}

impl Secret {
    /// A node's key, from the seed of its identity.
    pub fn of_node(identity: &Identity) -> Secret {
        let seed = identity.seed();
        let mut bytes = Zeroizing::new([0u8; 32]);
        // 32 bytes is within HKDF-SHA256's 8160, so the expansion cannot fail.
        Hkdf::<Sha256>::new(None, &seed[..]).expand(NODE_LABEL, &mut bytes[..]).expect("HKDF-SHA256 gives 32 bytes");
        Secret::from_bytes(*bytes)
    }

    /// A client's key for this run.
    pub fn random(entropy: &mut dyn Entropy) -> Result<Secret, NoRandom> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        entropy.fill(&mut bytes[..])?;
        Ok(Secret::from_bytes(*bytes))
    }

    /// The key of these 32 bytes, clamped as X25519 clamps.
    pub fn from_bytes(bytes: [u8; 32]) -> Secret {
        let secret = SecretKey::from_bytes(bytes);
        let public = Key(secret.public_key().to_bytes());
        Secret { secret, public }
    }

    pub fn public(&self) -> Key {
        self.public
    }

    /// `plain` sealed to the key `to`, under `nonce`: the nonce, then the box.
    pub fn seal(&self, to: &Key, plain: &[u8], nonce: [u8; NONCE]) -> Vec<u8> {
        let sealer = SalsaBox::new(&PublicKey::from(to.0), &self.secret);
        // The box of a message in memory cannot fail: XSalsa20 has no limit
        // that a frame of DERP reaches.
        let sealed = sealer.encrypt(&crypto_box::Nonce::from(nonce), plain).expect("a box of a message in memory");
        [&nonce[..], &sealed[..]].concat()
    }

    /// What `sealed` holds, when the key `from` sealed it to this key.
    pub fn open(&self, from: &Key, sealed: &[u8]) -> Result<Vec<u8>, String> {
        if sealed.len() < NONCE + 16 {
            return Err(format!("a sealed box of {} bytes, too short", sealed.len()));
        }
        let mut nonce = [0u8; NONCE];
        nonce.copy_from_slice(&sealed[..NONCE]);
        let opener = SalsaBox::new(&PublicKey::from(from.0), &self.secret);
        opener
            .decrypt(&crypto_box::Nonce::from(nonce), &sealed[NONCE..])
            .map_err(|_| "a box that does not open: another key sealed it, or it changed on its way".to_string())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(public {})", self.public)
    }
}

/// The client's info, as Go's `json.Marshal` writes `ClientInfo` with no
/// mesh key: the version of the protocol, the pings that it does not
/// acknowledge, and the name of the program, which a server may count by,
/// or refuse (derper's `--disallow-app-names`).
pub fn client_info_json(app: &str) -> Vec<u8> {
    format!(r#"{{"version":{},"CanAckPings":false,"AppName":"{app}"}}"#, super::frame::VERSION).into_bytes()
}

/// What the server says of itself: its version, and the rate at which it
/// would have its clients send, when it names one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerInfo {
    pub version: i64,
    /// Bytes each second, and the burst, of a token bucket; 0 for none.
    pub bytes_per_second: u64,
    pub burst: u64,
}

/// The names of Go's `ServerInfo`: `version` by its tag, the bucket by the
/// field names, which Go's decoder matches in any case and serde does not.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ServerInfoJson {
    #[serde(alias = "Version")]
    version: i64,
    #[serde(rename = "TokenBucketBytesPerSecond", alias = "tokenBucketBytesPerSecond")]
    per_second: i64,
    #[serde(rename = "TokenBucketBytesBurst", alias = "tokenBucketBytesBurst")]
    burst: i64,
}

/// The server's info, from its JSON.
pub fn server_info(json: &[u8]) -> Result<ServerInfo, String> {
    let info: ServerInfoJson =
        serde_json::from_slice(json).map_err(|e| format!("the server's info is not the JSON of DERP: {e}"))?;
    Ok(ServerInfo {
        version: info.version,
        bytes_per_second: u64::try_from(info.per_second).unwrap_or(0),
        burst: u64::try_from(info.burst).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A vector of NaCl's `crypto_box` from PHP Sodium Compat, as RustCrypto's
    // crypto_box 0.9.1 carries it in its tests/lib.rs: bytes of software that
    // podssh did not write.
    const ALICE_SECRET: &str = "68f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d4c";
    const ALICE_PUBLIC: &str = "ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d";
    const BOB_SECRET: &str = "b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b";
    const BOB_PUBLIC: &str = "e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754";
    const VECTOR_NONCE: &str = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
    const PLAINTEXT: &str = concat!(
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c6129",
        "6cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde",
        "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705",
    );
    const CIPHERTEXT: &str = concat!(
        "c03f27d188ef650cd12936913137bb17ed4c98c2648939e2e1d2e855470a7b8c632cabfd5ab3b3c2d313dc8c9ecf5da1",
        "73e1f9c318cdef1dced6d2519e695085e6b5c401a2bd5331442986c7076d412625497c4cb2fd94c6f103961033b2c930",
        "d7e82e0341f29d3879bd6ab9d881ea3a1f365d634e653c6e171aac7fc1e76934d23be6f04a54010808dbf0f9bd30f63b",
        "68d026",
    );

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    fn key32(hex: &str) -> [u8; 32] {
        bytes(hex).try_into().unwrap()
    }

    #[test]
    fn a_box_is_the_nonce_and_then_nacl_s_box_of_the_same_bytes() {
        let alice = Secret::from_bytes(key32(ALICE_SECRET));
        let bob = Secret::from_bytes(key32(BOB_SECRET));
        assert_eq!(alice.public(), Key(key32(ALICE_PUBLIC)));
        assert_eq!(bob.public(), Key(key32(BOB_PUBLIC)));
        let nonce: [u8; NONCE] = bytes(VECTOR_NONCE).try_into().unwrap();
        let sealed = alice.seal(&bob.public(), &bytes(PLAINTEXT), nonce);
        assert_eq!(sealed, [bytes(VECTOR_NONCE), bytes(CIPHERTEXT)].concat());
        assert_eq!(bob.open(&alice.public(), &sealed).unwrap(), bytes(PLAINTEXT));
    }

    #[test]
    fn a_box_opens_with_its_two_keys_alone_and_not_once_changed() {
        let node = Secret::from_bytes([1u8; 32]);
        let server = Secret::from_bytes([2u8; 32]);
        let other = Secret::from_bytes([3u8; 32]);
        let sealed = node.seal(&server.public(), b"{\"version\":2}", [9u8; NONCE]);
        assert_eq!(&sealed[..NONCE], &[9u8; NONCE]);
        assert_eq!(sealed.len(), NONCE + 16 + 13);
        assert_eq!(server.open(&node.public(), &sealed).unwrap(), b"{\"version\":2}");
        assert!(other.open(&node.public(), &sealed).is_err());
        let mut changed = sealed.clone();
        changed[NONCE + 20] ^= 1;
        assert!(server.open(&node.public(), &changed).is_err());
        assert!(server.open(&node.public(), &sealed[..NONCE + 15]).is_err());
    }

    #[test]
    fn a_node_s_key_comes_from_its_seed_and_is_not_its_channel_key() {
        let identity = Identity::from_seed(&[5u8; 32]);
        let first = Secret::of_node(&identity);
        let again = Secret::of_node(&Identity::from_seed(&[5u8; 32]));
        let another = Secret::of_node(&Identity::from_seed(&[6u8; 32]));
        assert_eq!(first.public(), again.public());
        assert_ne!(first.public(), another.public());
        assert_ne!(&first.public().0, identity.dh_public());
        assert_ne!(first.public().0, identity.public().0);
    }

    #[test]
    fn the_client_s_info_is_the_json_that_go_writes_and_the_server_s_is_read_in_both_cases() {
        assert_eq!(client_info_json(APP_NAME), br#"{"version":2,"CanAckPings":false,"AppName":"podssh"}"#);
        let go = server_info(br#"{"version":2,"TokenBucketBytesPerSecond":5000,"TokenBucketBytesBurst":9000}"#);
        assert_eq!(go, Ok(ServerInfo { version: 2, bytes_per_second: 5000, burst: 9000 }));
        let camel = server_info(br#"{"Version":2,"tokenBucketBytesPerSecond":1}"#).unwrap();
        assert_eq!((camel.version, camel.bytes_per_second, camel.burst), (2, 1, 0));
        assert_eq!(server_info(br#"{"version":2,"later":true}"#).unwrap().version, 2);
        assert!(server_info(b"not json").is_err());
    }
}
