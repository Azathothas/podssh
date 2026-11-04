//! The client protocol of magic-wormhole over a mailbox
//! (magic-wormhole/magic-wormhole-protocols:client-protocol.md, as its
//! Python library's `_key.py` speaks it), so that a peer of that library and
//! podssh's meet. Each end adds its `pake` phase, `{"pake_v1": HEX}` of
//! SPAKE2's symmetric message keyed by the whole code, with the AppID as its
//! identity; the two give a key of 32 bytes. Each later phase is sealed in
//! NaCl's SecretBox, a random nonce before it, under the key of
//! HKDF-SHA256(key, "wormhole:phase:" || SHA-256(side) || SHA-256(phase)),
//! the side the sender's, so that the mailbox cannot hand a message back to
//! the end that sealed it. The first is `version`: one that opens proves
//! that the other end holds the code, and one that does not ends the code
//! here (`scary`). Then the numbered phases from "0", each read in order,
//! each once, as the mailbox may repeat or reorder them.

use std::collections::HashSet;
use std::time::Duration;

use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity as SpakeIdentity, Password, Spake2};
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::mailbox::{Mailbox, Message, Mood};
use super::{hex, unhex, Code, Failed, APPID};
use crate::session::secret::{Entropy, OsEntropy};

/// The bytes of SecretBox's nonce, before each sealed message.
pub const NONCE: usize = 24;
/// The bytes of its tag.
pub const TAG: usize = 16;
/// The label of the key of each phase.
const PHASE_LABEL: &[u8] = b"wormhole:phase:";

/// Two ends of one code in one mailbox, from the key on.
pub struct Wormhole {
    mailbox: Mailbox,
    side: String,
    /// The mailbox's id.
    id: String,
    /// The nameplate while this side holds it.
    nameplate: Option<String>,
    spake: Option<Spake2<Ed25519Group>>,
    key: Option<Zeroizing<[u8; 32]>>,
    /// The side of the end that this one agreed a key with.
    peer: Option<String>,
    /// Messages of other sides that came before they were asked for.
    held: Vec<Message>,
    /// The phases of the peer read, so that a repeat is dropped.
    seen: HashSet<String>,
    sent: u64,
    read: u64,
    /// What this end says in its `version`, as `app_versions`.
    versions: Value,
    closed: bool,
}

impl Wormhole {
    /// Open the mailbox `id`, which this side reached by `nameplate`, and add
    /// this end's `pake` of `code`. `versions` goes in its `version` later.
    pub async fn open(
        mut mailbox: Mailbox,
        side: String,
        nameplate: String,
        id: String,
        code: &Code,
        versions: Value,
    ) -> Result<Wormhole, Failed> {
        let mut entropy = OsEntropy;
        let mut rng = Drawn { entropy: &mut entropy, failed: false };
        let (password, identity) = (Password::new(code.password()), SpakeIdentity::new(APPID.as_bytes()));
        let (spake, outbound) = Spake2::<Ed25519Group>::start_symmetric_with_rng(&password, &identity, &mut rng);
        if rng.failed {
            mailbox.end().await;
            return Err(Failed::NoRandom);
        }
        mailbox.open(&id).await?;
        let body = json!({ "pake_v1": hex(&outbound) }).to_string();
        mailbox.add("pake", body.as_bytes()).await?;
        Ok(Wormhole {
            mailbox,
            side,
            id,
            nameplate: Some(nameplate),
            spake: Some(spake),
            key: None,
            peer: None,
            held: Vec::new(),
            seen: HashSet::new(),
            sent: 0,
            read: 0,
            versions,
            closed: false,
        })
    }

    /// The mailbox's URL, as lines show it.
    pub fn shown(&self) -> &str {
        &self.mailbox.shown
    }

    /// Wait at most `wait` for another side's `pake`, and make the key with
    /// it: `false` when none came. That side is the peer for good: a later
    /// one changes nothing. The nameplate is released then, as both ends
    /// know the mailbox, and this end's `version` goes out sealed.
    pub async fn agree(&mut self, wait: Duration) -> Result<bool, Failed> {
        let deadline = Instant::now() + wait;
        let body = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some(message) = self.mailbox.message(left).await? else { return Ok(false) };
            if message.side == self.side {
                continue;
            }
            if message.phase == "pake" {
                self.peer = Some(message.side);
                break message.body;
            }
            self.held.push(message);
        };
        let made = self.spake.take().zip(pake_of(&body)).and_then(|(spake, theirs)| spake.finish(&theirs).ok());
        let made = Zeroizing::new(made.unwrap_or_default());
        if made.len() != 32 {
            let why = Failed::Peer("the other end's first message is not SPAKE2's".into());
            return Err(self.fail(Mood::Scary, why).await);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&made);
        self.key = Some(key);
        if let Some(nameplate) = self.nameplate.take() {
            self.mailbox.release(&nameplate).await?;
        }
        let versions = json!({ "abilities": [], "app_versions": self.versions }).to_string();
        self.add_sealed("version", versions.as_bytes()).await?;
        Ok(true)
    }

    /// The peer's `version`, within `wait`: its `app_versions`. One that
    /// does not open ends the code at this end, and the mailbox hears
    /// `scary`.
    pub async fn confirm(&mut self, wait: Duration) -> Result<Value, Failed> {
        let Some(body) = self.next_of_peer("version", wait).await? else {
            let why = format!("the other end gave its part of the key, then nothing for {} s", wait.as_secs());
            return Err(self.fail(Mood::Errory, Failed::Peer(why)).await);
        };
        let Some(plain) = self.unseal("version", &body) else {
            return Err(self.fail(Mood::Scary, Failed::WrongCode).await);
        };
        match serde_json::from_slice::<Value>(&plain) {
            Ok(versions) if versions.is_object() => Ok(versions["app_versions"].clone()),
            _ => Err(self.fail(Mood::Errory, Failed::Peer("the other end's version is not JSON".into())).await),
        }
    }

    /// Send `data` as the next numbered phase, sealed.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), Failed> {
        let phase = self.sent.to_string();
        self.sent += 1;
        self.add_sealed(&phase, data).await
    }

    /// The peer's next numbered phase, within `wait`, opened. One that does
    /// not open ends the exchange: the mailbox, or a third end, changed it.
    pub async fn receive(&mut self, wait: Duration) -> Result<Vec<u8>, Failed> {
        let phase = self.read.to_string();
        let Some(body) = self.next_of_peer(&phase, wait).await? else {
            let why = format!("the other end said nothing for {} s", wait.as_secs());
            return Err(self.fail(Mood::Errory, Failed::Peer(why)).await);
        };
        let Some(plain) = self.unseal(&phase, &body) else {
            let why = format!("message {phase} of the other end did not open: the mailbox changed it");
            return Err(self.fail(Mood::Scary, Failed::Peer(why)).await);
        };
        self.read += 1;
        Ok(plain)
    }

    /// Release the nameplate while this side holds it, close the mailbox
    /// with `mood`, and end the connection; once.
    pub async fn close(&mut self, mood: Mood) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(nameplate) = self.nameplate.take() {
            let _ = self.mailbox.release(&nameplate).await;
        }
        let _ = self.mailbox.close(&self.id, mood).await;
        self.mailbox.end().await;
    }

    /// Close with `mood`, then give `failed` back.
    pub async fn fail(&mut self, mood: Mood, failed: Failed) -> Failed {
        self.close(mood).await;
        failed
    }

    async fn add_sealed(&mut self, phase: &str, plain: &[u8]) -> Result<(), Failed> {
        let Some(key) = self.key.as_ref() else { return Err(Failed::Broken("no key was agreed".into())) };
        let sealed = seal(&phase_key(key, &self.side, phase), plain)?;
        self.mailbox.add(phase, &sealed).await
    }

    fn unseal(&self, phase: &str, body: &[u8]) -> Option<Vec<u8>> {
        let (key, peer) = (self.key.as_ref()?, self.peer.as_deref()?);
        open_sealed(&phase_key(key, peer, phase), body)
    }

    /// The body of the peer's `phase`, the first time it comes, within
    /// `wait`; `None` when it does not come.
    async fn next_of_peer(&mut self, phase: &str, wait: Duration) -> Result<Option<Vec<u8>>, Failed> {
        let Some(peer) = self.peer.clone() else { return Ok(None) };
        if let Some(at) = self.held.iter().position(|m| m.side == peer && m.phase == phase) {
            self.seen.insert(phase.to_string());
            return Ok(Some(self.held.remove(at).body));
        }
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some(message) = self.mailbox.message(left).await? else { return Ok(None) };
            if message.side != peer || self.seen.contains(&message.phase) {
                continue;
            }
            if message.phase == phase {
                self.seen.insert(message.phase);
                return Ok(Some(message.body));
            }
            if !self.held.iter().any(|m| m.side == peer && m.phase == message.phase) {
                self.held.push(message);
            }
        }
    }
}

/// The SPAKE2 message of a `pake` phase's body.
fn pake_of(body: &[u8]) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_slice(body).ok()?;
    unhex(value["pake_v1"].as_str()?)
}

/// The key of `phase` as `side` seals it, as magic-wormhole's
/// `derive_phase_key` makes it (HKDF-SHA256 with no salt).
pub fn phase_key(key: &[u8; 32], side: &str, phase: &str) -> Zeroizing<[u8; 32]> {
    let mut purpose = PHASE_LABEL.to_vec();
    purpose.extend_from_slice(&Sha256::digest(side.as_bytes()));
    purpose.extend_from_slice(&Sha256::digest(phase.as_bytes()));
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below HKDF-SHA256's 8160, so the expansion cannot fail.
    let _ = Hkdf::<Sha256>::new(None, key).expand(&purpose, &mut out[..]);
    out
}

/// `plain` sealed under `key`: a random nonce, then SecretBox's tag and the
/// ciphertext, as PyNaCl's `SecretBox.encrypt` writes them.
pub fn seal(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, Failed> {
    let mut nonce = [0u8; NONCE];
    OsEntropy.fill(&mut nonce).map_err(|_| Failed::NoRandom)?;
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let sealed = cipher.encrypt(Nonce::from_slice(&nonce), plain);
    let sealed = sealed.map_err(|_| Failed::Broken("a message could not be sealed".into()))?;
    Ok([&nonce[..], &sealed[..]].concat())
}

/// What [`seal`] sealed under `key`, or `None` for a body that does not
/// open: another key, or a byte changed.
pub fn open_sealed(key: &[u8; 32], body: &[u8]) -> Option<Vec<u8>> {
    if body.len() < NONCE + TAG {
        return None;
    }
    let (nonce, sealed) = body.split_at(NONCE);
    XSalsa20Poly1305::new(Key::from_slice(key)).decrypt(Nonce::from_slice(nonce), sealed).ok()
}

/// rand_core 0.6's traits over podssh's own source, for SPAKE2's scalar: a
/// draw that fails is marked, and the run that made it stops.
struct Drawn<'a> {
    entropy: &'a mut dyn Entropy,
    failed: bool,
}

impl rand_core_06::RngCore for Drawn<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.entropy.fill(dest).is_err() {
            self.failed = true;
            dest.fill(0);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for Drawn<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::secret::NoRandom;

    // Computed with Python's hmac and hashlib (HKDF by RFC 5869 written out,
    // with magic-wormhole's purpose), software that podssh did not write.
    const VERSION_KEY: &str = "65187c8822d10970289e2eaa1eb623d7c90d0ff2af2507fcdac4f1a08bf13fa9";
    const PHASE_0_KEY: &str = "0943da0b4118c8a69cffd544d1d6a3f4e1ed03d98051724095b4d794a8ed69c5";
    const OTHER_SIDE_KEY: &str = "83dc867fb920adfca223cf78e4b15dbf2ad019afc25f3976175069bd1f893225";

    #[test]
    fn the_key_of_a_phase_is_magic_wormholes_by_side_and_phase() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(hex(&phase_key(&key, "0123456789", "version")[..]), VERSION_KEY);
        assert_eq!(hex(&phase_key(&key, "0123456789", "0")[..]), PHASE_0_KEY);
        assert_eq!(hex(&phase_key(&key, "abcdefabcd", "version")[..]), OTHER_SIDE_KEY);
    }

    #[test]
    fn a_sealed_message_opens_under_its_key_alone_and_whole() {
        let (key, other) = ([7u8; 32], [8u8; 32]);
        let sealed = seal(&key, b"the operator's part").unwrap();
        assert_eq!(sealed.len(), NONCE + TAG + b"the operator's part".len());
        assert_eq!(open_sealed(&key, &sealed).as_deref(), Some(&b"the operator's part"[..]));
        assert_eq!(open_sealed(&other, &sealed), None, "another key");
        let mut changed = sealed.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(open_sealed(&key, &changed), None, "a byte changed");
        assert_eq!(open_sealed(&key, &sealed[..NONCE + TAG - 1]), None, "cut short");
        assert_ne!(seal(&key, b"x").unwrap()[..NONCE], seal(&key, b"x").unwrap()[..NONCE], "a nonce of its own");
    }

    fn start(code: &str, entropy: &mut dyn Entropy) -> (Spake2<Ed25519Group>, Vec<u8>, bool) {
        let mut rng = Drawn { entropy, failed: false };
        let (password, identity) = (Password::new(code.as_bytes()), SpakeIdentity::new(APPID.as_bytes()));
        let (spake, message) = Spake2::<Ed25519Group>::start_symmetric_with_rng(&password, &identity, &mut rng);
        (spake, message, rng.failed)
    }

    #[test]
    fn two_ends_of_one_code_agree_a_key_and_of_two_codes_do_not() {
        let (mut a, mut b) = (OsEntropy, OsEntropy);
        let ((one, to_two, _), (two, to_one, _)) = (start("7-a-b", &mut a), start("7-a-b", &mut b));
        assert_eq!((to_two.len(), to_two[0]), (33, b'S'), "SPAKE2's symmetric message");
        let (k1, k2) = (one.finish(&to_one).unwrap(), two.finish(&to_two).unwrap());
        assert_eq!(k1.len(), 32);
        assert_eq!(k1, k2);
        let ((one, to_two, _), (two, to_one, _)) = (start("7-a-b", &mut a), start("7-a-c", &mut b));
        assert_ne!(one.finish(&to_one).unwrap(), two.finish(&to_two).unwrap());
    }

    struct Dry;

    impl Entropy for Dry {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), NoRandom> {
            Err(NoRandom)
        }
    }

    #[test]
    fn a_scalar_whose_draw_failed_is_marked_and_never_used() {
        let (_, _, failed) = start("7-a-b", &mut Dry);
        assert!(failed);
        let (_, _, failed) = start("7-a-b", &mut OsEntropy);
        assert!(!failed);
    }

    #[test]
    fn a_pake_body_is_read_as_magic_wormhole_writes_it() {
        assert_eq!(pake_of(br#"{"pake_v1": "53ab"}"#), Some(vec![0x53, 0xab]));
        assert_eq!(pake_of(br#"{"pake_v2": "53ab"}"#), None);
        assert_eq!(pake_of(b"not json"), None);
    }
}
