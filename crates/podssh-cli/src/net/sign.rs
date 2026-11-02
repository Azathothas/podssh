//! The owner's signature of the net's document (T-429): OpenSSH's SSHSIG
//! over the document's bytes, in the namespace `podssh-net`, so that
//! `ssh-keygen -Y verify` checks a document as podssh does, and a document
//! that `ssh-keygen -Y sign` signed is taken: software that podssh did not
//! write. The signed form is the document's bytes, then the armoured
//! signature, in one file that is replaced whole; the two parts apart, as
//! `ssh-keygen` reads and writes them, are a document and `FILE.sig`.

use std::path::{Path, PathBuf};

use podssh_ssh::russh::keys::ssh_key::HashAlg;
use podssh_ssh::russh::keys::PublicKey;
use podssh_ssh::sshsig;
use sha2::Digest;

use super::doc::Doc;
use crate::keygen_sign::{self, Signing};

/// The namespace of the signature: a signature of the net is no signature
/// of git's, nor of a file's.
pub const NAMESPACE: &str = "podssh-net";
/// Where the armoured signature starts, on a line of its own.
const ARMOUR: &[u8] = b"-----BEGIN SSH SIGNATURE-----";

/// A document with its owner's signature, both checked.
#[derive(Debug, Clone)]
pub struct Signed {
    pub doc: Doc,
    /// The document's bytes, as signed.
    pub bytes: Vec<u8>,
    /// The armoured signature.
    pub signature: String,
}

impl Signed {
    /// The signed form: the document, then its signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.bytes[..], self.signature.as_bytes()].concat()
    }

    /// The owner, as the channel names it (`podssh_relay::e2e::net`): the
    /// SHA-256 of the owner key's fingerprint.
    pub fn owner_id(&self) -> [u8; 32] {
        owner_id(&self.doc.owner)
    }
}

/// The owner of a document as the channel names it.
pub fn owner_id(owner: &str) -> [u8; 32] {
    let shown = PublicKey::from_openssh(owner).map(|key| podssh_ssh::known_hosts::fingerprint(&key));
    sha2::Sha256::digest(shown.unwrap_or_default().as_bytes()).into()
}

/// The owner key's fingerprint, as `ssh-keygen -l` shows it.
pub fn owner_fingerprint(owner: &str) -> String {
    PublicKey::from_openssh(owner).map(|key| podssh_ssh::known_hosts::fingerprint(&key)).unwrap_or_default()
}

/// The two parts of the signed form: the document's bytes and the armour.
pub fn split(signed: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let at = (0..signed.len())
        .find(|&i| signed[i..].starts_with(ARMOUR) && (i == 0 || signed[i - 1] == b'\n'))
        .ok_or("no signature after the document: a net's document is signed by its owner")?;
    Ok(signed.split_at(at))
}

/// Check `bytes` and its armoured `signature`: a signature in the namespace
/// of the net, made by the key that the document names as its owner, over
/// these bytes. A document that another key signed is refused, whatever
/// its owner field says.
pub fn verify(bytes: &[u8], signature: &[u8]) -> Result<Signed, String> {
    let doc = Doc::parse(bytes)?;
    let read = sshsig::read_signature(signature)?;
    if read.certificate.is_some() {
        return Err("the document is signed with a certificate; a net's owner signs with a plain key".into());
    }
    let owner = PublicKey::from_openssh(&doc.owner).map_err(|e| format!("the owner's key: {e}"))?;
    if read.signature.public_key() != owner.key_data() {
        let by = PublicKey::new(read.signature.public_key().clone(), "");
        return Err(format!(
            "the document is signed by {}, not by its owner {}",
            podssh_ssh::known_hosts::fingerprint(&by),
            podssh_ssh::known_hosts::fingerprint(&owner)
        ));
    }
    let prehash = sshsig::digest(&mut &bytes[..], read.signature.hash_alg()).map_err(|e| e.to_string())?;
    sshsig::check(&read.signature, NAMESPACE, &prehash)?;
    let signature = String::from_utf8(signature.to_vec()).map_err(|_| "the signature is not text".to_string())?;
    Ok(Signed { doc, bytes: bytes.to_vec(), signature })
}

/// The signed form, checked.
pub fn verify_signed(signed: &[u8]) -> Result<Signed, String> {
    let (bytes, signature) = split(signed)?;
    verify(bytes, signature)
}

/// The document of `path`, signed: the signed form, or a document whose
/// signature is `PATH.sig`, as `ssh-keygen -Y sign` writes it.
pub fn read_file(path: &Path) -> Result<Signed, String> {
    let shown = path.display();
    let text = std::fs::read(path).map_err(|e| format!("{shown}: {e}"))?;
    if text.len() > podssh_relay::cache::MAX_FILE as usize {
        return Err(format!("{shown} is larger than a net's document can be"));
    }
    if split(&text).is_ok() {
        return verify_signed(&text).map_err(|why| format!("{shown}: {why}"));
    }
    let sig_path = PathBuf::from(format!("{}.sig", path.display()));
    let signature =
        std::fs::read(&sig_path).map_err(|e| format!("{shown} holds no signature, and {}: {e}", sig_path.display()))?;
    verify(&text, &signature).map_err(|why| format!("{shown}: {why}"))
}

/// The owner's key that signs: `key` when named (a private key, or a public
/// one whose private half the agent holds), else the agent's key or the
/// file of `~/.ssh` whose public half is `owner`. Its passphrase, if any, is
/// asked once.
pub(crate) fn signing_for(owner: &str, key: Option<&Path>) -> Result<Signing, String> {
    let owner = PublicKey::from_openssh(owner).map_err(|e| format!("the owner's key: {e}"))?;
    let signing = match key {
        Some(path) => named(path)?,
        None => found(&owner)?,
    };
    let public = public_of(&signing);
    if public.key_data() != owner.key_data() {
        return Err(format!(
            "the key {} is not the net's owner {}",
            podssh_ssh::known_hosts::fingerprint(&public),
            podssh_ssh::known_hosts::fingerprint(&owner)
        ));
    }
    Ok(signing)
}

/// Sign `doc` with `signing`, then check what was signed as each member
/// will check it.
pub(crate) fn sign_with(doc: &Doc, signing: &Signing) -> Result<Signed, String> {
    let bytes = doc.to_bytes();
    let signature = sign_bytes(signing, &bytes)?;
    verify(&bytes, signature.as_bytes())
}

fn public_of(signing: &Signing) -> PublicKey {
    match signing {
        Signing::Agent(public) => public.clone(),
        Signing::Key(key) => key.public_key().clone(),
    }
}

/// The owner's public key of `path`, for `net init`: a private key, a
/// public one, or `FILE.pub`.
pub(crate) fn owner_of(path: &Path) -> Result<(String, Signing), String> {
    let signing = named(path)?;
    let public = public_of(&signing);
    let line = PublicKey::new(public.key_data().clone(), "").to_openssh().map_err(|e| e.to_string())?;
    Ok((line.trim().to_string(), signing))
}

/// The armoured signature of `bytes`, as `ssh-keygen -Y sign` makes it,
/// with SHA-512.
pub(crate) fn sign_bytes(signing: &Signing, bytes: &[u8]) -> Result<String, String> {
    let prehash = sshsig::digest(&mut &bytes[..], HashAlg::Sha512).map_err(|e| e.to_string())?;
    let signature = match signing {
        Signing::Key(key) => sshsig::sign(key, NAMESPACE, HashAlg::Sha512, &prehash)?,
        Signing::Agent(public) => keygen_sign::with_agent(public, NAMESPACE, HashAlg::Sha512, &prehash)?,
    };
    sshsig::armour(&signature, None)
}

/// The key of a file that the user named, as `ssh-keygen -Y sign -f` takes
/// it; never a certificate.
fn named(path: &Path) -> Result<Signing, String> {
    match keygen_sign::signer(path, false)? {
        (_, Some(_)) => Err(format!("{}: a certificate; a net's owner signs with a plain key", path.display())),
        (signing, None) => Ok(signing),
    }
}

/// The owner's key where no file is named: the agent's, else a key of
/// `~/.ssh` whose public half is the owner.
fn found(owner: &PublicKey) -> Result<Signing, String> {
    if keygen_sign::agent_has(owner) {
        return Ok(Signing::Agent(owner.clone()));
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
    for name in ["id_ed25519", "id_ecdsa", "id_ed25519_sk", "id_ecdsa_sk", "id_rsa"] {
        let Some(path) = home.as_ref().map(|home| home.join(".ssh").join(name)) else { break };
        let public = std::fs::read_to_string(podssh_ssh::keygen::public_path(&path)).ok();
        if public.as_deref().and_then(keygen_sign::public_line).is_some_and(|k| k.key_data() == owner.key_data()) {
            return named(&path);
        }
    }
    Err(format!(
        "the owner's key {} is not in the agent nor in ~/.ssh: name it with --owner-key FILE",
        podssh_ssh::known_hosts::fingerprint(owner)
    ))
}
