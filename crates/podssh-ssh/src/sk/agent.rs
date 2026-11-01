//! The security keys that `podssh agent` holds (T-229). russh's agent
//! server cannot sign with an `sk-` key, so the front of the agent (where
//! the store of credentials answers, T-228) keeps them itself: it takes the
//! request to add one (with the constraint `sk-provider@openssh.com` that
//! OpenSSH's `ssh-add` sends, and a lifetime), lists them after the keys of
//! russh's server, signs with the device, and removes them. A key needs no
//! secret in the agent: its file holds a handle, and the device the key.

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use russh::keys::ssh_encoding::Decode;
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::PublicKey;
use zeroize::Zeroizing;

use super::SkKey;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const ADD_IDENTITY: u8 = 17;
const REMOVE_IDENTITY: u8 = 18;
const REMOVE_ALL_IDENTITIES: u8 = 19;
const ADD_ID_CONSTRAINED: u8 = 25;
const CONSTRAIN_LIFETIME: u8 = 1;
const CONSTRAIN_EXTENSION: u8 = 255;

/// The constraint by which OpenSSH's `ssh-add` names the helper of a
/// security key. podssh reaches the device its own way, whatever it names.
pub const SK_PROVIDER: &str = "sk-provider@openssh.com";

/// One key: its public key in SSH's wire format, what a signature needs,
/// its comment, and the end of its lifetime.
struct Entry {
    blob: Vec<u8>,
    key: SkKey,
    public: PublicKey,
    comment: String,
    until: Option<Instant>,
}

/// The security keys of an agent, in its memory.
#[derive(Default)]
pub struct Held {
    entries: Mutex<Vec<Entry>>,
}

impl Held {
    /// The answer to `request`, the body of a client's frame, when it is
    /// about a security key: to add one, remove one or sign with one. `None`
    /// for each other request, which russh's server answers. A locked agent
    /// refuses each.
    pub async fn answer(&self, request: &[u8], locked: bool) -> Option<Zeroizing<Vec<u8>>> {
        let (&kind, body) = request.split_first()?;
        if kind != SIGN_REQUEST {
            return self.at_once(kind, body, locked);
        }
        let mut rest = body;
        let blob = take_string(&mut rest)?;
        let data = take_string(&mut rest)?;
        let (key, public) = self.find(&blob)?;
        if locked {
            return Some(reply(FAILURE));
        }
        Some(sign(key, public, data).await)
    }

    /// russh's `answer` to a `request` that went to it, with the security
    /// keys: a list of the keys gets them after russh's, and a removal of
    /// each key removes them too.
    pub fn after(&self, request: &[u8], answer: Zeroizing<Vec<u8>>, locked: bool) -> Zeroizing<Vec<u8>> {
        match request.first() {
            Some(&REMOVE_ALL_IDENTITIES) if answer.first() == Some(&SUCCESS) => {
                self.entries().clear();
                answer
            }
            Some(&REQUEST_IDENTITIES) if !locked => self.list(answer),
            _ => answer,
        }
    }

    /// The number of security keys held.
    pub fn count(&self) -> usize {
        self.entries().len()
    }

    /// An add or a removal of a security key.
    fn at_once(&self, kind: u8, body: &[u8], locked: bool) -> Option<Zeroizing<Vec<u8>>> {
        match kind {
            ADD_IDENTITY | ADD_ID_CONSTRAINED => {
                let kept = added(body, kind == ADD_ID_CONSTRAINED)?;
                let code = match kept {
                    Some(entry) if !locked => {
                        let mut entries = self.entries();
                        entries.retain(|e| e.blob != entry.blob);
                        entries.push(entry);
                        SUCCESS
                    }
                    _ => FAILURE,
                };
                Some(reply(code))
            }
            REMOVE_IDENTITY => {
                let mut rest = body;
                let blob = take_string(&mut rest)?;
                let mut entries = self.entries();
                let at = entries.iter().position(|e| e.blob == blob)?;
                if locked {
                    return Some(reply(FAILURE));
                }
                entries.remove(at);
                Some(reply(SUCCESS))
            }
            _ => None,
        }
    }

    /// The key whose public key is `blob`, if it is held.
    fn find(&self, blob: &[u8]) -> Option<(SkKey, PublicKey)> {
        self.entries().iter().find(|e| e.blob == blob).map(|e| (e.key.clone(), e.public.clone()))
    }

    /// russh's answer to a request for the keys, with these keys after its
    /// own; an answer of another kind (FAILURE) stays as it is.
    fn list(&self, answer: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
        let entries = self.entries();
        let head = answer.get(..5).map(|h| (h[0], u32::from_be_bytes([h[1], h[2], h[3], h[4]])));
        let Some((IDENTITIES_ANSWER, count)) = head else { return answer };
        if entries.is_empty() {
            return answer;
        }
        let mut out = Zeroizing::new(Vec::with_capacity(answer.len() + entries.len() * 128));
        out.push(IDENTITIES_ANSWER);
        out.extend_from_slice(&(count + entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&answer[5..]);
        for entry in entries.iter() {
            put_string(&mut out, &entry.blob);
            put_string(&mut out, entry.comment.as_bytes());
        }
        out
    }

    /// The keys, those whose lifetime ended dropped.
    fn entries(&self) -> MutexGuard<'_, Vec<Entry>> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        entries.retain(|e| e.until.is_none_or(|until| now < until));
        entries
    }
}

/// The key of a request to add one, when it is a security key: `None` for
/// another key, which russh's server takes; `Some(None)` for a security key
/// that podssh does not keep (a constraint that it does not know, as a
/// confirmation of each use, which nobody here can give).
fn added(body: &[u8], constrained: bool) -> Option<Option<Entry>> {
    let mut peek = body;
    let name = take_string(&mut peek)?;
    if name != super::Alg::Ed25519.ssh_name().as_bytes() && name != super::Alg::EcdsaP256.ssh_name().as_bytes() {
        return None;
    }
    Some(entry(body, constrained))
}

fn entry(body: &[u8], constrained: bool) -> Option<Entry> {
    let mut rest = body;
    let keypair = KeypairData::decode(&mut rest).ok()?;
    let key = SkKey::of(&keypair)?;
    let public = PublicKey::from(KeyData::try_from(&keypair).ok()?);
    let blob = public.to_bytes().ok()?;
    let comment = String::from_utf8_lossy(&take_string(&mut rest)?).into_owned();
    let mut until = None;
    while constrained && !rest.is_empty() {
        let Some((&constraint, after)) = rest.split_first() else { break };
        rest = after;
        match constraint {
            CONSTRAIN_LIFETIME => {
                let seconds = take_u32(&mut rest)?;
                until = Some(Instant::now() + Duration::from_secs(u64::from(seconds)));
            }
            CONSTRAIN_EXTENSION => {
                // The body of an extension that podssh does not know cannot
                // be read past.
                if take_string(&mut rest)? != SK_PROVIDER.as_bytes() {
                    return None;
                }
                take_string(&mut rest)?;
            }
            _ => return None,
        }
    }
    Some(Entry { blob, key, public, comment, until })
}

/// Sign `data` with `key` in the device, on a thread that may wait: the
/// agent's answer, its signature or FAILURE. The touch and a failure are
/// said on the agent's stderr. The PIN of a key that needs it is asked
/// through `SSH_ASKPASS` only (`SSH_ASKPASS_REQUIRE=force`): the agent runs
/// in the background, where a read of the terminal would stop it.
async fn sign(key: SkKey, public: PublicKey, data: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let shown = format!("{} {}", crate::known_hosts::key_type(&public), crate::known_hosts::fingerprint(&public));
    let signed = tokio::task::spawn_blocking(move || {
        let say = |line: &str| crate::err_line!("podssh agent: {line}");
        if key.touch() {
            say(&format!("Confirm user presence for key {shown}"));
        }
        super::sign_blob(&key, &data, &say, crate::prompt::askpass_only())
    })
    .await;
    match signed {
        Ok(Ok(blob)) => {
            let mut out = Zeroizing::new(vec![SIGN_RESPONSE]);
            put_string(&mut out, &blob);
            out
        }
        Ok(Err(why)) => {
            crate::err_line!("podssh agent: the security key did not sign: {why}");
            reply(FAILURE)
        }
        Err(_) => reply(FAILURE),
    }
}

fn reply(code: u8) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(vec![code])
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn take_u32(rest: &mut &[u8]) -> Option<u32> {
    let (bytes, tail) = rest.split_first_chunk::<4>()?;
    *rest = tail;
    Some(u32::from_be_bytes(*bytes))
}

fn take_string(rest: &mut &[u8]) -> Option<Vec<u8>> {
    let length = take_u32(rest)? as usize;
    if rest.len() < length {
        return None;
    }
    let (value, tail) = rest.split_at(length);
    *rest = tail;
    Some(value.to_vec())
}

#[cfg(test)]
#[path = "agent_tests.rs"]
mod tests;
