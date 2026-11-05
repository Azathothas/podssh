//! The door of a node of the iroh road (T-163): its key, and who may
//! connect, said as the node starts and read again for each connection. In
//! a file of its own, so that `node_iroh` stays short.

use iroh::{PublicKey, SecretKey};
use podssh_iroh::keys::{self, Place};
use podssh_iroh::Allowlist;
use podssh_relay::identity::PublicKey as IdentityKey;
use podssh_relay::session::OsEntropy;

use crate::relay_settings::Refusal;

/// The node's key at `place`. A node's key for this run only is the same
/// across its upgrade in place, as its ticket names it (T-679); `podssh chat`
/// loads its own as before.
pub(crate) fn key(place: &Place, node: bool) -> Result<keys::Key, Refusal> {
    if !node {
        return keys::load(place, &mut OsEntropy).map_err(|why| Refusal::config(format!("the node's key: {why}")));
    }
    let key = crate::node_upgrade::parts::node_key(place)?;
    let secret = SecretKey::from_bytes(&key.identity.seed());
    Ok(keys::Key { secret, identity: key.identity, path: key.path, made: key.made })
}

/// Who may connect, as the node starts.
pub(crate) fn who_may(allow: Option<&std::path::Path>) -> String {
    let Some(path) = allow else {
        return "no client may connect over the iroh road: --allow FILE names the client keys that may, one on each line".into();
    };
    match Allowlist::read(path) {
        Ok(list) if list.bad_lines().is_empty() => {
            format!("{} client keys may connect ({})", list.len(), path.display())
        }
        Ok(list) => format!(
            "{} client keys may connect ({}); lines {} are not keys",
            list.len(),
            path.display(),
            lines(list.bad_lines())
        ),
        Err(why) => format!("no client may connect yet: {why}"),
    }
}

/// Whether the client `key` may connect: the allowlist is read again for
/// each connection, so a key added counts at once. A refusal is said with
/// the key, which is the line to add.
pub(crate) fn admits(
    allow: Option<&std::path::Path>,
    me: &IdentityKey,
    key: &PublicKey,
    say: &impl Fn(String),
) -> bool {
    let shown = keys::fingerprint(key);
    if crate::net::admit::lets_in(me, &keys::identity_key(key)) {
        say(format!("the client key {shown} connected, a member of the net"));
        return true;
    }
    let Some(path) = allow else {
        say(format!("refused the client key {shown}: no --allow file"));
        return false;
    };
    match Allowlist::read(path) {
        Ok(list) if list.admits(key) => {
            say(format!("the client key {shown} connected"));
            true
        }
        Ok(_) => {
            say(format!("refused the client key {shown}: it is not in {}", path.display()));
            false
        }
        Err(why) => {
            say(format!("refused the client key {shown}: {why}"));
            false
        }
    }
}

fn lines(numbers: &[usize]) -> String {
    numbers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}
