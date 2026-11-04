//! The list of deployments that `podssh relay serve` signs (T-346): each
//! `--deployment NAME=HOST[:PORT][,HOST[:PORT]...]`, in order, signed by the
//! Ed25519 key of `--list-key FILE`, else `relay-list.key` in the cache, made
//! when it is missing. A client that trusts the key (`PODSSH_RELAY_KEYS`,
//! `RelayKeys`, a member of its net with the role `relay`, or a key compiled
//! in) takes those deployments after the default list.

use podssh_relay::identity::file::{self, Place};
use podssh_relay::pool::signed::{self, Deployment, Signer};
use podssh_relay::session::OsEntropy;

use super::ServeArgs;
use crate::relay_settings::Refusal;

/// Sign the list of `s`'s deployments in each `/relays.json` of the role:
/// nothing with no `--deployment`. Its words for the first line, after a
/// comma: the deployments, and the key by its fingerprint, which a client
/// names to trust it.
pub(super) fn install(s: &ServeArgs) -> Result<String, Refusal> {
    if s.deployment.is_empty() {
        return match &s.list_key {
            Some(_) => Err(Refusal::usage("--list-key goes with --deployment NAME=HOSTS, the list that it signs")),
            None => Ok(String::new()),
        };
    }
    let mut deployments: Vec<Deployment> = Vec::new();
    for word in &s.deployment {
        let found = signed::parse_deployment(word).map_err(|why| Refusal::usage(format!("--deployment {why}")))?;
        if deployments.iter().any(|d| d.name == found.name) {
            return Err(Refusal::usage(format!("--deployment {}: two deployments of one name", found.name)));
        }
        deployments.push(found);
    }
    let place = match &s.list_key {
        Some(path) => Place::File(path.into()),
        None => Place::Cache { name: signed::ROLE_KEY_FILE.to_string(), old: None },
    };
    let key = file::load(&place, &mut OsEntropy).map_err(|why| Refusal::config(format!("the list's key: {why}")))?;
    let kept = key.path.as_deref().map(|p| format!(" of {}", p.display())).unwrap_or_default();
    let made = if key.made { ", made now" } else { "" };
    let names: Vec<String> = deployments.iter().map(|d| format!("{} ({})", d.name, d.shown())).collect();
    let signer = Signer::new(key.identity, deployments).map_err(|why| Refusal::usage(format!("--deployment {why}")))?;
    let print = signer.key().fingerprint();
    podssh_relay::serve::docs::sign_list(signer);
    Ok(format!(", its list of deployments {} signed by the key {print}{kept}{made}", names.join(", ")))
}
