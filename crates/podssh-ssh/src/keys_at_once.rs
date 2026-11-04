//! The key that a host took last, signed in the first request, with no query
//! before it (T-664, [`crate::accepted`]). A child of `keys`, as it offers a
//! key file as [`PublicKeys`] does and keeps the same record of what was
//! offered.

use std::path::Path;

use russh::client::Handle;
use russh::keys::{PrivateKey, PublicKey};

use super::PublicKeys;
use crate::answer::within;
use crate::auth::Step;
use crate::handler::Client;
use crate::sk::SkKey;

impl PublicKeys {
    /// The key file whose key has `fingerprint`, signed in the first request,
    /// when it signs here with no question and no device: a key file that
    /// opens with no passphrase, or one that a passphrase opened earlier in
    /// this run. Not a security key, whose touch waits for the server's yes;
    /// not RSA, which podssh signs through its own signer (T-257); not a key
    /// that `PubkeyAcceptedAlgorithms` refuses. `None`: no such key here, and
    /// nothing was sent. A key sent is offered, so the usual way does not ask
    /// for it again.
    pub(crate) async fn try_at_once(
        &mut self,
        handle: &mut Handle<Client>,
        user: &str,
        fingerprint: &str,
    ) -> Result<Option<Step>, String> {
        for path in self.all_files.clone() {
            let Some(key) = self.without_question(&path) else { continue };
            let public = key.public_key().clone();
            if crate::known_hosts::fingerprint(&public) != fingerprint {
                continue;
            }
            let signs_here =
                !public.algorithm().is_rsa() && SkKey::of(key.key_data()).is_none() && self.accepted.refuses(&public).is_none();
            let key = match crate::rsa_key::russh_key(key, None) {
                Ok(key) if signs_here => key,
                _ => return Ok(None),
            };
            super::warn_if_readable_by_others(&path, &self.log);
            let kind = crate::known_hosts::key_type(&public);
            self.log.debug(&format!("signing at once with the {kind} key {}, which this host took last", path.display()));
            let call = handle.authenticate_publickey_signed(user, key);
            let result = within(self.limit, &self.host, "the signed publickey request", call)
                .await?
                .map_err(|e| format!("public key authentication failed: {e}"))?;
            self.offered.push(public);
            return Ok(Some(Step::from(result)));
        }
        Ok(None)
    }

    /// The key that the server took, after a success of the usual way: the
    /// one offered last.
    pub(crate) fn last_offered(&self) -> Option<&PublicKey> {
        self.offered.last()
    }

    /// The key of `path` with no question: a file with no passphrase, or one
    /// that a passphrase opened earlier in this run.
    fn without_question(&self, path: &Path) -> Option<PrivateKey> {
        if !path.exists() {
            return None;
        }
        match crate::key_file::load(path, None) {
            Ok(key) => Some(key),
            Err(russh::keys::Error::KeyIsEncrypted) => self.kept(path),
            Err(_) => None,
        }
    }
}
