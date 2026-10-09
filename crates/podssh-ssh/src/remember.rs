//! What a run of podssh keeps of a login that worked, for its next
//! connection to the same server: the key that a passphrase opened, and the
//! password that the server took. A copy opens new connections after a
//! break and before the relay's limits (T-136, T-137); without this, each
//! would ask again, and with no terminal it could not. In memory, for this
//! run only; never on disk. The secrets are wiped when the last copy drops.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use russh::keys::PrivateKey;
use zeroize::Zeroizing;

/// A run's memory of a login. Cloneable; each clone shares it.
#[derive(Clone, Default)]
pub struct Remembered(Arc<Mutex<Kept>>);

#[derive(Default)]
struct Kept {
    keys: Vec<(PathBuf, PrivateKey)>,
    password: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Remembered {
    // The count only: a secret never goes into a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kept = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("Remembered")
            .field("keys", &kept.keys.len())
            .field("password", &kept.password.is_some())
            .finish()
    }
}

impl Remembered {
    /// The key of the file `path`, when a passphrase opened it in this run.
    pub fn key(&self, path: &Path) -> Option<PrivateKey> {
        let kept = self.0.lock().unwrap_or_else(|e| e.into_inner());
        kept.keys.iter().find(|(p, _)| p == path).map(|(_, key)| key.clone())
    }

    /// Keep the key that a passphrase opened.
    pub fn keep_key(&self, path: &Path, key: &PrivateKey) {
        let mut kept = self.0.lock().unwrap_or_else(|e| e.into_inner());
        kept.keys.retain(|(p, _)| p != path);
        kept.keys.push((path.to_path_buf(), key.clone()));
    }

    /// The password that the server took in this run.
    pub fn password(&self) -> Option<Zeroizing<String>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).password.clone()
    }

    /// Keep the password that the server took.
    pub fn keep_password(&self, password: &str) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).password = Some(Zeroizing::new(password.to_string()));
    }

    /// Forget the password, which the server no longer takes.
    pub fn forget_password(&self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).password = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::Algorithm;

    #[test]
    fn a_login_is_kept_for_the_run_and_never_shown() {
        let memory = Remembered::default();
        let shared = memory.clone();
        assert!(memory.key(Path::new("id")).is_none() && memory.password().is_none());
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a key");
        shared.keep_key(Path::new("id"), &key);
        shared.keep_password("hunter2");
        assert_eq!(memory.key(Path::new("id")).map(|k| k.public_key().clone()), Some(key.public_key().clone()));
        assert!(memory.key(Path::new("other")).is_none());
        assert_eq!(memory.password().as_deref().map(String::as_str), Some("hunter2"));
        let shown = format!("{memory:?}");
        assert!(!shown.contains("hunter2") && shown.contains("keys: 1"), "{shown}");
        memory.forget_password();
        assert!(shared.password().is_none());
    }
}
