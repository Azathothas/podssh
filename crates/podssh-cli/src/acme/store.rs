//! Where ACME's state is kept (T-447), so that a restart asks the CA for
//! nothing: in the cache, under `acme/HOST-DIGEST/` for each directory URL
//! (mode 0700), `account.key`, the account's key, made once and never
//! replaced; and `NAME.pem`, the certificate's key and its chain in one file
//! of mode 0600, replaced whole by a rename at each renewal, so that no
//! reader ever takes the key of one certificate with the chain of another.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use podssh_relay::cache::{self, Chosen, Others};
use sha2::Digest as _;
use zeroize::Zeroizing;

use super::certs::{self, Key};
use super::jws::Account;
use crate::exitmap::sysexits::EX_CANTCREAT;
use crate::relay_settings::Refusal;
use crate::update::fetch::Url;

/// The directory under the cache.
pub const DIR: &str = "acme";
/// The account's key, in each CA's directory.
pub const ACCOUNT: &str = "account.key";

/// The state of one name at one CA.
#[derive(Debug, Clone)]
pub struct Store {
    pub dir: PathBuf,
    pub name: String,
}

/// `HOST-DIGEST`: the CA's host, and 8 hex digits of the SHA-256 of its
/// directory's URL, which tell a CA's staging directory from its own.
pub fn tag(directory: &str) -> String {
    let host = Url::parse(directory).map(|u| u.host).unwrap_or_default();
    let digest = sha2::Sha256::digest(directory.as_bytes());
    let hex: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{hex}", cache::safe_name(&host))
}

impl Store {
    /// The state of `name` at the CA of `directory`: in the cache's
    /// directory that holds this CA's account already, else in the first
    /// one that can be made private.
    pub fn open(directory: &str, name: &str) -> Result<Store, Refusal> {
        if cache::chosen() == Chosen::Nothing {
            return Err(Refusal::config(format!(
                "{}=none: --acme keeps its account and certificate in the cache, so that a restart asks the CA \
                 for nothing; name a directory, or leave it unset",
                cache::DIR_ENV
            )));
        }
        let ca = tag(directory);
        let dirs: Vec<PathBuf> = cache::candidate_dirs().into_iter().map(|d| d.join(DIR).join(&ca)).collect();
        let held = dirs.iter().find(|d| d.join(ACCOUNT).is_file());
        let mut tried = Vec::new();
        for dir in held.into_iter().chain(dirs.iter()) {
            match made_private(dir) {
                Ok(()) => return Ok(Store { dir: dir.clone(), name: name.to_string() }),
                Err(e) => tried.push(format!("{}: {e}", dir.display())),
            }
        }
        let message = format!("no private directory for ACME's state: {}", tried.join("; "));
        Err(Refusal { message, code: EX_CANTCREAT })
    }

    /// The file of the certificate's key and its chain.
    pub fn pem_path(&self) -> PathBuf {
        self.dir.join(format!("{}.pem", self.name))
    }

    /// The account's key: the one kept, else a new one, kept now.
    pub fn account(&self) -> Result<Account, String> {
        let path = self.dir.join(ACCOUNT);
        for _ in 0..2 {
            if let Some(text) = cache::read_own(&path, Others::NoAccess)? {
                let text = Zeroizing::new(text);
                let der = certs::pem_block(&text, "PRIVATE KEY")
                    .ok_or_else(|| format!("{} holds no PRIVATE KEY block", path.display()))?;
                return Account::from_pkcs8(&der).map_err(|why| format!("{}: {why}", path.display()));
            }
            let account = Account::generate()?;
            // Never over another file: a second run that made one first wins.
            match cache::create_private(&path, account.pem().as_bytes()) {
                Ok(true) => return Ok(account),
                Ok(false) => continue,
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
        Err(format!("{} could not be made or read", path.display()))
    }

    /// The text of the certificate kept, when there is one.
    pub fn held(&self) -> Result<Option<Zeroizing<String>>, String> {
        Ok(cache::read_own(&self.pem_path(), Others::NoAccess)?.map(Zeroizing::new))
    }

    /// Keep `key` and `chain` in place of the certificate of before.
    pub fn keep(&self, key: &Key, chain: &str) -> Result<PathBuf, String> {
        let path = self.pem_path();
        let body = Zeroizing::new(format!("{}{chain}", key.pem().as_str()));
        replace(&path, body.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(path)
    }
}

/// `dir` and the parent that names this module, each private (0700).
fn made_private(dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = dir.parent() {
        cache::private_dir(parent)?;
    }
    cache::private_dir(dir)
}

/// `path` replaced whole by `body`: a private file beside it, then a rename.
fn replace(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let result = (|| {
        let mut file = cache::create_new_private(&tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory of the test's own, removed when it goes.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(tag: &str) -> Scratch {
        let name = format!("podssh-acme-{tag}-{}-{:08x}", std::process::id(), rand::random::<u32>());
        let dir = std::env::temp_dir().join(name);
        cache::private_dir(&dir).unwrap();
        Scratch(dir)
    }

    #[test]
    fn a_ca_s_tag_is_its_host_and_a_digest_of_its_url() {
        let production = tag("https://acme-v02.api.letsencrypt.org/directory");
        let staging = tag("https://acme-staging-v02.api.letsencrypt.org/directory");
        assert!(production.starts_with("acme-v02.api.letsencrypt.org-") && production.len() == 29 + 8, "{production}");
        assert_ne!(production, staging);
        assert_eq!(tag("https://127.0.0.1:14000/dir"), tag("https://127.0.0.1:14000/dir"));
    }

    #[test]
    fn the_account_is_made_once_and_the_certificate_replaced_whole_each_file_private() {
        let s = scratch("store");
        let store = Store { dir: s.0.join(DIR).join("ca.test-00000000"), name: "relay.podssh.test".into() };
        made_private(&store.dir).unwrap();
        let first = store.account().unwrap();
        let again = store.account().unwrap();
        assert_eq!(first.thumbprint(), again.thumbprint(), "the account's key is kept, never made again");
        assert!(store.held().unwrap().is_none());
        let (cert_a, key_a) = certs::tests::plain(&store.name);
        let key_a = Key::from_pkcs8(&certs::pem_block(&key_a, "PRIVATE KEY").unwrap()).unwrap();
        let path = store.keep(&key_a, &cert_a).unwrap();
        assert_eq!(path, store.dir.join("relay.podssh.test.pem"));
        let held = store.held().unwrap().expect("the certificate is kept");
        let (_, leaf) = certs::load(held.as_bytes(), held.as_bytes()).expect("one file: the key and its chain");
        assert_eq!(leaf.names, vec![store.name.clone()]);
        let (cert_b, key_b) = certs::tests::plain(&store.name);
        let key_b = Key::from_pkcs8(&certs::pem_block(&key_b, "PRIVATE KEY").unwrap()).unwrap();
        store.keep(&key_b, &cert_b).unwrap();
        let held = store.held().unwrap().unwrap();
        assert!(held.contains(cert_b.trim()) && !held.contains(cert_a.trim()), "the new pair alone");
        let left: Vec<_> = std::fs::read_dir(&store.dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left.len(), 2, "account.key and NAME.pem, no temporary file: {left:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fn mode(p: &Path) -> u32 {
                std::fs::metadata(p).unwrap().permissions().mode() & 0o777
            }
            assert_eq!(mode(&store.dir), 0o700);
            assert_eq!(mode(&store.dir.join(ACCOUNT)), 0o600);
            assert_eq!(mode(&path), 0o600);
        }
    }
}
