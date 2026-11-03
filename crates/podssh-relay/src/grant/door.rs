//! The node's check of a grant (T-226), in this order: the form; the key that
//! the channel proved is the certificate's; the issuer's signature, and an
//! issuer that the node trusts for what the operator asked; a user
//! certificate; a principal of this node, and of the route asked; the
//! window, which a grant must have, with the skew; each critical option
//! known, `once@podssh` among them; the list of revoked serials; and last
//! the record of its use, written and synced. Only then is the operator let
//! in, so a crash between the two burns the grant.

use std::path::PathBuf;
use std::sync::Arc;

use super::cert::{Cert, USER};
use super::spent::{NotRecorded, Spent};
use super::{principal, ONCE, SKEW_SECS};
use crate::cache::{self, Others};
use crate::e2e::Ask;
use crate::identity::{KeyName, PublicKey};

/// Whether `issuer` may grant what an operator asks (`Err` is why not): the
/// node's own key, and the keys that its door names, each for what it may
/// reach itself, so that a grant never reaches more than its issuer.
pub type Issuers = dyn Fn(&PublicKey, &Ask) -> Result<(), String> + Send + Sync;

/// A node's door for grants.
#[derive(Clone)]
pub struct Door {
    /// The node's key: its principal, and an issuer of each grant.
    pub node: PublicKey,
    /// The other issuers.
    pub issuers: Arc<Issuers>,
    pub spent: Spent,
    /// A file of revoked serials, read again for each grant.
    pub revoked: Option<PathBuf>,
}

/// A grant that let an operator in: what the node's line says of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redeemed {
    pub serial: u64,
    pub key_id: String,
    pub issuer: PublicKey,
}

impl std::fmt::Display for Redeemed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the grant of serial {} (id {:?}) by {}, used now", self.serial, self.key_id, self.issuer)
    }
}

impl Door {
    /// Check the grant `blob` of the operator `peer`, which the channel
    /// proved, for what it asked, at `now` (seconds since the epoch), and
    /// record its use: `Ok` once; `Err` is why not, for the node's log.
    pub fn redeem(&self, peer: &PublicKey, ask: &Ask, blob: &[u8], now: u64) -> Result<Redeemed, String> {
        let cert = Cert::from_blob(blob).map_err(|why| format!("not a grant: {why}"))?;
        if cert.key != *peer {
            return Err(format!("the grant is for the key {}, not {peer}, which the channel proved", cert.key));
        }
        if !cert.signed_by_issuer() {
            return Err(format!("the grant's signature does not verify under its issuer's key {}", cert.issuer));
        }
        if cert.issuer != self.node {
            (self.issuers)(&cert.issuer, ask)
                .map_err(|why| format!("its issuer {} is not one of this node's: {why}", cert.issuer))?;
        }
        if cert.kind != USER {
            return Err("a host certificate is no grant: ssh-keygen -s makes one with no -h".into());
        }
        let wanted = match ask {
            Ask::Target => principal(&self.node, None),
            Ask::Route(route) => principal(&self.node, Some(route.as_str())),
            Ask::Exit { .. } => return Err("a grant names a node, or a route of it, never an exit's target".into()),
        };
        if !cert.principals.contains(&wanted) {
            return Err(format!("it names {:?}, not {wanted}", cert.principals));
        }
        window(&cert, now)?;
        options(&cert)?;
        if let Some(path) = &self.revoked {
            revoked(path, &cert)?;
        }
        match self.spent.record(&cert, now) {
            Ok(()) => Ok(Redeemed { serial: cert.serial, key_id: cert.key_id.clone(), issuer: cert.issuer }),
            Err(NotRecorded::Used) => Err(format!("the grant of serial {} was used already", cert.serial)),
            Err(NotRecorded::Failed(why)) => Err(format!("its use could not be recorded, so it is not let in: {why}")),
        }
    }
}

/// A window of its own, which `now` is in, give or take the skew.
fn window(cert: &Cert, now: u64) -> Result<(), String> {
    if cert.valid_before == u64::MAX {
        return Err("it has no end, and a grant needs one: ssh-keygen -V +1h, or podssh node --grant-for".into());
    }
    if now.saturating_add(SKEW_SECS) < cert.valid_after {
        return Err(format!("its window starts in {} s", cert.valid_after - now));
    }
    if now >= cert.valid_before.saturating_add(SKEW_SECS) {
        return Err(format!("its window ended {} s ago", now - cert.valid_before));
    }
    Ok(())
}

/// Each critical option is one that podssh reads, as OpenSSH refuses a
/// certificate with one that it does not; `once@podssh`, with no data, must
/// be there.
fn options(cert: &Cert) -> Result<(), String> {
    let mut once = false;
    for (name, data) in &cert.critical {
        match name.as_str() {
            ONCE if data.is_empty() => once = true,
            ONCE => return Err(format!("its option {ONCE} carries data, which it has none of")),
            other => return Err(format!("its critical option {other} is not one that podssh reads")),
        }
    }
    if !once {
        return Err(format!("it has no critical option {ONCE}: a certificate for SSH logins is no grant"));
    }
    Ok(())
}

/// The file of revoked serials: a serial on each line, of any issuer, or a
/// fingerprint (or a key) and a serial, of that issuer; `#` starts a comment.
/// A file that is missing, or that others can change, lets no grant in, as
/// a revocation that is not read must not let one in.
fn revoked(path: &std::path::Path, cert: &Cert) -> Result<(), String> {
    let text = match cache::read_own(path, Others::Read)? {
        Some(text) => text,
        None => return Err(format!("{}: no such file, so no grant is let in", path.display())),
    };
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let (issuer, serial) = match words.as_slice() {
            [serial, ..] if serial.parse::<u64>().is_ok() => (None, *serial),
            [issuer, serial, ..] => (Some(*issuer), *serial),
            _ => continue,
        };
        let Ok(serial) = serial.parse::<u64>() else { continue };
        let by = issuer.is_none_or(|word| KeyName::parse(word).is_some_and(|name| name.matches(&cert.issuer)));
        if serial == cert.serial && by {
            return Err(format!("its serial {serial} is revoked in {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Mint;
    use crate::identity::Identity;

    #[test]
    fn a_revoked_serial_is_refused_by_any_issuer_or_by_its_own() {
        let dir = std::env::temp_dir().join(format!("podssh-revoked-{}-{}", std::process::id(), line!()));
        crate::cache::private_dir(&dir).unwrap();
        let issuer = Identity::from_seed(&[2; 32]);
        let principals = vec!["node:x".to_string()];
        let cert = |serial: u64| {
            Mint {
                nonce: [1; 32],
                key: Identity::from_seed(&[1; 32]).public(),
                serial,
                key_id: "t",
                principals: &principals,
                valid_after: 0,
                valid_before: 10,
                critical: &[],
            }
            .sign(&issuer)
        };
        let path = dir.join("revoked");
        let other = Identity::from_seed(&[3; 32]).public();
        std::fs::write(&path, format!("# revoked\n7\n{} 8\n{} 9\nnot a line\n", issuer.public(), other)).unwrap();
        // Others may read it, never change it, whatever this host's umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(revoked(&path, &cert(7)).unwrap_err().contains("serial 7 is revoked"));
        assert!(revoked(&path, &cert(8)).is_err(), "by its own issuer");
        assert_eq!(revoked(&path, &cert(9)), Ok(()), "revoked by another issuer only");
        assert_eq!(revoked(&path, &cert(10)), Ok(()));
        assert!(revoked(&dir.join("missing"), &cert(10)).unwrap_err().contains("no grant is let in"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
