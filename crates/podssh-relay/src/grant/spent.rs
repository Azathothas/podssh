//! The record of each grant that a node let in (T-226): one private file for
//! each, made create-new, so that of two sessions with one grant at once
//! one alone makes it, also in two processes; written, synced, and its
//! directory synced, before the node lets the operator in, so that a crash
//! burns a grant and never gives it a second use. A file is named by the end
//! of the grant's window and the digest of what its issuer signed, and goes
//! once that end and its skew passed, as the window refuses the grant then.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::cert::Cert;
use super::SKEW_SECS;

/// The first part of each record's name.
const PREFIX: &str = "spent-";

/// Where a node records the grants that it let in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spent {
    place: Place,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Place {
    Dir(PathBuf),
    /// No directory took the record: why, and each grant is refused.
    Nowhere(String),
}

/// Why a grant was not recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotRecorded {
    /// A record of it is there: it was used.
    Used,
    /// The record could not be made, so the grant is not let in: why.
    Failed(String),
}

impl Spent {
    /// The records in `dir`, made private when it is missing.
    pub fn at(dir: PathBuf) -> Spent {
        Spent { place: Place::Dir(dir) }
    }

    /// No place for the records: each grant is refused, with `why`.
    pub fn nowhere(why: impl Into<String>) -> Spent {
        Spent { place: Place::Nowhere(why.into()) }
    }

    /// The directory of the records, when there is one.
    pub fn dir(&self) -> Option<&Path> {
        match &self.place {
            Place::Dir(dir) => Some(dir),
            Place::Nowhere(_) => None,
        }
    }

    /// Record `cert` as used at `now` (seconds since the epoch): `Ok` once,
    /// and [`NotRecorded::Used`] for each later use, until the end of its
    /// window and the skew; the records whose end passed go first.
    pub fn record(&self, cert: &Cert, now: u64) -> Result<(), NotRecorded> {
        let dir = match &self.place {
            Place::Dir(dir) => dir,
            Place::Nowhere(why) => return Err(NotRecorded::Failed(why.clone())),
        };
        let failed = |e: std::io::Error| NotRecorded::Failed(format!("{}: {e}", dir.display()));
        crate::cache::private_dir(dir).map_err(failed)?;
        prune(dir, now);
        let until = cert.valid_before.saturating_add(SKEW_SECS);
        let path = dir.join(name(until, &cert.digest()));
        let mut file = match crate::cache::create_new_private(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(NotRecorded::Used),
            Err(e) => return Err(failed(e)),
        };
        // The serial and the issuer, for a person who reads the directory:
        // no secret, as a certificate is public.
        let line = format!("serial {} by {} at {now}\n", cert.serial, cert.issuer);
        let written = file.write_all(line.as_bytes()).and_then(|()| file.sync_all());
        drop(file);
        // A record that is not on the disk could be lost with a crash, and the
        // grant used again: it is not let in, and its file stays, so it is
        // burnt rather than given twice.
        written.and_then(|()| sync_dir(dir)).map_err(failed)
    }
}

/// The name of a record: the end of its grant, then the digest in hex.
fn name(until: u64, digest: &[u8; 32]) -> String {
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("{PREFIX}{until}-{hex}")
}

/// Remove each record whose end passed at `now`; a name of another form is
/// left as it is.
fn prune(dir: &Path, now: u64) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else { continue };
        let until = name.strip_prefix(PREFIX).and_then(|rest| rest.split_once('-')).and_then(|(n, _)| n.parse().ok());
        if until.is_some_and(|until: u64| until < now) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// The directory's entry of a new file, on the disk.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Windows has no handle of a directory to sync: the file's own sync, and
/// NTFS's journal of its entry, are what there is.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Mint;
    use crate::identity::Identity;

    fn grant(nonce: u8, valid_before: u64) -> Cert {
        let principals = vec!["node:x".to_string()];
        Mint {
            nonce: [nonce; 32],
            key: Identity::from_seed(&[1; 32]).public(),
            serial: 9,
            key_id: "t",
            principals: &principals,
            valid_after: 0,
            valid_before,
            critical: &[],
        }
        .sign(&Identity::from_seed(&[2; 32]))
    }

    fn scratch(tag: u32) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("podssh-spent-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_grant_is_recorded_once_and_its_record_goes_after_its_end() {
        let dir = scratch(line!());
        let spent = Spent::at(dir.join("lab"));
        let first = grant(1, 1_000);
        assert_eq!(spent.record(&first, 500), Ok(()));
        assert_eq!(spent.record(&first, 501), Err(NotRecorded::Used), "a second use");
        assert_eq!(spent.record(&grant(2, 1_000), 501), Ok(()), "another nonce is another grant");
        // Its end and the skew passed: the record goes, and the window, not
        // the record, refuses the grant from then on.
        assert_eq!(spent.record(&grant(3, 5_000), 1_000 + SKEW_SECS + 1), Ok(()));
        let left: Vec<String> = std::fs::read_dir(dir.join("lab"))
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(left[0].starts_with(&format!("{PREFIX}{}-", 5_000 + SKEW_SECS)), "{left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_no_place_each_grant_is_refused() {
        let spent = Spent::nowhere("PODSSH_CACHE_DIR=none");
        assert_eq!(spent.record(&grant(1, 10), 1), Err(NotRecorded::Failed("PODSSH_CACHE_DIR=none".into())));
        assert_eq!(spent.dir(), None);
    }
}
