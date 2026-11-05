//! The file of each key's counts (T-636): its totals by its fingerprint,
//! read at the role's start as the pairs' file is (a regular file of this
//! user that nobody else may read), and written through a private file
//! beside it and a rename (`super::super::reverse::pairs`). Apart from
//! `usage.rs`, so that it stays within 500 lines.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::Totals;

/// The largest file of counts read: a cache file's 64 KiB would hold a few
/// hundred keys, and a role that cannot read its own file does not start.
pub const FILE_MOST: u64 = 16 << 20;

/// The file: each key's totals, by its fingerprint.
#[derive(Serialize, Deserialize)]
pub struct File {
    #[serde(default)]
    pub keys: BTreeMap<String, Totals>,
}

/// The counts of `path` as of `day`, each that still counts; none for a
/// missing file, the role's first run.
pub fn load(path: &Path, day: u64) -> Result<HashMap<String, Totals>, String> {
    if matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(HashMap::new());
    }
    let text = read_counts(path)?;
    let file: File =
        serde_json::from_str(&text).map_err(|e| format!("{}: not a file of counts: {e}", path.display()))?;
    Ok(file.keys.into_iter().map(|(k, t)| (k, t.on(day))).filter(|(_, t)| t.carried()).collect())
}

/// The text of the private file `path`, as the cache reads one, but
/// [`FILE_MOST`] at most.
fn read_counts(path: &Path) -> Result<String, String> {
    let shown = path.display();
    let file = std::fs::File::open(path).map_err(|e| format!("{shown}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    if meta.len() > FILE_MOST {
        return Err(format!("{shown} holds more than {} MiB", FILE_MOST >> 20));
    }
    crate::cache::closed(path, &file, crate::cache::Others::NoAccess)?;
    let mut text = String::new();
    std::io::Read::read_to_string(&mut &file, &mut text).map_err(|e| format!("{shown}: {e}"))?;
    Ok(text)
}
