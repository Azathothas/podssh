//! The end of `--delete` (T-144): what may not be a mirror's root, and the
//! deletes that wait for the end of the run, each one only when no copy of
//! the run failed.

use podssh_ssh::Log;

use super::link::Link;
use super::transfer::{self, Failed, Side};
use super::tree_copy::{failed, sftp_of};
use super::Outcome;
use crate::exitmap::Fault;

/// Whether `--delete` may not take `root` as its target: the root of a file
/// system, or the home directory (`home`). The answer says why.
pub(super) fn refused_root(root: &str, home: Option<&str>) -> Option<String> {
    let trimmed = root.trim_end_matches(['/', '\\']);
    // A path that Windows gives in its verbatim form (`\\?\C:\`).
    let trimmed = trimmed.strip_prefix(r"\\?\").unwrap_or(trimmed);
    let drive_root = trimmed.len() == 2 && trimmed.ends_with(':');
    if trimmed.is_empty() || drive_root || trimmed == "." {
        return Some(format!("--delete may not take {root:?}, the root of a file system or the home directory"));
    }
    match home {
        Some(home) if home.trim_end_matches(['/', '\\']).eq_ignore_ascii_case(trimmed) => {
            Some(format!("--delete may not take {root}, the home directory"))
        }
        _ => None,
    }
}

/// A delete of `--delete` that waits for the end of the run: on the server
/// or here, a directory or not.
pub struct Pending {
    pub far: bool,
    pub dir: bool,
    pub path: String,
}

/// The deletes of the run, at its end: each one when no copy of the run
/// failed; else none, which is said (T-144).
pub async fn finish_deletes(link: &Option<Link>, outcome: &mut Outcome, log: &Log) {
    let pending = std::mem::take(&mut outcome.pending);
    if pending.is_empty() {
        return;
    }
    if outcome.failed.is_some() {
        log.info(&format!("a copy failed, so nothing was deleted ({} would have been)", pending.len()));
        return;
    }
    for item in pending {
        let removed = if item.far {
            match sftp_of(link) {
                Some(sftp) if item.dir => {
                    sftp.rmdir(&item.path).await.map_err(|e| transfer::from_sftp(e, Side::Destination))
                }
                Some(sftp) => sftp.remove(&item.path).await.map_err(|e| transfer::from_sftp(e, Side::Destination)),
                None => Err(Failed::new(Fault::SessionFault, format!("{}: no connection was left", item.path))),
            }
        } else {
            let gone = if item.dir { std::fs::remove_dir(&item.path) } else { std::fs::remove_file(&item.path) };
            gone.map_err(|e| Failed::new(Fault::CantCreate, format!("{}: {e}", item.path)))
        };
        match removed {
            Ok(()) => outcome.deleted.push(item.path),
            Err(f) => failed(outcome, log, item.path, f),
        }
    }
}
