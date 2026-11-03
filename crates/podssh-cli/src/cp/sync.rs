//! The copy of `podssh run` (T-192): a local directory onto a far one, as
//! `podssh cp -r -p` copies it (each file to a temporary name, the digests,
//! a rename; its times kept; several files at once; a new connection after a
//! break), but onto the far directory itself, also when it is there already,
//! and with each file whose size and time of change are the far file's left
//! as it is. A dry run (T-475) makes the same looks, which only read, and
//! gives the plan of what the copy would change.

use std::sync::Arc;

use podssh_ssh::sftp::FileAttributes;
use podssh_ssh::Log;

use super::link::{Link, Road};
use super::meta::Keep;
use super::operand::{Operand, Remote};
use super::pipe::{Shape, FILES_AT_ONCE};
use super::summary::Counts;
use super::transfer::{self, Failed, Side};
use super::tree::Tree;
use super::tree_conn::Conn;
use super::{report, tree_copy, Outcome};
use crate::exitmap::Fault;
use crate::ssh::resolve::Resolved;

/// What a copy of `podssh run` did: its counts for the summary (T-472), the
/// files that it sent and those that were as they are here among them, and
/// its first failure; for a dry run, the lines of its plan, as `cp -r
/// --dry-run` prints them (T-475).
pub(crate) struct Synced {
    pub counts: Counts,
    pub failed: Option<Failed>,
    pub plan: Vec<String>,
}

/// Each directory above `path` on the server, made when it is not there,
/// with mode 0700: `.podssh` and `.podssh/run` for the default of `podssh
/// run`. A directory goes over SFTP only. Each one made, in its order; a dry
/// run makes none, and gives each one that it would make (T-475).
pub(crate) async fn parents(link: &Link, path: &str, dry_run: bool) -> Result<Vec<String>, Failed> {
    let Road::Sftp(sftp) = &link.road else {
        return Err(Failed::new(Fault::Capability, "a directory goes over SFTP, and this server has none".into()));
    };
    let parts: Vec<&str> = path.split('/').collect();
    let mut at = if path.starts_with('/') { "/".to_string() } else { String::new() };
    let mut made = Vec::new();
    for part in &parts[..parts.len().saturating_sub(1)] {
        if part.is_empty() || *part == "." {
            continue;
        }
        if !at.is_empty() && !at.ends_with('/') {
            at.push('/');
        }
        at.push_str(part);
        match sftp.stat(&at).await {
            Ok(attrs) if attrs.is_dir() => {}
            Ok(_) => return Err(Failed::new(Fault::CantCreate, format!("{at} is there, and is no directory"))),
            // Each one below a missing one is missing too: its stat fails.
            Err(_) if dry_run => made.push(at.clone()),
            Err(_) => {
                let attrs = FileAttributes { permissions: Some(0o700), ..FileAttributes::default() };
                sftp.mkdir(&at, attrs).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
                made.push(at.clone());
            }
        }
    }
    Ok(made)
}

/// Copy the directory `local` onto the far directory `far` over `link`:
/// each file that changed, verified, with its times. What it did, and its
/// first failure; each one is said on `log` as it comes.
pub(crate) async fn up(
    link: &mut Option<Link>,
    resolved: &Resolved,
    local: &str,
    far: &Remote,
    tree: &Tree,
    log: &Arc<Log>,
) -> Synced {
    let mut outcome = Outcome::default();
    // The files go several at once, as `cp -r` sends them with no
    // `--parallel` (T-474).
    let shape = Shape { files: FILES_AT_ONCE, keep: Keep { times: true, ..Keep::default() }, ..Shape::default() };
    let (source, dest) = (Operand::Local(local.to_string()), Operand::Remote(far.clone()));
    let mut conn = Conn::Again { link, resolved };
    tree_copy::copy(&mut conn, &source, &dest, false, tree, log, shape, false, &mut outcome).await;
    // A look that the far side did not answer reads as a file to copy: one
    // more look shows that the session lasted to the end of the plan.
    if tree.dry_run && outcome.failed.is_none() {
        let lasted = match conn.sftp() {
            Some(sftp) => sftp.realpath(".").await.is_ok(),
            None => false,
        };
        if !lasted {
            let why = format!("{}: the server stopped answering during the dry run, so it has no plan", far.path);
            outcome.fail(log, far.path.clone(), Failed::new(Fault::SessionFault, why));
        }
    }
    let plan = outcome.planned.iter().map(|(action, from, to)| report::planned_line(action, from, to)).collect();
    Synced { counts: Counts::of(&outcome), failed: outcome.failed.map(|(_, failed)| failed), plan }
}
