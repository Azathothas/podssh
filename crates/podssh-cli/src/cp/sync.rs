//! The copy of `podssh run` (T-192): a local directory onto a far one, as
//! `podssh cp -r -p` copies it (each file to a temporary name, the digests,
//! a rename; its times kept; a new connection after a break), but onto the
//! far directory itself, also when it is there already, and with each file
//! whose size and time of change are the far file's left as it is.

use std::sync::Arc;

use podssh_ssh::sftp::FileAttributes;
use podssh_ssh::Log;

use super::link::{Link, Road};
use super::meta::Keep;
use super::operand::{Operand, Remote};
use super::pipe::Shape;
use super::transfer::{self, Failed, Side};
use super::tree::Tree;
use super::tree_conn::Conn;
use super::{tree_copy, Outcome};
use crate::exitmap::Fault;
use crate::ssh::resolve::Resolved;

/// What a copy of `podssh run` did: the files that it sent, and those that
/// were as they are here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Synced {
    pub sent: usize,
    pub unchanged: usize,
}

/// Each directory above `path` on the server, made when it is not there,
/// with mode 0700: `.podssh` and `.podssh/run` for the default of `podssh
/// run`. A directory goes over SFTP only.
pub(crate) async fn parents(link: &Link, path: &str) -> Result<(), Failed> {
    let Road::Sftp(sftp) = &link.road else {
        return Err(Failed::new(Fault::Capability, "a directory goes over SFTP, and this server has none".into()));
    };
    let parts: Vec<&str> = path.split('/').collect();
    let mut at = if path.starts_with('/') { "/".to_string() } else { String::new() };
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
            Err(_) => {
                let attrs = FileAttributes { permissions: Some(0o700), ..FileAttributes::default() };
                sftp.mkdir(&at, attrs).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
            }
        }
    }
    Ok(())
}

/// Copy the directory `local` onto the far directory `far` over `link`:
/// each file that changed, verified, with its times. The first failure;
/// each one is said on `log` as it comes.
pub(crate) async fn up(
    link: &mut Option<Link>,
    resolved: &Resolved,
    local: &str,
    far: &Remote,
    tree: &Tree,
    log: &Arc<Log>,
) -> Result<Synced, Failed> {
    let mut outcome = Outcome::default();
    let shape = Shape { keep: Keep { times: true, ..Keep::default() }, ..Shape::default() };
    let (source, dest) = (Operand::Local(local.to_string()), Operand::Remote(far.clone()));
    let mut conn = Conn::Again { link, resolved };
    tree_copy::copy(&mut conn, &source, &dest, false, tree, log, shape, false, &mut outcome).await;
    match outcome.failed {
        Some((_, failed)) => Err(failed),
        None => Ok(Synced { sent: outcome.done.len(), unchanged: outcome.unchanged }),
    }
}
