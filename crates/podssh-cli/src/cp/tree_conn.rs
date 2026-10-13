//! The connection of a tree's copy (T-143): `cp -r`'s, which connects again
//! after a break and goes on at the file's offset (`session::attempts`), or
//! the one session of `podssh sftp`, whose `get -r` and `put -r` copy each
//! file as its `get` and `put` copy one, and end where the session breaks
//! (T-298). The walk, the checks of names, the links and the modes are
//! `tree_copy`'s for both.

use std::sync::Arc;

use podssh_ssh::sftp::Sftp;
use podssh_ssh::Log;

use super::link::{Link, Road};
use super::operand::{Operand, Remote};
use super::pipe::Shape;
use super::resume::Progress;
use super::session::{self, attempts};
use super::transfer::{Cause, Done, Failed};
use super::tree::Tree;
use super::{tree_copy, Outcome};
use crate::ssh::resolve::Resolved;

/// How the files of a tree reach the server.
pub enum Conn<'a> {
    /// `cp -r`: the connection, replaced after a break; `None` once none is
    /// left.
    Again { link: &'a mut Option<Link>, resolved: &'a Resolved },
    /// `sftp`'s `get -r` and `put -r`: the batch's session, until it breaks.
    Once { link: &'a Link, broke: bool },
}

impl Conn<'_> {
    /// The SFTP session, while the connection lasts.
    pub fn sftp(&self) -> Option<&Sftp> {
        match self {
            Conn::Again { link, .. } => tree_copy::sftp_of(link),
            Conn::Once { broke: true, .. } => None,
            Conn::Once { link, .. } => match &link.road {
                Road::Sftp(sftp) => Some(sftp),
                Road::Exec(_) => None,
            },
        }
    }

    /// Whether no connection is left for the next file.
    pub fn gone(&self) -> bool {
        match self {
            Conn::Again { link, .. } => link.is_none(),
            Conn::Once { broke, .. } => *broke,
        }
    }

    /// The copy of one file of the tree, `from` to `to`.
    pub async fn file(&mut self, from: &Operand, to: &Operand, log: &Arc<Log>, shape: Shape) -> Result<Done, Failed> {
        match self {
            Conn::Again { link, resolved } => {
                attempts(link, resolved, from, to, false, log, shape).await.map(|(done, _)| done)
            }
            Conn::Once { link, broke } => {
                // No side file: a copy of `sftp` does not go on in a later
                // run, as its `get` and `put` do not.
                let copied = session::copy(link, from, to, false, log, &mut Progress::default(), shape).await;
                if matches!(&copied, Err(f) if f.cause == Cause::Broke) {
                    *broke = true;
                }
                copied
            }
        }
    }
}

/// `sftp`'s `get -r` and `put -r` (T-298): the tree at `far` on the server
/// comes to `local` here, or the one at `local` goes to `far` (`up`), over
/// the batch's session, as `cp -r` copies one: each link as a link, each
/// name of a far listing checked, each directory's mode after its files.
/// `many` is a source of several, which goes under `far` or `local`. Each
/// item that fails is said at once, and the rest goes on; the answer is the
/// first failure's fault, once the tree is done.
pub(crate) async fn over_session(
    link: &Link,
    up: bool,
    local: &str,
    far: &str,
    many: bool,
    log: &Arc<Log>,
    shape: Shape,
) -> Result<(), Failed> {
    let mut conn = Conn::Once { link, broke: false };
    // The session is open: only the far path is needed, not its server.
    let far_side =
        Operand::Remote(Remote { user: None, host: String::new(), port: None, path: far.into(), node: false });
    let here = Operand::Local(local.to_string());
    let (source, dest) = if up { (here, far_side) } else { (far_side, here) };
    let shown = session::shown(&source);
    let mut outcome = Outcome::default();
    let tree = Tree::default();
    tree_copy::copy(&mut conn, &source, &dest, many, &tree, log, shape, false, &mut outcome).await;
    match outcome.failed {
        None => Ok(()),
        Some((_, first)) => Err(Failed {
            message: format!("{shown}: a part of the tree was not copied; each failure is said above"),
            ..first
        }),
    }
}
