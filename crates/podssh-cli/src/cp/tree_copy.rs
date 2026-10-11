//! The copy of a directory over one connection (T-143): the walk of
//! `tree.rs`, then each directory made, each file copied as one copy goes
//! (`session::attempts`, with its continuation after a break), each link
//! made, and each directory's mode set after its files. An item that cannot
//! be copied is reported and the walk goes on; the exit is then not zero, as
//! for `scp`. `--dry-run` says each action and changes nothing.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use podssh_ssh::sftp::{FileAttributes, Sftp};
use podssh_ssh::Log;

use super::link::{Link, Road};
use super::operand::{Operand, Remote};
use super::pipe::Shape;
use super::session::{attempts, shown};
use super::transfer::{self, Failed, Side};
use super::tree::{self, Item, Tree};
use super::Outcome;
use crate::exitmap::Fault;
use crate::ssh::resolve::Resolved;

/// One action of a dry run, as `report` prints it: what, from, and to.
pub type Planned = (&'static str, String, String);

fn remote_join(root: &str, rel: &str) -> String {
    match (root, rel) {
        (_, "") => root.to_string(),
        ("", _) => rel.to_string(),
        _ => format!("{}/{rel}", root.trim_end_matches('/')),
    }
}

fn local_join(root: &Path, rel: &str) -> PathBuf {
    rel.split('/').filter(|c| !c.is_empty()).fold(root.to_path_buf(), |path, c| path.join(c))
}

/// The SFTP session of the connection, while it lasts.
fn sftp_of(link: &Option<Link>) -> Option<&Sftp> {
    match link.as_ref().map(|l| &l.road) {
        Some(Road::Sftp(sftp)) => Some(sftp),
        _ => None,
    }
}

/// Whether `source` is a directory: here, or on the server.
pub async fn is_dir(link: &Option<Link>, source: &Operand, tree: &Tree) -> bool {
    match source {
        Operand::Local(path) => std::fs::metadata(path).is_ok_and(|m| m.is_dir()),
        Operand::Remote(remote) => match sftp_of(link) {
            Some(sftp) if tree.follow => sftp.stat(&remote.path).await.is_ok_and(|a| a.is_dir()),
            Some(sftp) => sftp.lstat(&remote.path).await.is_ok_and(|a| a.is_dir()),
            None => false,
        },
    }
}

/// Record a failure of the tree, and say it at once: each one is reported,
/// and the first sets the exit code.
fn failed(outcome: &mut Outcome, log: &Log, name: String, failed: Failed) {
    log.error(&failed.message);
    outcome.failed.get_or_insert((name, failed));
}

/// Copy the directory `source` to `dest` over `link`: up or down.
#[allow(clippy::too_many_arguments)]
pub async fn copy(
    link: &mut Option<Link>,
    resolved: &Resolved,
    source: &Operand,
    dest: &Operand,
    many: bool,
    tree: &Tree,
    log: &Arc<Log>,
    shape: Shape,
    moving: bool,
    outcome: &mut Outcome,
) {
    let name = shown(source);
    if sftp_of(link).is_none() {
        let why = format!("{name}: a directory goes over SFTP, and this server has none");
        return failed(outcome, log, name, Failed::new(Fault::Capability, why));
    }
    match (source, dest) {
        (Operand::Local(src), Operand::Remote(dst)) => {
            up(link, resolved, src, dst, many, tree, log, shape, moving, outcome).await
        }
        (Operand::Remote(src), Operand::Local(dst)) => {
            down(link, resolved, src, dst, many, tree, log, shape, moving, outcome).await
        }
        _ => {
            let why = format!("{name}: a directory goes up or down, not from one server to another");
            failed(outcome, log, name, Failed::new(Fault::Usage, why));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn up(
    link: &mut Option<Link>,
    resolved: &Resolved,
    src: &str,
    dst: &Remote,
    many: bool,
    tree: &Tree,
    log: &Arc<Log>,
    shape: Shape,
    moving: bool,
    outcome: &mut Outcome,
) {
    let leaf = Path::new(src).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
    let Some(sftp) = sftp_of(link) else { return };
    let into =
        many || dst.path.is_empty() || dst.path.ends_with('/') || sftp.stat(&dst.path).await.is_ok_and(|a| a.is_dir());
    let root = if into { remote_join(&dst.path, &leaf) } else { dst.path.clone() };
    let items = tree::walk_local(Path::new(src), tree);
    let mut dirs = Vec::new();
    let mut clean = true;
    for item in &items {
        match item {
            Item::Dir { rel, mode } => {
                let target = remote_join(&root, rel);
                if tree.dry_run {
                    outcome.planned.push(("mkdir", local_join(Path::new(src), rel).display().to_string(), target));
                    continue;
                }
                let Some(sftp) = sftp_of(link) else { return };
                let made = match sftp.lstat(&target).await {
                    Ok(attrs) if attrs.is_dir() => Ok(()),
                    _ => sftp.mkdir(&target, FileAttributes::default()).await,
                };
                if let Err(e) = made {
                    clean = false;
                    failed(outcome, log, target.clone(), transfer::from_sftp(e, Side::Destination));
                    continue;
                }
                dirs.push((target, *mode));
            }
            Item::File { rel } => {
                let from = local_join(Path::new(src), rel).display().to_string();
                let target = remote_join(&root, rel);
                if tree.dry_run {
                    outcome.planned.push(("copy", from, target));
                    continue;
                }
                let to = Operand::Remote(Remote { path: target, ..dst.clone() });
                match attempts(link, resolved, &Operand::Local(from.clone()), &to, false, log, shape).await {
                    Ok((done, _)) => outcome.done.push(done),
                    Err(f) => {
                        clean = false;
                        failed(outcome, log, from, f);
                        if link.is_none() {
                            return;
                        }
                    }
                }
            }
            Item::Link { rel, target: names } => {
                let target = remote_join(&root, rel);
                if tree.dry_run {
                    outcome.planned.push(("link", target, names.clone()));
                    continue;
                }
                let Some(sftp) = sftp_of(link) else { return };
                if let Err(e) = sftp.symlink(&target, names).await {
                    clean = false;
                    failed(outcome, log, target, transfer::from_sftp(e, Side::Destination));
                }
            }
            Item::Skip { rel, why } => {
                let from = local_join(Path::new(src), rel).display().to_string();
                if tree.dry_run {
                    outcome.planned.push(("skip", from, why.clone()));
                    continue;
                }
                clean = false;
                failed(outcome, log, from.clone(), Failed::new(Fault::NoInput, format!("{from}: not copied: {why}")));
            }
        }
    }
    // Each directory's mode after its files, the deepest first.
    if let Some(sftp) = sftp_of(link) {
        for (dir, mode) in dirs.iter().rev() {
            if let Some(mode) = mode {
                let attrs = FileAttributes { permissions: Some(*mode), ..FileAttributes::default() };
                let _ = sftp.setstat(dir, attrs).await;
            }
        }
    }
    // mv -r: the source goes once each item of it is copied.
    if moving && clean && !tree.dry_run {
        remove_local(src, &items, log);
    }
}

#[allow(clippy::too_many_arguments)]
async fn down(
    link: &mut Option<Link>,
    resolved: &Resolved,
    src: &Remote,
    dst: &str,
    many: bool,
    tree: &Tree,
    log: &Arc<Log>,
    shape: Shape,
    moving: bool,
    outcome: &mut Outcome,
) {
    let leaf = src.path.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
    if let Err(why) = tree::check_name(&leaf, cfg!(windows)) {
        return failed(outcome, log, src.path.clone(), Failed::new(Fault::Usage, format!("{}: {why}", src.path)));
    }
    let into = many || Path::new(dst).is_dir();
    let root = if into { Path::new(dst).join(&leaf) } else { PathBuf::from(dst) };
    let Some(sftp) = sftp_of(link) else { return };
    let items = tree::walk_far(sftp, &src.path, tree, cfg!(windows)).await;
    let mut dirs = Vec::new();
    let mut clean = true;
    for item in &items {
        match item {
            Item::Dir { rel, mode } => {
                let target = local_join(&root, rel);
                if tree.dry_run {
                    outcome.planned.push(("mkdir", remote_join(&src.path, rel), target.display().to_string()));
                    continue;
                }
                if let Err(e) = std::fs::create_dir_all(&target) {
                    clean = false;
                    let shown = target.display().to_string();
                    failed(outcome, log, shown.clone(), Failed::new(Fault::CantCreate, format!("{shown}: {e}")));
                    continue;
                }
                dirs.push((target, *mode));
            }
            Item::File { rel } => {
                let from = remote_join(&src.path, rel);
                let target = local_join(&root, rel).display().to_string();
                if tree.dry_run {
                    outcome.planned.push(("copy", from, target));
                    continue;
                }
                let source = Operand::Remote(Remote { path: from.clone(), ..src.clone() });
                match attempts(link, resolved, &source, &Operand::Local(target), false, log, shape).await {
                    Ok((done, _)) => outcome.done.push(done),
                    Err(f) => {
                        clean = false;
                        failed(outcome, log, from, f);
                        if link.is_none() {
                            return;
                        }
                    }
                }
            }
            Item::Link { rel, target: names } => {
                let target = local_join(&root, rel);
                if tree.dry_run {
                    outcome.planned.push(("link", target.display().to_string(), names.clone()));
                    continue;
                }
                if let Err(e) = make_link(&target, names) {
                    clean = false;
                    let shown = target.display().to_string();
                    let why = format!("{shown}: the link to {names} is not made: {e}");
                    failed(outcome, log, shown, Failed::new(Fault::CantCreate, why));
                }
            }
            Item::Skip { rel, why } => {
                let from = remote_join(&src.path, rel);
                if tree.dry_run {
                    outcome.planned.push(("skip", from, why.clone()));
                    continue;
                }
                clean = false;
                let fault = if why.starts_with("refused") { Fault::SessionFault } else { Fault::NoInput };
                failed(outcome, log, from.clone(), Failed::new(fault, format!("{from}: not copied: {why}")));
            }
        }
    }
    #[cfg(unix)]
    for (dir, mode) in dirs.iter().rev() {
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(*mode));
        }
    }
    #[cfg(not(unix))]
    let _ = dirs;
    if moving && clean && !tree.dry_run {
        if let Some(sftp) = sftp_of(link) {
            remove_far(sftp, &src.path, &items, log).await;
        }
    }
}

/// A symbolic link at `at` that names `names`.
fn make_link(at: &Path, names: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(names, at)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(names, at)
    }
}

/// mv -r up: the local source, each file and link, then each directory, the
/// deepest first.
fn remove_local(src: &str, items: &[Item], log: &Log) {
    for item in items.iter().rev() {
        let gone = match item {
            Item::File { rel } | Item::Link { rel, .. } => std::fs::remove_file(local_join(Path::new(src), rel)),
            Item::Dir { rel, .. } => std::fs::remove_dir(local_join(Path::new(src), rel)),
            Item::Skip { .. } => Ok(()),
        };
        if let Err(e) = gone {
            log.info(&format!("{src}: a part of the source stays: {e}"));
            return;
        }
    }
}

/// mv -r down: the far source, as [`remove_local`] does here.
async fn remove_far(sftp: &Sftp, src: &str, items: &[Item], log: &Log) {
    for item in items.iter().rev() {
        let gone = match item {
            Item::File { rel } | Item::Link { rel, .. } => sftp.remove(&remote_join(src, rel)).await,
            Item::Dir { rel, .. } => sftp.rmdir(&remote_join(src, rel)).await,
            Item::Skip { .. } => Ok(()),
        };
        if let Err(e) = gone {
            log.info(&format!("{src}: a part of the source stays: {e}"));
            return;
        }
    }
}
