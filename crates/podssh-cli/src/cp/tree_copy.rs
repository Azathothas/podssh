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

/// Whether `--delete` may not take `root` as its target: the root of a file
/// system, or the home directory (`home`). The answer says why.
fn refused_root(root: &str, home: Option<&str>) -> Option<String> {
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
    if tree.delete {
        let real = sftp.realpath(if root.is_empty() { "." } else { &root }).await.unwrap_or_else(|_| root.clone());
        let home = sftp.realpath(".").await.ok();
        if let Some(why) = refused_root(&real, home.as_deref()).or_else(|| refused_root(&root, None)) {
            return failed(outcome, log, root, Failed::new(Fault::Usage, why));
        }
    }
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
                if let Err(e) = far_link(sftp, &target, names).await {
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
    // --delete: what the target has and the source lacks; it goes at the end
    // of the run, once each copy of it succeeded (T-144).
    if tree.delete {
        if let Some(sftp) = sftp_of(link) {
            let target = tree::walk_far(sftp, &root, &Tree { follow: false, ..tree.clone() }, false).await;
            for item in tree::to_delete(&items, &target) {
                let path = remote_join(&root, tree::rel_of(&item));
                if tree.dry_run {
                    outcome.planned.push(("delete", String::new(), path));
                } else {
                    outcome.pending.push(Pending { far: true, dir: matches!(item, Item::Dir { .. }), path });
                }
            }
        }
    }
    // mv -r: the source goes once each item of it is copied.
    if moving && clean && !tree.dry_run {
        remove_local(src, &items, log);
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
    if tree.delete {
        let real = std::fs::canonicalize(&root)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| root.display().to_string());
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).ok();
        let home = home.and_then(|h| std::fs::canonicalize(h).ok()).map(|p| p.display().to_string());
        let shown_root = root.display().to_string();
        if let Some(why) = refused_root(&real, home.as_deref()).or_else(|| refused_root(&shown_root, None)) {
            return failed(outcome, log, shown_root, Failed::new(Fault::Usage, why));
        }
    }
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
    // --delete: what the target has and the source lacks; it goes at the end
    // of the run (T-144).
    if tree.delete && root.is_dir() {
        let mut target = tree::walk_local(&root, &Tree { follow: false, ..tree.clone() });
        target.retain(|i| !matches!(i, Item::Skip { .. }));
        for item in tree::to_delete(&items, &target) {
            let path = local_join(&root, tree::rel_of(&item)).display().to_string();
            if tree.dry_run {
                outcome.planned.push(("delete", String::new(), path));
            } else {
                outcome.pending.push(Pending { far: false, dir: matches!(item, Item::Dir { .. }), path });
            }
        }
    }
    if moving && clean && !tree.dry_run {
        if let Some(sftp) = sftp_of(link) {
            remove_far(sftp, &src.path, &items, log).await;
        }
    }
}

/// A symbolic link at `target` on the server that names `names`: one that a
/// copy before made stays, and anything else there is replaced, as a file
/// is (a link cannot be made over a name that exists).
async fn far_link(sftp: &Sftp, target: &str, names: &str) -> Result<(), podssh_ssh::sftp::SftpError> {
    if let Ok(attrs) = sftp.lstat(target).await {
        if attrs.is_symlink() && sftp.readlink(target).await.is_ok_and(|now| now == names) {
            return Ok(());
        }
        if attrs.is_dir() {
            sftp.rmdir(target).await?;
        } else {
            sftp.remove(target).await?;
        }
    }
    sftp.symlink(target, names).await
}

/// A symbolic link at `at` that names `names`: one there that names the same
/// stays, and another file or link there is replaced.
fn make_link(at: &Path, names: &str) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(at) {
        if meta.file_type().is_symlink() && std::fs::read_link(at).is_ok_and(|now| now == Path::new(names)) {
            return Ok(());
        }
        if meta.is_dir() {
            std::fs::remove_dir(at)?;
        } else {
            std::fs::remove_file(at)?;
        }
    }
    new_link(at, names)
}

fn new_link(at: &Path, names: &str) -> std::io::Result<()> {
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
