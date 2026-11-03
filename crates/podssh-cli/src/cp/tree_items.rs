//! The steps of a tree's copy (`tree_copy.rs`) that act on one name each: a
//! far file, directory or link that a copy of `podssh run` leaves as it is,
//! which its dry run plans no more (T-475), a link made there or
//! here, another name of a file copied up, and the removal of the source of
//! `mv -r`, which leaves each device, FIFO or socket, with the directories
//! that hold it, as it copied none (T-476), and each file that
//! `--no-clobber` or `--update` left out (T-473).

use std::collections::HashSet;
use std::path::Path;

use podssh_ssh::sftp::Sftp;
use podssh_ssh::Log;

use super::clobber::{self, Clobber, Mode, Skip};
use super::digest::Sum;
use super::meta;
use super::transfer::{Done, Failed};
use super::tree::{rel_of, Item};
use super::tree_copy::{local_join, remote_join};

/// Whether the far regular file `target` has the size of the local file
/// `from`, and its time of change to the second: a copy of `podssh run`
/// that kept the times left it so (T-192).
pub(super) async fn same_far(sftp: Option<&Sftp>, from: &str, target: &str) -> bool {
    let (Some(sftp), Ok(local)) = (sftp, std::fs::metadata(from)) else { return false };
    let Ok(far) = sftp.lstat(target).await else { return false };
    let time = local.modified().ok().and_then(meta::seconds);
    far.is_regular() && !far.is_symlink() && far.size == Some(local.len()) && time.is_some() && far.mtime == time
}

/// Whether the far `target` is a directory already, which the copy of
/// `podssh run` makes no more, so its dry run plans no `mkdir` (T-475).
pub(super) async fn far_dir(sftp: Option<&Sftp>, target: &str) -> bool {
    let Some(sftp) = sftp else { return false };
    sftp.lstat(target).await.is_ok_and(|attrs| attrs.is_dir())
}

/// Whether the far `target` is a link that names `names` already, which
/// [`far_link`] leaves as it is, so a dry run of `podssh run` plans no
/// `link` (T-475).
pub(super) async fn same_link(sftp: Option<&Sftp>, target: &str, names: &str) -> bool {
    let Some(sftp) = sftp else { return false };
    let is_link = sftp.lstat(target).await.is_ok_and(|attrs| attrs.is_symlink());
    is_link && sftp.readlink(target).await.is_ok_and(|now| now == names)
}

/// A symbolic link at `target` on the server that names `names`: one that a
/// copy before made stays, and anything else there is replaced, as a file
/// is (a link cannot be made over a name that exists). Under `--no-clobber`
/// and `--update` a name that is there stays, as a link has no time of the
/// source's to compare; under `--backup` the old one takes the suffix
/// (T-473).
pub(super) async fn far_link(
    sftp: &Sftp,
    target: &str,
    names: &str,
    clobber: Clobber,
) -> Result<Option<Skip>, podssh_ssh::sftp::SftpError> {
    if let Ok(attrs) = sftp.lstat(target).await {
        if attrs.is_symlink() && sftp.readlink(target).await.is_ok_and(|now| now == names) {
            return Ok(None);
        }
        if clobber.mode != Mode::Replace {
            return Ok(Some(Skip::Exists));
        }
        match clobber.backup {
            Some(suffix) if !attrs.is_dir() => {
                let aside = format!("{target}{suffix}");
                let _ = sftp.remove(&aside).await;
                sftp.rename(target, &aside).await?;
            }
            _ if attrs.is_dir() => sftp.rmdir(target).await?,
            _ => sftp.remove(target).await?,
        }
    }
    sftp.symlink(target, names).await.map(|()| None)
}

/// A symbolic link at `at` that names `names`: one there that names the same
/// stays, and another file or link there is replaced, or kept as
/// [`far_link`] keeps one.
pub(super) fn make_link(at: &Path, names: &str, clobber: Clobber) -> std::io::Result<Option<Skip>> {
    if let Ok(meta) = std::fs::symlink_metadata(at) {
        if meta.file_type().is_symlink() && std::fs::read_link(at).is_ok_and(|now| now == Path::new(names)) {
            return Ok(None);
        }
        if clobber.mode != Mode::Replace {
            return Ok(Some(Skip::Exists));
        }
        match clobber.backup {
            Some(suffix) if !meta.is_dir() => {
                let mut aside = at.as_os_str().to_owned();
                aside.push(suffix);
                let _ = std::fs::remove_file(&aside);
                std::fs::rename(at, &aside)?;
            }
            _ if meta.is_dir() => std::fs::remove_dir(at)?,
            _ => std::fs::remove_file(at)?,
        }
    }
    new_link(at, names).map(|()| None)
}

/// Another name of a file of a tree up, as a far hard link of its copy
/// `first` (T-146), after the look of `--no-clobber` and `--update`
/// (T-473): the name done, or left out; `None` with no hard link there, for
/// a copy. `first` is the copy's name, its size and its digest.
pub(super) async fn second_name(
    sftp: &Sftp,
    from: &str,
    first: (&str, u64, Option<Sum>),
    target: &str,
    clobber: Clobber,
    log: &Log,
) -> Result<Option<Done>, Failed> {
    let (first, bytes, sum) = first;
    if let Ok(local) = std::fs::metadata(from) {
        let seen = clobber::Seen::of_local(&local);
        if let Some(kept) = clobber::before_far(sftp, from, target, seen, clobber, false, log).await? {
            return Ok(Some(kept));
        }
    }
    let Some(placed) = meta::hard_link(sftp, first, target, clobber, log).await? else { return Ok(None) };
    if let Some(skip) = placed.skipped {
        return Ok(Some(clobber::skipped(from, target, skip)));
    }
    let (source, destination, verified_by) = (from.into(), target.into(), format!("a hard link to {first}"));
    Ok(Some(Done { source, destination, bytes, sum, verified_by, backup: placed.backup, ..Done::default() }))
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

/// The directories of `items` that hold an item that `stays` keeps, at any
/// depth, the root `""` included: `mv -r` leaves them.
fn holding(items: &[Item], stays: impl Fn(&Item) -> bool) -> HashSet<&str> {
    let mut out = HashSet::new();
    for item in items.iter().filter(|&item| stays(item)) {
        let mut at = rel_of(item);
        while let Some((parent, _)) = at.rsplit_once('/') {
            out.insert(parent);
            at = parent;
        }
        out.insert("");
    }
    out
}

/// The directories of `items` that hold a device, a FIFO or a socket.
pub(super) fn holding_specials(items: &[Item]) -> HashSet<&str> {
    holding(items, |item| matches!(item, Item::Special { .. }))
}

/// What `mv -r` leaves, said once: each special file, which it did not copy,
/// and each file that the run left out (T-473).
fn said_kept(src: &str, specials: bool, left: bool, log: &Log) {
    if specials {
        log.info(&format!("{src}: each device, FIFO or socket stays, with the directories that hold it"));
    }
    if left {
        log.info(&format!("{src}: each file that was not copied stays, with the directories that hold it"));
    }
}

/// mv -r up: the local source, each file and link, then each directory, the
/// deepest first; a special file, each file or link of `left` (the sources
/// that the run left out, by their names) and the directories that hold
/// them stay.
pub(super) fn remove_local(src: &str, items: &[Item], left: &HashSet<&str>, log: &Log) {
    let named = |rel: &str| local_join(Path::new(src), rel).display().to_string();
    let not_copied = |item: &Item| match item {
        Item::File { rel } | Item::Link { rel, .. } => left.contains(named(rel).as_str()),
        _ => false,
    };
    let kept = holding(items, |item| matches!(item, Item::Special { .. }) || not_copied(item));
    for item in items.iter().rev() {
        let gone = match item {
            _ if not_copied(item) => Ok(()),
            Item::File { rel } | Item::Link { rel, .. } => std::fs::remove_file(local_join(Path::new(src), rel)),
            Item::Dir { rel, .. } if kept.contains(rel.as_str()) => Ok(()),
            Item::Dir { rel, .. } => std::fs::remove_dir(local_join(Path::new(src), rel)),
            Item::Special { .. } | Item::Skip { .. } => Ok(()),
        };
        if let Err(e) = gone {
            log.info(&format!("{src}: a part of the source stays: {e}"));
            return;
        }
    }
    said_kept(src, !holding_specials(items).is_empty(), items.iter().any(not_copied), log);
}

/// mv -r down: the far source, as [`remove_local`] does here.
pub(super) async fn remove_far(sftp: &Sftp, src: &str, items: &[Item], left: &HashSet<&str>, log: &Log) {
    let not_copied = |item: &Item| match item {
        Item::File { rel } | Item::Link { rel, .. } => left.contains(remote_join(src, rel).as_str()),
        _ => false,
    };
    let kept = holding(items, |item| matches!(item, Item::Special { .. }) || not_copied(item));
    for item in items.iter().rev() {
        let gone = match item {
            _ if not_copied(item) => Ok(()),
            Item::File { rel } | Item::Link { rel, .. } => sftp.remove(&remote_join(src, rel)).await,
            Item::Dir { rel, .. } if kept.contains(rel.as_str()) => Ok(()),
            Item::Dir { rel, .. } => sftp.rmdir(&remote_join(src, rel)).await,
            Item::Special { .. } | Item::Skip { .. } => Ok(()),
        };
        if let Err(e) = gone {
            log.info(&format!("{src}: a part of the source stays: {e}"));
            return;
        }
    }
    said_kept(src, !holding_specials(items).is_empty(), items.iter().any(not_copied), log);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::meta::Stamp;
    use crate::cp::tree::Special;

    #[test]
    fn the_directories_that_hold_a_special_file_stay() {
        let dir = |r: &str| Item::Dir { rel: r.into(), stamp: Stamp::default() };
        let items = [
            dir(""),
            dir("a"),
            dir("a/b"),
            Item::Special { rel: "a/b/fifo".into(), kind: Special::Fifo },
            dir("c"),
            Item::File { rel: "c/f".into() },
        ];
        let kept = holding_specials(&items);
        assert_eq!(kept, HashSet::from(["", "a", "a/b"]), "c holds none");
        assert!(holding_specials(&[dir(""), Item::File { rel: "f".into() }]).is_empty());
    }

    #[test]
    fn mv_r_leaves_a_fifo_and_what_holds_it_and_removes_the_rest() {
        let src = std::env::temp_dir().join(format!("podssh-tree-items-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(src.join("a/b")).unwrap();
        std::fs::create_dir_all(src.join("c")).unwrap();
        std::fs::write(src.join("a/b/f"), b"1").unwrap();
        std::fs::write(src.join("c/g"), b"2").unwrap();
        // A file stands in for the FIFO: only its kind in the list counts here.
        std::fs::write(src.join("a/b/fifo"), b"").unwrap();
        let dir = |r: &str| Item::Dir { rel: r.into(), stamp: Stamp::default() };
        let items = [
            dir(""),
            dir("a"),
            dir("a/b"),
            Item::File { rel: "a/b/f".into() },
            Item::Special { rel: "a/b/fifo".into(), kind: Special::Fifo },
            dir("c"),
            Item::File { rel: "c/g".into() },
        ];
        let shown = src.display().to_string();
        remove_local(&shown, &items, &HashSet::new(), &Log::new(podssh_ssh::LogLevel::Quiet));
        assert!(!src.join("a/b/f").exists() && !src.join("c").exists(), "what was copied went");
        assert!(src.join("a/b/fifo").exists(), "the special file stays, and what holds it");
        let _ = std::fs::remove_dir_all(&src);
    }
}
