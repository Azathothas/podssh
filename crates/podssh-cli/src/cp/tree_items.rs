//! The steps of a tree's copy (`tree_copy.rs`) that act on one name each: a
//! far file that a copy of `podssh run` left as it is, a link made there or
//! here, and the removal of the source of `mv -r`, which leaves each device,
//! FIFO or socket, with the directories that hold it, as it copied none
//! (T-476).

use std::collections::HashSet;
use std::path::Path;

use podssh_ssh::sftp::Sftp;
use podssh_ssh::Log;

use super::meta;
use super::tree::Item;
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

/// A symbolic link at `target` on the server that names `names`: one that a
/// copy before made stays, and anything else there is replaced, as a file
/// is (a link cannot be made over a name that exists).
pub(super) async fn far_link(sftp: &Sftp, target: &str, names: &str) -> Result<(), podssh_ssh::sftp::SftpError> {
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
pub(super) fn make_link(at: &Path, names: &str) -> std::io::Result<()> {
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

/// The directories of `items` that hold a device, a FIFO or a socket, at
/// any depth, the root `""` included: `mv -r` leaves them.
pub(super) fn holding_specials(items: &[Item]) -> HashSet<&str> {
    let mut out = HashSet::new();
    for item in items {
        if let Item::Special { rel, .. } = item {
            let mut at = rel.as_str();
            while let Some((parent, _)) = at.rsplit_once('/') {
                out.insert(parent);
                at = parent;
            }
            out.insert("");
        }
    }
    out
}

/// What `mv -r` leaves, said once: each special file, which it did not copy.
fn said_kept(src: &str, kept: &HashSet<&str>, log: &Log) {
    if !kept.is_empty() {
        log.info(&format!("{src}: each device, FIFO or socket stays, with the directories that hold it"));
    }
}

/// mv -r up: the local source, each file and link, then each directory, the
/// deepest first; a special file and the directories that hold it stay.
pub(super) fn remove_local(src: &str, items: &[Item], log: &Log) {
    let kept = holding_specials(items);
    for item in items.iter().rev() {
        let gone = match item {
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
    said_kept(src, &kept, log);
}

/// mv -r down: the far source, as [`remove_local`] does here.
pub(super) async fn remove_far(sftp: &Sftp, src: &str, items: &[Item], log: &Log) {
    let kept = holding_specials(items);
    for item in items.iter().rev() {
        let gone = match item {
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
    said_kept(src, &kept, log);
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
        remove_local(&shown, &items, &Log::new(podssh_ssh::LogLevel::Quiet));
        assert!(!src.join("a/b/f").exists() && !src.join("c").exists(), "what was copied went");
        assert!(src.join("a/b/fifo").exists(), "the special file stays, and what holds it");
        let _ = std::fs::remove_dir_all(&src);
    }
}
