//! `podssh mv` (T-138): a copy, then the source removed, each step checked.
//!
//! **Within one server the server renames**, and no byte moves:
//! `posix-rename@openssh.com` (else T-134's rule), or `mv -f` by exec. A
//! rename that the server fails for a reason of its own (two file systems)
//! becomes a copy and a delete, said first.
//!
//! **Between hosts a move is not atomic**, and podssh says so before any byte
//! moves. **The source goes last**: after the digests matched and the rename
//! onto the destination succeeded, and only while it is still the file that
//! was copied: the same size and time of change, the same file where its
//! side can tell, and the same bytes where a digest command runs there. A
//! delete that fails leaves the data in two places, never in none.

use podssh_ssh::sftp::SftpError;
use podssh_ssh::Log;

use super::byexec::Kind;
use super::digest;
use super::link::{Link, Road};
use super::operand::Operand;
use super::plan::Plan;
use super::resume::{far, local, Before};
use super::transfer::{self, Done, Failed, Side};
use crate::exitmap::Fault;

/// What a session does with each source once its copy is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum After {
    /// `cp`: nothing.
    Keep,
    /// `mv` up or down, or within one server: remove it.
    Remove,
    /// The first leg of a move between servers: keep what the source was, for
    /// the session that removes it after the second leg.
    Record,
}

/// The line that says, before any byte moves, that a move between hosts is
/// not atomic; `None` within one server, where the server renames.
pub fn notice(paths: &[String], plan: &Plan) -> Option<String> {
    if let (Operand::Remote(a), Operand::Remote(b)) = (&plan.sources[0], &plan.destination) {
        if a.same_server(b) {
            return None;
        }
    }
    let (dest, sources) = paths.split_last()?;
    let (what, each) = match sources {
        [one] => (one.clone(), "the source"),
        many => (format!("the {} sources", many.len()), "each source"),
    };
    Some(format!(
        "{what} and {dest} are on different hosts: this is a copy, a digest check, then a delete of {each}; \
         it is not atomic"
    ))
}

/// One file named twice on one server, as typed: a usage error before
/// anything connects. A spelling that differs more is the server's to tell.
pub fn same_text(plan: &Plan) -> Option<String> {
    let (Operand::Remote(a), Operand::Remote(b)) = (&plan.sources[0], &plan.destination) else {
        return None;
    };
    let plain = |p: &str| p.trim_start_matches("./").trim_end_matches('/').to_string();
    (a.same_server(b) && plain(&a.path) == plain(&b.path))
        .then(|| format!("{} and {} name one file on {}", a.path, b.path, a.destination()))
}

/// Remove the source of a copy that is done, when it is still what was
/// copied: 66 when it changed (it stays, and the copy holds it as it was
/// read), 70 when the delete fails (the data is then in both places).
pub async fn finish(link: &Link, source: &Operand, before: &Before, done: &Done) -> Result<(), Failed> {
    match source {
        Operand::Local(path) => remove_local(path, before),
        Operand::Remote(r) => remove_far(link, &r.path, before, done).await,
    }
}

/// [`finish`] for a local source.
pub fn remove_local(path: &str, before: &Before) -> Result<(), Failed> {
    let now = local(path).map_err(|f| unchecked(path, &f.message))?;
    if &now != before {
        return Err(changed(path, "its size, time of change or file is not the one copied"));
    }
    std::fs::remove_file(path).map_err(|e| not_removed(path, &e.to_string()))
}

/// [`finish`] for a far source.
pub async fn remove_far(link: &Link, path: &str, before: &Before, done: &Done) -> Result<(), Failed> {
    let now = far(link, path).await.map_err(|f| unchecked(path, &f.message))?;
    if &now != before {
        return Err(changed(path, "its size or time of change is not the one copied"));
    }
    // The bytes too, where a digest command runs: a write in the same second
    // keeps the size and the time.
    if let Some(sum) = &done.sum {
        let named = if path.starts_with('/') { path.to_string() } else { format!("./{path}") };
        if let Some((now, _)) = digest::by_command(link.handle(), &named, done.bytes).await {
            if &now != sum {
                return Err(changed(path, "its bytes are not the ones copied"));
            }
        }
    }
    let gone = match &link.road {
        Road::Sftp(sftp) => sftp.remove(path).await.map_err(|e| e.to_string()),
        Road::Exec(far) => far.delete(link.handle(), path).await,
    };
    gone.map_err(|why| not_removed(path, &why))
}

/// Move `source` onto `dest` within one server: the server renames, and no
/// byte moves. `None` when the server fails the rename for a reason of its
/// own (two file systems), for a copy and a delete instead.
pub async fn rename(link: &Link, source: &str, dest: &str, log: &Log) -> Result<Option<Done>, Failed> {
    let (_, name) = transfer::split_remote(source.trim_end_matches('/'));
    match &link.road {
        Road::Sftp(sftp) => {
            let attrs = sftp.stat(source).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
            if !attrs.is_regular() {
                return Err(not_a_file(source));
            }
            let target = transfer::remote_target(sftp, dest, name, false).await?;
            if let (Ok(a), Ok(b)) = (sftp.realpath(source).await, sftp.realpath(&target).await) {
                if a == b {
                    return Err(one_file(source, &target));
                }
            }
            log.verbose(&format!("{source}: a rename to {target} on the server"));
            match transfer::rename_raw(sftp, source, &target, log).await {
                Ok(not_atomic) => Ok(Some(renamed(source, &target, attrs.size.unwrap_or(0), not_atomic))),
                // SSH_FX_FAILURE: a reason of the server's own, such as two
                // file systems; a copy and a delete can still move the file.
                Err(SftpError::Status { code: 4, .. }) => Ok(None),
                Err(e) => Err(transfer::from_sftp(e, Side::Destination)),
            }
        }
        Road::Exec(far) => {
            let handle = link.handle();
            let size = match far.kind(handle, source).await? {
                Kind::File(n) => n,
                // A rename reads nothing.
                Kind::Unreadable => 0,
                Kind::Missing => {
                    return Err(Failed::new(Fault::NoInput, format!("{source}: no such file or directory")))
                }
                Kind::Dir | Kind::Other => return Err(not_a_file(source)),
            };
            let target = far.target(handle, dest, name, false).await?;
            if far.same_file(handle, source, &target).await? {
                return Err(one_file(source, &target));
            }
            log.verbose(&format!("{source}: a rename to {target} on the server, by mv"));
            // Across two file systems, `mv` copies and removes by itself.
            far.rename(handle, source, &target, None).await?;
            Ok(Some(renamed(source, &target, size, false)))
        }
    }
}

/// A move that the server made by a rename.
fn renamed(source: &str, target: &str, bytes: u64, not_atomic: bool) -> Done {
    Done {
        source: source.into(),
        destination: target.into(),
        bytes,
        sum: None,
        verified_by: "rename".into(),
        not_atomic,
        removed: Some(true),
    }
}

fn not_a_file(source: &str) -> Failed {
    Failed::new(Fault::NoInput, format!("{source}: not a regular file; podssh mv moves files"))
}

fn one_file(source: &str, target: &str) -> Failed {
    Failed::new(Fault::Usage, format!("{source} and {target} name one file; nothing was done"))
}

/// The source could not be looked at again: podssh leaves it as it is.
fn unchecked(path: &str, why: &str) -> Failed {
    Failed::new(
        Fault::NoInput,
        format!(
            "{path} could not be checked after the copy ({why}), so podssh did not remove it; the copy holds it \
             as it was read"
        ),
    )
}

fn changed(path: &str, why: &str) -> Failed {
    Failed::new(
        Fault::NoInput,
        format!("{path} changed during the move ({why}), so it was kept; the copy holds it as it was read"),
    )
}

/// The copy is there and verified; the source stays too.
pub fn not_removed(path: &str, why: &str) -> Failed {
    Failed::new(Fault::SessionFault, format!("the copy is complete and verified; {path} was not removed: {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::plan::plan;

    fn paths(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn the_notice_names_both_hosts_and_says_it_is_not_atomic() {
        let up = paths(&["a.txt", "h:dir/"]);
        let text = notice(&up, &plan(&up, false).expect("a plan")).expect("between hosts");
        assert!(text.starts_with("a.txt and h:dir/ are on different hosts"), "{text}");
        assert!(text.contains("then a delete of the source; it is not atomic"), "{text}");
        let many = paths(&["h:a", "h:b", "."]);
        let text = notice(&many, &plan(&many, false).expect("a plan")).expect("between hosts");
        assert!(text.starts_with("the 2 sources and . are"), "{text}");
        let two = paths(&["h:a", "g:b"]);
        assert!(notice(&two, &plan(&two, false).expect("a plan")).is_some());
        // Within one server the server renames: no notice.
        let one = paths(&["u@h:a", "u@H:b"]);
        assert_eq!(notice(&one, &plan(&one, false).expect("a plan")), None);
    }

    #[test]
    fn one_file_named_twice_is_found_as_typed() {
        for words in [&["h:a", "h:a"][..], &["h:a", "h:./a"][..], &["h:dir/a", "h:./dir/a/"][..]] {
            let p = plan(&paths(words), false).expect("a plan");
            assert!(same_text(&p).is_some_and(|why| why.contains("name one file")), "{words:?}");
        }
        for words in [&["h:a", "g:a"][..], &["h:a", "h:b"][..], &["u@h:a", "h:a"][..], &["a", "h:a"][..]] {
            let p = plan(&paths(words), false).expect("a plan");
            assert_eq!(same_text(&p), None, "{words:?}");
        }
    }

    #[test]
    fn a_local_source_that_changes_is_kept() {
        let dir = std::env::temp_dir().join(format!("podssh-mv-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&dir).expect("a directory");
        let path = dir.join("f");
        let shown = path.display().to_string();
        std::fs::write(&path, b"one").expect("written");
        let before = local(&shown).expect("a stat");
        assert_eq!(local(&shown).expect("a stat"), before, "nothing changed");
        std::fs::write(&path, b"one more").expect("written");
        let kept = remove_local(&shown, &before).expect_err("a source that grew");
        assert_eq!(kept.fault, Fault::NoInput);
        assert!(path.exists(), "a source that changed stays");
        let now = local(&shown).expect("a stat");
        remove_local(&shown, &now).expect("the same file goes");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
