//! The far file of `podssh edit` (T-149): its fetch and its send, each as
//! `podssh cp` copies one file (over SFTP, or by exec; a temporary name, the
//! digests, a rename; a new connection after a break), each over a
//! connection that closes at its end; and, before the send, the check that
//! the far file is still the one that came.

use std::path::Path;
use std::sync::Arc;

use podssh_ssh::Log;

use crate::cp::digest::Sum;
use crate::cp::link::{self, Link, Road};
use crate::cp::operand::{Operand, Remote};
use crate::cp::pipe::Shape;
use crate::cp::resume::{self, Before};
use crate::cp::session;
use crate::cp::transfer::{self, Done, Failed, Side};
use crate::exitmap::Fault;
use crate::ssh::resolve::Resolved;

/// The far file as it was fetched.
#[derive(Debug, Clone)]
pub(crate) struct Record {
    /// Its state when the copy began: the size and the time of change over
    /// SFTP, the line of `ls -lnid` by exec.
    pub before: Before,
    /// The SHA-256 of what came, which the far digest matched.
    pub sum: Sum,
    pub bytes: u64,
    /// Its permission bits, which the send keeps; `None` when the server
    /// gave none.
    pub mode: Option<u32>,
}

/// Fetch the far file to `local`: the file that the edit changes (over
/// SFTP the one that a link names), and its record.
pub(crate) async fn fetch(
    resolved: &Resolved,
    remote: &Remote,
    local: &Path,
    log: &Arc<Log>,
) -> Result<(Remote, Record), Failed> {
    let first = link::connect(resolved, log).await?;
    let path = match target(&first, &remote.path, log).await {
        Ok(path) => path,
        Err(failed) => {
            first.close().await;
            return Err(failed);
        }
    };
    let far = Remote { path, ..remote.clone() };
    let mut link = Some(first);
    let source = Operand::Remote(far.clone());
    let dest = Operand::Local(local.display().to_string());
    let got = session::attempts(&mut link, resolved, &source, &dest, false, log, Shape::default()).await;
    let mode = match (&got, &link) {
        (Ok((_, before)), Some(current)) => mode_of(current, &far.path, before).await,
        _ => None,
    };
    if let Some(current) = link {
        current.close().await;
    }
    let (done, before) = got?;
    let Some(sum) = done.sum else {
        return Err(Failed::new(Fault::SessionFault, format!("{}: the copy gave no digest", far.path)));
    };
    Ok((far, Record { before, sum, bytes: done.bytes, mode }))
}

/// Send `local` over the far file with the far file's mode, once the far
/// file is still the one that was fetched; else nothing is sent (73).
pub(crate) async fn send(
    resolved: &Resolved,
    far: &Remote,
    local: &Path,
    record: &Record,
    log: &Arc<Log>,
) -> Result<Done, Failed> {
    let first = link::connect(resolved, log).await?;
    if let Err(why) = unchanged(&first, &far.path, record).await {
        first.close().await;
        let message = format!("{} changed on the server since it was fetched ({why}), so nothing was sent", far.path);
        return Err(Failed::new(Fault::CantCreate, message));
    }
    if record.mode.is_none() {
        log.info(&format!("{}: the server gave no mode, so it gets the mode of the copy here", far.path));
    }
    let mut link = Some(first);
    let source = Operand::Local(local.display().to_string());
    let shape = Shape { mode: record.mode, ..Shape::default() };
    let sent = session::attempts(&mut link, resolved, &source, &Operand::Remote(far.clone()), false, log, shape).await;
    if let Some(current) = link {
        current.close().await;
    }
    sent.map(|(done, _)| done)
}

/// The path of the file that the edit changes: `path`, or over SFTP the
/// file that a symbolic link at `path` names, so that the send replaces
/// that file and the link stays a link. By exec a link is refused: no
/// portable command names its file.
async fn target(link: &Link, path: &str, log: &Log) -> Result<String, Failed> {
    match &link.road {
        Road::Sftp(sftp) => {
            let attrs = sftp.lstat(path).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
            if !attrs.is_symlink() {
                return Ok(path.to_string());
            }
            let real = sftp.realpath(path).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
            log.info(&format!("{path} is a symbolic link: podssh edits {real}, the file that it names"));
            Ok(real)
        }
        Road::Exec(_) => match resume::far(link, path).await? {
            Before::Exec(line) if line.split_whitespace().nth(1).is_some_and(|m| m.starts_with('l')) => {
                let why = format!(
                    "{path} is a symbolic link, and with no SFTP podssh cannot tell which file it names; give the \
                     path of that file"
                );
                Err(Failed::new(Fault::NoInput, why))
            }
            _ => Ok(path.to_string()),
        },
    }
}

/// The permission bits of the far file: SFTP's attributes, or the line of
/// `ls -lnid` that the exec road keeps.
async fn mode_of(link: &Link, path: &str, before: &Before) -> Option<u32> {
    match (&link.road, before) {
        (_, Before::Exec(line)) => mode_in_listing(line),
        (Road::Sftp(sftp), _) => sftp.stat(path).await.ok()?.permissions.map(|bits| bits & 0o777),
        _ => None,
    }
}

/// Whether the far file is still the one that was fetched: its state, then
/// its bytes, as a write in the same second keeps the size and the time.
/// Else what differs.
async fn unchanged(link: &Link, path: &str, record: &Record) -> Result<(), String> {
    let now = resume::far(link, path).await.map_err(|f| format!("it could not be looked at again: {}", f.message))?;
    if now != record.before {
        return Err("its size or time of change is not the one fetched".into());
    }
    let sum = match &link.road {
        Road::Sftp(sftp) => transfer::far_digest(link.handle(), sftp, path, record.bytes, Side::Source).await,
        Road::Exec(far) => far.digest(link.handle(), path, record.bytes).await,
    };
    match sum {
        Ok((sum, _)) if sum == record.sum => Ok(()),
        Ok(_) => Err("its bytes are not the ones fetched".into()),
        Err(f) => Err(format!("its digest could not be taken: {}", f.message)),
    }
}

/// The permission bits of a regular file in a line of `ls -lnid`: its second
/// word, such as `-rw-r-----`. `None` for another kind of file, or for a
/// word that is not one.
pub fn mode_in_listing(line: &str) -> Option<u32> {
    let word = line.split_whitespace().nth(1)?.as_bytes();
    if word.len() < 10 || word[0] != b'-' {
        return None;
    }
    let mut mode = 0u32;
    for (i, &c) in word[1..10].iter().enumerate() {
        let on = match (i % 3, c) {
            (_, b'-') => false,
            (0, b'r') | (1, b'w') | (2, b'x' | b's' | b't') => true,
            // A set-id or sticky bit with no x under it.
            (2, b'S' | b'T') => false,
            _ => return None,
        };
        if on {
            mode |= 1 << (8 - i);
        }
    }
    Some(mode)
}

/// A copy's message in the words of `podssh edit`: its hints name what
/// `cp` does.
pub(crate) fn in_edit_words(message: &str) -> String {
    message
        .replace("; -r copies it", "; podssh edit edits one file")
        .replace("; podssh cp copies files", "; podssh edit edits one file")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mode_of_a_listing_is_its_permission_bits() {
        let line = |mode: &str| format!("1234 {mode} 1 1000 1000 6 Oct 12 10:00 notes.txt");
        assert_eq!(mode_in_listing(&line("-rw-r-----")), Some(0o640));
        assert_eq!(mode_in_listing(&line("-rwxr-xr-x")), Some(0o755));
        assert_eq!(mode_in_listing(&line("-rwsr-xr-T")), Some(0o754));
        assert_eq!(mode_in_listing(&line("-rw-------.")), Some(0o600), "an SELinux mark after the bits");
        assert_eq!(mode_in_listing(&line("lrwxrwxrwx")), None, "a link is not the file");
        assert_eq!(mode_in_listing(&line("-rw?r--r--")), None);
        assert_eq!(mode_in_listing("1234"), None);
    }

    #[test]
    fn the_hints_of_a_copy_name_what_edit_does() {
        assert_eq!(in_edit_words("dir: a directory; -r copies it"), "dir: a directory; podssh edit edits one file");
        assert_eq!(in_edit_words("f: no such file"), "f: no such file");
    }
}
