//! `--no-clobber`, `--update` and `--backup` of `cp` and `mv` (T-473): what a
//! copy does with a destination that is there. **The look comes first**,
//! before any byte goes: a destination that stays is said, and its file is
//! a skip, no failure. **Then the verified file takes its name**: under
//! `--no-clobber` by a hard link, which never takes a name that is there, so
//! a name that came during the copy stays too; under `--backup` the old file
//! first takes its name with the suffix, by a hard link where one can be
//! made, so that the destination's name is never missing. With no hard
//! link, the look is the guard of `--no-clobber`, and the old file of
//! `--backup` is renamed aside first; `-v` says each.

use std::path::{Path, PathBuf};

use podssh_ssh::sftp::{FileAttributes, Sftp};
use podssh_ssh::Log;

use super::digest::Sum;
use super::meta;
use super::pipe::Shape;
use super::transfer::{self, Done, Failed, Side};
use super::tree::{self, Item};
use super::tree_copy::Planned;
use crate::exitmap::Fault;

/// What a copy does with a destination that is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Replace it, as with no flag.
    #[default]
    Replace,
    /// `--no-clobber`: leave it as it is.
    Keep,
    /// `--update`: replace it only when the source is newer, as rsync does.
    Update,
}

/// The rule of a run: its mode, and the suffix of `--backup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Clobber {
    pub mode: Mode,
    pub backup: Option<&'static str>,
}

/// Why a file did not go: the `why` of its `skipped` object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// `--no-clobber`, or a link of a tree under `--update`: a name is there.
    Exists,
    /// `--update`: the destination is not older than the source.
    NotNewer,
}

impl Skip {
    pub fn why(self) -> &'static str {
        match self {
            Skip::Exists => "exists",
            Skip::NotNewer => "not newer",
        }
    }
}

/// A file as the look sees it: its time of change in whole seconds, as SFTP
/// version 3 carries it and as `podssh run` compares it, and its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    pub mtime: Option<u32>,
    pub size: u64,
}

impl Seen {
    pub fn of_local(file: &std::fs::Metadata) -> Seen {
        Seen { mtime: file.modified().ok().and_then(meta::seconds), size: file.len() }
    }

    pub fn of_far(attrs: &FileAttributes) -> Seen {
        Seen { mtime: attrs.mtime, size: attrs.size.unwrap_or(0) }
    }
}

/// The rule that `-n`, `-u`, `-b` and `--suffix` ask for, or why they do
/// not go together: a usage error before anything connects.
pub fn of(
    no_clobber: bool,
    update: bool,
    backup: bool,
    suffix: Option<&str>,
    inplace: bool,
) -> Result<Clobber, String> {
    if no_clobber && backup {
        return Err(
            "--no-clobber and --backup do not go together: one keeps the destination, the other its old file".into()
        );
    }
    if backup && inplace {
        return Err("--backup and --inplace do not go together: a copy into the destination keeps no old file".into());
    }
    let backup = match (backup, suffix) {
        (false, Some(_)) => return Err("--suffix goes with --backup".into()),
        (false, None) => None,
        (true, None) => Some("~"),
        // The backup stays beside its file: a suffix names no directory.
        (true, Some(s)) if s.is_empty() || s.contains(['/', '\\', '\0']) => {
            return Err(format!("--suffix {s:?}: give a suffix that is not empty, with no / or \\"))
        }
        // Once for the run, so that the rule stays `Copy` in each `Shape`.
        (true, Some(s)) => Some(&*Box::leak(s.to_string().into_boxed_str())),
    };
    // -n wins over -u: a name that is there stays, whatever its time.
    let mode = match (no_clobber, update) {
        (true, _) => Mode::Keep,
        (false, true) => Mode::Update,
        (false, false) => Mode::Replace,
    };
    Ok(Clobber { mode, backup })
}

/// Whether a file stays out: `dest` is `None` when its name is missing.
/// `--update` copies a later source, and one of the same second whose size
/// differs, as rsync's does; with no time to compare, the file goes.
pub fn decide(mode: Mode, source: Seen, dest: Option<Seen>) -> Option<Skip> {
    let dest = dest?;
    match (mode, source.mtime, dest.mtime) {
        (Mode::Replace, ..) => None,
        (Mode::Keep, ..) => Some(Skip::Exists),
        (Mode::Update, Some(s), Some(d)) if s > d || (s == d && source.size != dest.size) => None,
        (Mode::Update, Some(_), Some(_)) => Some(Skip::NotNewer),
        (Mode::Update, ..) => None,
    }
}

/// The line of a destination that `--no-clobber` keeps.
pub fn there(target: &str) -> String {
    format!("{target}: there, so not replaced")
}

/// [`decide`] for `target`, and said: a name that `--no-clobber` keeps at
/// the default level, one that `--update` keeps at `-v`, and a time that
/// cannot be compared at the default level.
pub fn judged(clobber: Clobber, target: &str, source: Seen, dest: Option<Seen>, log: &Log) -> Option<Skip> {
    let unknown = dest.is_some_and(|d| d.mtime.is_none() || source.mtime.is_none());
    if clobber.mode == Mode::Update && unknown {
        log.info(&format!("{target}: a time of change is not known here, so --update replaces it"));
    }
    let skip = decide(clobber.mode, source, dest);
    match skip {
        Some(Skip::Exists) => log.info(&there(target)),
        Some(Skip::NotNewer) => log.verbose(&format!("{target}: not older than the source, so not replaced")),
        None => {}
    }
    skip
}

/// The answer of a file that did not go: no byte went, and its destination
/// is as it was.
pub fn skipped(source: &str, target: &str, skip: Skip) -> Done {
    Done { source: source.into(), destination: target.into(), skipped: Some(skip), ..Done::default() }
}

/// The far `target` as the look sees it: `None` when its name is missing.
async fn far_seen(sftp: &Sftp, target: &str) -> Result<Option<Seen>, Failed> {
    match sftp.lstat(target).await {
        Ok(attrs) => Ok(Some(Seen::of_far(&attrs))),
        Err(e) if e.is_missing() => Ok(None),
        Err(e) => Err(transfer::from_sftp(e, Side::Destination)),
    }
}

/// The local `target` as the look sees it.
fn local_seen(target: &Path) -> Result<Option<Seen>, Failed> {
    match std::fs::symlink_metadata(target) {
        Ok(meta) => Ok(Some(Seen::of_local(&meta))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Failed::new(Fault::CantCreate, format!("{}: {e}", target.display()))),
    }
}

/// The look on the server before a copy's first byte: the answer of a file
/// that does not go. A copy that goes on from an attempt before looked then.
pub async fn before_far(
    sftp: &Sftp,
    source: &str,
    target: &str,
    seen: Seen,
    clobber: Clobber,
    resumed: bool,
    log: &Log,
) -> Result<Option<Done>, Failed> {
    if clobber.mode == Mode::Replace || resumed {
        return Ok(None);
    }
    let dest = far_seen(sftp, target).await?;
    Ok(judged(clobber, target, seen, dest, log).map(|skip| skipped(source, target, skip)))
}

/// [`before_far`] for a destination here.
pub fn before_local(
    source: &str,
    target: &Path,
    seen: Seen,
    clobber: Clobber,
    resumed: bool,
    log: &Log,
) -> Result<Option<Done>, Failed> {
    if clobber.mode == Mode::Replace || resumed {
        return Ok(None);
    }
    let shown = target.display().to_string();
    let dest = local_seen(target)?;
    Ok(judged(clobber, &shown, seen, dest, log).map(|skip| skipped(source, &shown, skip)))
}

/// What the placing of a verified file did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Placed {
    /// The old file was removed before the rename: no posix-rename.
    pub not_atomic: bool,
    /// `--backup`: the name that holds the old file.
    pub backup: Option<String>,
    /// `--no-clobber`: a name that came during the copy, which stays.
    pub skipped: Option<Skip>,
}

/// The verified file `temp` at `target` on the server, as `clobber` asks;
/// `temp`'s name is gone after it, also when the destination stays.
pub async fn place_far(sftp: &Sftp, temp: &str, target: &str, clobber: Clobber, log: &Log) -> Result<Placed, Failed> {
    if clobber.mode == Mode::Keep {
        if let Some(placed) = link_far(sftp, temp, target, log).await {
            if placed.skipped.is_some() {
                let _ = sftp.remove(temp).await;
            }
            return Ok(placed);
        }
    }
    let backup = match clobber.backup {
        Some(suffix) => backup_far(sftp, target, suffix, log).await?,
        None => None,
    };
    let not_atomic = transfer::rename_onto(sftp, temp, target, log).await?;
    Ok(Placed { not_atomic, backup, skipped: None })
}

/// `--no-clobber` on the server: `from` takes the name `target` by a hard
/// link (`hardlink@openssh.com`, POSIX `link()` on OpenSSH's server), which
/// refuses a name that is there, and its own name then goes. `None` with no
/// hard link there, for the rename after the look; `from` stays when the
/// name was taken, for the caller (`mv` keeps its source).
pub async fn link_far(sftp: &Sftp, from: &str, target: &str, log: &Log) -> Option<Placed> {
    if !sftp.has("hardlink@openssh.com") {
        log.verbose(&format!(
            "{target}: the server has no hardlink@openssh.com, so the look is the guard of --no-clobber"
        ));
        return None;
    }
    match sftp.hardlink(from, target).await {
        Ok(()) => {
            let _ = sftp.remove(from).await;
            Some(Placed::default())
        }
        // A name that came during the copy stays.
        Err(_) if sftp.lstat(target).await.is_ok() => {
            log.info(&there(target));
            Some(Placed { skipped: Some(Skip::Exists), ..Placed::default() })
        }
        Err(e) => {
            log.verbose(&format!("{target}: no hard link ({e}), so the look is the guard of --no-clobber"));
            None
        }
    }
}

/// `--backup` on the server: the old file at `target` takes the name with
/// `suffix`, an older backup there going first. A hard link leaves `target`
/// as it is until the rename; with none, a rename, and the name is missing
/// for that moment. `None` when no file is there to keep; a directory there
/// fails the rename as with no flag.
pub async fn backup_far(sftp: &Sftp, target: &str, suffix: &str, log: &Log) -> Result<Option<String>, Failed> {
    if !matches!(sftp.lstat(target).await, Ok(attrs) if !attrs.is_dir()) {
        return Ok(None);
    }
    let aside = format!("{target}{suffix}");
    if let Ok(attrs) = sftp.lstat(&aside).await {
        if attrs.is_dir() {
            return Err(Failed::new(
                Fault::CantCreate,
                format!("{aside}: a directory, where --backup keeps the old file"),
            ));
        }
        sftp.remove(&aside).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
    }
    if sftp.has("hardlink@openssh.com") && sftp.hardlink(target, &aside).await.is_ok() {
        return Ok(Some(aside));
    }
    log.verbose(&format!(
        "{target}: no hard link, so the old file is renamed to {aside} first; the name is missing a moment"
    ));
    sftp.rename(target, &aside).await.map_err(|e| transfer::from_sftp(e, Side::Destination))?;
    Ok(Some(aside))
}

/// [`place_far`] for a destination here: `std::fs::hard_link` refuses a
/// name that is there, as `link()` does.
pub fn place_local(temp: &Path, target: &Path, clobber: Clobber, log: &Log) -> Result<Placed, Failed> {
    let shown = target.display().to_string();
    if clobber.mode == Mode::Keep {
        match std::fs::hard_link(temp, target) {
            Ok(()) => {
                let _ = std::fs::remove_file(temp);
                return Ok(Placed::default());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(temp);
                log.info(&there(&shown));
                return Ok(Placed { skipped: Some(Skip::Exists), ..Placed::default() });
            }
            Err(e) => log.verbose(&format!("{shown}: no hard link ({e}), so the look is the guard of --no-clobber")),
        }
    }
    let backup = match clobber.backup {
        Some(suffix) => backup_local(target, suffix, log)?,
        None => None,
    };
    std::fs::rename(temp, target).map_err(|e| Failed::new(Fault::CantCreate, format!("{shown}: {e}")))?;
    Ok(Placed { backup, ..Placed::default() })
}

/// The end of a copy down: the verified `temp` at `target` as the rule
/// asks, or where it is with `--inplace`; the file done, or not copied when
/// its name came during the copy.
#[allow(clippy::too_many_arguments)]
pub fn done_here(
    source: &str,
    temp: &Path,
    target: &Path,
    bytes: u64,
    sum: Sum,
    verified_by: String,
    shape: Shape,
    log: &Log,
) -> Result<Done, Failed> {
    let shown = target.display().to_string();
    let placed = if shape.inplace { Placed::default() } else { place_local(temp, target, shape.clobber, log)? };
    if let Some(skip) = placed.skipped {
        return Ok(skipped(source, &shown, skip));
    }
    let backup = placed.backup;
    Ok(Done {
        source: source.into(),
        destination: shown,
        bytes,
        sum: Some(sum),
        verified_by,
        backup,
        ..Done::default()
    })
}

/// [`backup_far`] for a destination here.
fn backup_local(target: &Path, suffix: &str, log: &Log) -> Result<Option<String>, Failed> {
    if !matches!(std::fs::symlink_metadata(target), Ok(meta) if !meta.is_dir()) {
        return Ok(None);
    }
    let mut name = target.as_os_str().to_owned();
    name.push(suffix);
    let aside = PathBuf::from(name);
    let shown = aside.display().to_string();
    let cant = |e: std::io::Error| Failed::new(Fault::CantCreate, format!("{shown}: {e}"));
    match std::fs::symlink_metadata(&aside) {
        Ok(meta) if meta.is_dir() => {
            return Err(Failed::new(
                Fault::CantCreate,
                format!("{shown}: a directory, where --backup keeps the old file"),
            ))
        }
        Ok(_) => std::fs::remove_file(&aside).map_err(cant)?,
        Err(_) => {}
    }
    if std::fs::hard_link(target, &aside).is_err() {
        let from = target.display();
        log.verbose(&format!(
            "{from}: no hard link, so the old file is renamed to {shown} first; the name is missing a moment"
        ));
        std::fs::rename(target, &aside).map_err(cant)?;
    }
    Ok(Some(shown))
}

/// `--delete` with `--backup`: a name that ends with the suffix is never
/// deleted, as rsync protects its backups, nor a directory that holds one.
pub(super) fn protect(target: &mut Vec<Item>, clobber: Clobber) {
    let Some(suffix) = clobber.backup else { return };
    let kept: Vec<String> = target
        .iter()
        .map(tree::rel_of)
        .filter(|rel| rel.rsplit('/').next().is_some_and(|name| name.ends_with(suffix)))
        .map(str::to_string)
        .collect();
    target.retain(|item| {
        let rel = tree::rel_of(item);
        let within = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
        !kept.iter().any(|k| within(k.as_str(), rel) || within(rel, k.as_str()))
    });
}

/// A dry run's actions for one file of a tree: `skip` when the look keeps
/// its destination, else `backup` first when one is there, then `copy`.
pub(super) fn planned(
    from: String,
    target: String,
    source: Option<Seen>,
    dest: Option<Seen>,
    clobber: Clobber,
) -> Vec<Planned> {
    if let Some(skip) = source.and_then(|s| decide(clobber.mode, s, dest)) {
        return vec![("skip", from, skip.why().to_string())];
    }
    let mut out = Vec::new();
    if let (Some(suffix), true) = (clobber.backup, dest.is_some()) {
        out.push(("backup", target.clone(), format!("{target}{suffix}")));
    }
    out.push(("copy", from, target));
    out
}

/// [`planned`] for a file of a tree up: the local source, the far target.
pub(super) async fn dry_up(sftp: Option<&Sftp>, from: String, target: String, clobber: Clobber) -> Vec<Planned> {
    if clobber == Clobber::default() {
        return vec![("copy", from, target)];
    }
    let source = std::fs::metadata(&from).ok().map(|m| Seen::of_local(&m));
    let dest = match sftp {
        Some(sftp) => far_seen(sftp, &target).await.ok().flatten(),
        None => None,
    };
    planned(from, target, source, dest, clobber)
}

/// [`planned`] for a file of a tree down: the far source, the local target.
pub(super) async fn dry_down(sftp: Option<&Sftp>, from: String, target: String, clobber: Clobber) -> Vec<Planned> {
    if clobber == Clobber::default() {
        return vec![("copy", from, target)];
    }
    let source = match sftp {
        Some(sftp) => sftp.stat(&from).await.ok().map(|a| Seen::of_far(&a)),
        None => None,
    };
    let dest = local_seen(Path::new(&target)).ok().flatten();
    planned(from, target, source, dest, clobber)
}

#[cfg(test)]
#[path = "clobber_tests.rs"]
mod tests;
