//! A copy that continues after a broken connection (T-136).
//!
//! **What a copy has done is kept**: its temporary file stays, with the
//! offset below which each byte is in it, in memory for the run and in a side
//! file of the cache directories across runs (`podssh-cp-*.resume`, private;
//! never a byte of the file). A new connection, or the same command run
//! again, continues at that offset while the source is still what it was;
//! else the copy starts over, and says so.
//!
//! **The attempts are bounded**: [`TRIES`] in a row with no new byte, with
//! the relay opener's backoff between them. A refused login, a host key that
//! changed (pinned for the run) or a refusal of the relay's policy ends the
//! copy at once, and `--timeout` bounds it all. The digest still covers the
//! whole file: a continued copy whose digests differ starts once more from
//! the first byte, then fails.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use super::link::{Link, Road};
use super::operand::Operand;
use super::transfer::{self, Failed, Side};
use crate::exitmap::Fault;

/// Attempts in a row with no new byte, after a break, before the copy stops.
pub const TRIES: u32 = 5;

/// The side file is written again after each this many bytes.
const SAVE_EVERY: u64 = 4 << 20;

/// A source as it was before its copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Before {
    /// A local file: its size, its time of change, and which file it is
    /// (the device and inode; on Windows, when it was made).
    Local { len: u64, modified: Option<SystemTime>, id: Option<(u64, u64)> },
    /// A far file over SFTP: its size and time of change, in seconds;
    /// version 3 names no inode.
    Sftp { size: Option<u64>, mtime: Option<u32> },
    /// A far file by exec: what `ls -lnid` says of it, its inode first.
    Exec(String),
}

impl Before {
    /// The state on one line, for the side file.
    pub fn key(&self) -> String {
        match self {
            Before::Local { len, modified, id } => {
                let nanos = modified.and_then(|m| m.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_nanos());
                format!("local {len} {nanos:?} {id:?}")
            }
            Before::Sftp { size, mtime } => format!("sftp {size:?} {mtime:?}"),
            Before::Exec(line) => format!("exec {line}"),
        }
    }
}

/// What a local source is now.
pub fn local(path: &str) -> Result<Before, Failed> {
    let meta = std::fs::metadata(path).map_err(|e| Failed::new(Fault::NoInput, format!("{path}: {e}")))?;
    Ok(Before::Local { len: meta.len(), modified: meta.modified().ok(), id: file_id(&meta) })
}

/// Which file a local path names: the device and inode, or on Windows the
/// time the file was made, which a file renamed into its place does not
/// share.
fn file_id(meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((meta.dev(), meta.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Some((meta.creation_time(), 0))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = meta;
        None
    }
}

/// What a far source is now, by the link's road.
pub async fn far(link: &Link, path: &str) -> Result<Before, Failed> {
    match &link.road {
        Road::Sftp(sftp) => {
            let attrs = sftp.stat(path).await.map_err(|e| transfer::from_sftp(e, Side::Source))?;
            Ok(Before::Sftp { size: attrs.size, mtime: attrs.mtime })
        }
        Road::Exec(far) => far.listing(link.handle(), path).await.map(Before::Exec),
    }
}

/// What `source` is now, on its side.
pub async fn before(link: &Link, source: &Operand) -> Result<Before, Failed> {
    match source {
        Operand::Local(path) => local(path),
        Operand::Remote(r) => far(link, &r.path).await,
    }
}

/// The side file of a copy: a digest of the server, the current directory
/// and both paths, so that its name says nothing of them.
pub fn side_name(server: &str, port: u16, source: &str, dest: &str) -> String {
    let here = std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default();
    let mut hasher = Sha256::new();
    for part in [server, &port.to_string(), &here, source, dest] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    let sum: [u8; 32] = hasher.finalize().into();
    let hex: String = sum[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("podssh-cp-{hex}.resume")
}

/// Whether `path` names one of podssh's temporary files, as
/// [`transfer::temp_name`] makes them: the only kind that a side file may
/// have removed.
pub fn is_temp(path: &str) -> bool {
    let leaf = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let Some(rest) = leaf.strip_prefix('.').and_then(|l| l.strip_suffix(".part")) else { return false };
    rest.rsplit_once(".podssh-").is_some_and(|(_, tag)| tag.len() == 16 && tag.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// What the copy of one file has done, so that a new connection, or the
/// same command run again, can continue it.
#[derive(Debug, Clone, Default)]
pub struct Progress {
    /// The cache directories, in order.
    dirs: Vec<PathBuf>,
    /// The side file's name in them.
    side: String,
    /// The source's state when the copy began ([`Before::key`]).
    pub state: String,
    /// The destination's name, once known.
    pub target: Option<String>,
    /// The temporary file, once made: on the server for a copy up, here for
    /// a copy down.
    pub temp: Option<String>,
    /// Each byte below this offset is in the temporary file.
    pub offset: u64,
    /// The offset when the side file was last written.
    saved: u64,
}

impl Progress {
    /// The copy whose side file is `side`, for a source now in the state
    /// `state`: where an earlier run left it when that run saw the same
    /// state, else a copy from the start. A side file that is stale goes,
    /// and its temporary file is given back, to be removed.
    pub fn load(side: String, state: String) -> (Progress, Option<String>) {
        Progress::load_in(podssh_relay::cache::candidate_dirs(), side, state)
    }

    /// [`Progress::load`] in the cache directories `dirs`.
    pub fn load_in(dirs: Vec<PathBuf>, side: String, state: String) -> (Progress, Option<String>) {
        let fresh = Progress { dirs: dirs.clone(), side: side.clone(), state: state.clone(), ..Progress::default() };
        let Some(text) = podssh_relay::cache::load_file_from(&dirs, &side) else { return (fresh, None) };
        let kept: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        let field = |name: &str| kept.get(name).and_then(|v| v.as_str()).map(str::to_string);
        let temp = field("temp").filter(|t| is_temp(t));
        let offset = kept.get("offset").and_then(|v| v.as_u64());
        match (field("state"), temp, field("target"), offset) {
            (Some(was), Some(temp), Some(target), Some(offset)) if was == state => {
                let progress =
                    Progress { dirs, side, state, target: Some(target), temp: Some(temp), offset, saved: offset };
                (progress, None)
            }
            (_, stale, _, _) => {
                podssh_relay::cache::remove_named_from(&dirs, &side);
                (fresh, stale)
            }
        }
    }

    /// A copy that starts: the temporary file `temp` for `target`.
    pub fn begin(&mut self, target: &str, temp: &str) {
        self.target = Some(target.to_string());
        self.temp = Some(temp.to_string());
        self.offset = 0;
        self.save();
    }

    /// Each byte below `offset` is in the temporary file; the side file
    /// follows each [`SAVE_EVERY`] bytes.
    pub fn advance(&mut self, offset: u64) {
        self.offset = offset;
        if offset >= self.saved.saturating_add(SAVE_EVERY) {
            self.save();
        }
    }

    /// The copy is done, or cannot continue: the side file goes.
    pub fn clear(&mut self) {
        podssh_relay::cache::remove_named_from(&self.dirs, &self.side);
        self.target = None;
        self.temp = None;
        self.offset = 0;
        self.saved = 0;
    }

    /// Write the side file. Without a cache directory the copy continues
    /// within this run only.
    pub fn save(&mut self) {
        let body = serde_json::json!({
            "state": self.state,
            "target": self.target,
            "temp": self.temp,
            "offset": self.offset,
        });
        if podssh_relay::cache::store_file_in_first(&self.dirs, &self.side, body.to_string().as_bytes()).is_ok() {
            self.saved = self.offset;
        }
    }
}

/// The local temporary file of a copy down, open, and the bytes in it: the
/// one that `progress` names, cut at its offset, when it holds that many and
/// the source has as many (`size`); else a new one beside `target`, private.
pub fn local_temp(target: &Path, size: u64, progress: &mut Progress) -> Result<(PathBuf, File, u64), Failed> {
    if let Some(temp) = progress.temp.clone() {
        let path = PathBuf::from(&temp);
        let fits = progress.offset <= size
            && std::fs::metadata(&path).is_ok_and(|m| m.is_file() && m.len() >= progress.offset);
        let opened = fits.then(|| std::fs::OpenOptions::new().read(true).write(true).open(&path).ok()).flatten();
        if let Some(mut file) = opened {
            if file.set_len(progress.offset).and_then(|()| file.seek(SeekFrom::Start(0))).is_ok() {
                return Ok((path, file, progress.offset));
            }
        }
        let _ = std::fs::remove_file(&path);
    }
    let leaf = target.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let temp = target.with_file_name(transfer::temp_name(leaf));
    let file = transfer::create_private(&temp)
        .map_err(|e| Failed::new(Fault::CantCreate, format!("{}: {e}", temp.display())))?;
    progress.begin(&target.display().to_string(), &temp.display().to_string());
    Ok((temp, file, 0))
}

/// Read the first `n` bytes of `reader` into `hasher`: the part of a file
/// that an earlier attempt sent, which the digest covers too.
pub fn hash_prefix(reader: &mut impl Read, hasher: &mut Sha256, n: u64) -> std::io::Result<()> {
    let mut left = n;
    let mut buf = vec![0u8; 1 << 20];
    while left > 0 {
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let got = reader.read(&mut buf[..want])?;
        if got == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the file is shorter than its offset"));
        }
        hasher.update(&buf[..got]);
        left -= got as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_podssh_s_temporary_names_count_as_temporary() {
        assert!(is_temp(&format!("dir/{}", transfer::temp_name("a b.txt"))));
        assert!(is_temp(r"C:\x\.f.podssh-0123456789abcdef.part"));
        for not in ["f.part", ".f.part", ".f.podssh-xyz.part", "dir/.f.podssh-0123456789abcdef", "/etc/passwd"] {
            assert!(!is_temp(not), "{not}");
        }
    }

    #[test]
    fn a_side_file_names_neither_path() {
        let a = side_name("u@h", 22, "/srv/secret.db", "local.db");
        assert!(a.starts_with("podssh-cp-") && a.ends_with(".resume") && !a.contains("secret"), "{a}");
        assert_ne!(a, side_name("u@h", 22, "/srv/secret.db", "other.db"));
        assert_ne!(a, side_name("u@h", 2222, "/srv/secret.db", "local.db"));
    }

    /// A cache directory of the test's own.
    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!("podssh-resume-{:016x}", rand::random::<u64>()))
    }

    #[test]
    fn a_side_file_continues_the_same_source_only() {
        let dir = scratch();
        let temp = format!("srv/{}", transfer::temp_name("f"));
        let load = |state: &str| Progress::load_in(vec![dir.clone()], "s.resume".into(), state.into());
        let (mut first, stale) = load("local 5 x");
        assert_eq!((first.temp.as_deref(), stale), (None, None));
        first.begin("srv/f", &temp);
        first.advance(SAVE_EVERY + 1);
        // The same source: the copy goes on where the side file says.
        let (again, stale) = load("local 5 x");
        assert_eq!(stale, None);
        assert_eq!(again.temp.as_deref(), Some(temp.as_str()));
        assert_eq!((again.target.as_deref(), again.offset), (Some("srv/f"), SAVE_EVERY + 1));
        // A changed source: the copy starts over, the stale temporary file is
        // given back for removal, and the side file goes.
        let (fresh, stale) = load("local 6 y");
        assert_eq!(stale.as_deref(), Some(temp.as_str()));
        assert_eq!((fresh.temp, fresh.offset), (None, 0));
        let (gone, stale) = load("local 5 x");
        assert_eq!((gone.temp, stale), (None, None), "the stale side file was removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_side_file_follows_each_four_mib_and_goes_when_done() {
        let dir = scratch();
        let load = || Progress::load_in(vec![dir.clone()], "t.resume".into(), "state".into()).0;
        let mut p = load();
        p.begin("f", &transfer::temp_name("f"));
        p.advance(SAVE_EVERY - 1);
        assert_eq!(load().offset, 0, "not written yet");
        p.advance(SAVE_EVERY);
        assert_eq!(load().offset, SAVE_EVERY);
        p.clear();
        assert_eq!(load().temp, None, "a copy that is done leaves no side file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_side_file_that_names_another_file_is_not_trusted() {
        let dir = scratch();
        let load = || Progress::load_in(vec![dir.clone()], "u.resume".into(), "state".into());
        load().0.begin("f", "/etc/passwd");
        let (fresh, stale) = load();
        assert_eq!((fresh.temp, stale), (None, None), "never a file that podssh did not make");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_prefix_of_a_file_goes_into_the_digest() {
        let data = b"0123456789";
        let mut hasher = Sha256::new();
        hash_prefix(&mut &data[..], &mut hasher, 4).expect("four bytes");
        hasher.update(&data[4..]);
        assert_eq!(<[u8; 32]>::from(hasher.finalize()), <[u8; 32]>::from(Sha256::digest(data)));
        let mut short = Sha256::new();
        assert!(hash_prefix(&mut &data[..], &mut short, 11).is_err(), "a file shorter than its offset");
    }
}
