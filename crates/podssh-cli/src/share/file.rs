//! A node's share file (T-433): one share on each line, `NAME=HOST:PORT`,
//! and `#` a comment. The node reads it again for each session, and `podssh
//! share` changes it: `node-NAME.shares` in the cache, beside the node's key,
//! or the file of `--shares FILE`, for both. A change is made under the lock
//! of `FILE.lock` beside it, on the text read again there, and kept whole by
//! a rename, so that two changes at once both count and a node never reads
//! half a file. The lines that a change does not touch stay as they are, a
//! person's comments with them.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use podssh_relay::cache::{self, Others};
use podssh_relay::reverse::routes::Route;

use crate::exitmap::sysexits;
use crate::relay_settings::Refusal;

/// How long a change waits for another one's lock: a read and a write.
pub const WAIT: Duration = Duration::from_secs(5);
/// The most shares of one node, as each session may read them all.
pub const MAX_SHARES: usize = 256;
/// The first line of a file that `podssh share` makes.
const HEAD: &str = "# A podssh node's shares, NAME=HOST:PORT on each line (podssh share)\n";

/// Where a node's shares are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// The file of this name in the first of the cache's directories that
    /// has it.
    Cache(String),
    /// The file of `--shares FILE`.
    File(PathBuf),
}

impl Place {
    /// The place as a line says it, before the file is found.
    pub fn shown(&self) -> String {
        match self {
            Place::Cache(name) => format!("{name} in the cache"),
            Place::File(path) => path.display().to_string(),
        }
    }
}

/// The file's name in the cache for the node `label`: beside its key,
/// `node-NAME.key`, by the same rule.
pub fn file_name(label: &str) -> String {
    format!("node-{}.shares", cache::safe_name(label))
}

/// One share: its name, a route's, and the TCP service that it reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub name: String,
    pub host: String,
    pub port: u16,
}

impl Share {
    /// `NAME=HOST:PORT`, checked as a node checks its `ROUTE=TARGET`.
    pub fn parse(word: &str) -> Result<Share, String> {
        let (name, target) = word.split_once('=').ok_or_else(|| format!("{word:?} is not NAME=HOST:PORT"))?;
        podssh_ws::names::check_node_name(name).map_err(|_| {
            format!("{word}: {name:?} is not a share's name: letters, digits, '.', '-' and '_', not first '-' or '.'")
        })?;
        // A UDP flow is a node's one TARGET (T-168), never one of its routes.
        if target.starts_with("udp:") {
            return Err(format!("{word}: a share is a TCP service; a UDP one is the TARGET of a node of its own"));
        }
        let (host, port) = crate::proxy::parse_target(Some(target), None).map_err(|why| format!("{word}: {why}"))?;
        Ok(Share { name: name.to_string(), host, port })
    }

    /// `HOST:PORT`, or `[IPV6]:PORT`.
    pub fn target(&self) -> String {
        podssh_ws::dial::authority(&self.host, self.port)
    }

    /// Its line of the file.
    pub fn line(&self) -> String {
        format!("{}={}", self.name, self.target())
    }

    /// The route that the node serves for it.
    pub fn route(&self) -> Route {
        Route { name: Some(self.name.clone()), host: self.host.clone(), port: self.port }
    }
}

/// What a file says: each share, and the numbers of its lines that are
/// none, from 1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shares {
    pub list: Vec<Share>,
    pub bad: Vec<usize>,
}

impl Shares {
    /// The shares of `text`. A name's first line counts, as a route is given
    /// once; a later one, and one past [`MAX_SHARES`], is a bad line.
    pub fn parse(text: &str) -> Shares {
        let mut shares = Shares::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match Share::parse(line) {
                Ok(share) if shares.list.len() < MAX_SHARES && !shares.list.iter().any(|s| s.name == share.name) => {
                    shares.list.push(share)
                }
                _ => shares.bad.push(n + 1),
            }
        }
        shares
    }

    /// The names, by commas, as a node's line says them.
    pub fn names(&self) -> String {
        self.list.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")
    }
}

/// `text` with `share` in the line of its name, or added at its end: the
/// other lines as they are, and a later line of the same name gone, as it
/// served nothing. The new text, and the share that it replaced.
pub fn with_share(text: &str, share: &Share) -> (String, Option<Share>) {
    let mut before = None;
    let mut out = String::new();
    for line in text.lines() {
        match Share::parse(line.trim()) {
            Ok(old) if old.name == share.name && before.is_none() => {
                out.push_str(&share.line());
                before = Some(old);
            }
            Ok(old) if old.name == share.name => continue,
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    if before.is_none() {
        if out.is_empty() {
            out.push_str(HEAD);
        }
        out.push_str(&share.line());
        out.push('\n');
    }
    (out, before)
}

/// `text` with no line of the share `name`: the new text, and the share
/// that went, when there was one.
pub fn without(text: &str, name: &str) -> (String, Option<Share>) {
    let mut gone = None;
    let mut out = String::new();
    for line in text.lines() {
        match Share::parse(line.trim()) {
            Ok(old) if old.name == name => {
                gone.get_or_insert(old);
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    (out, gone)
}

/// The file of `place` now, as the node reads it for each session: its path
/// and its text, or none. A file that others may change is refused, as an
/// allowlist is: it names what the node dials.
pub fn read(place: &Place) -> Result<Option<(PathBuf, String)>, String> {
    match place {
        Place::File(path) => Ok(cache::read_own(path, Others::Read)?.map(|text| (path.clone(), text))),
        Place::Cache(name) => {
            for dir in cache::candidate_dirs() {
                let path = dir.join(name);
                if let Some(text) = cache::read_own(&path, Others::Read)? {
                    return Ok(Some((path, text)));
                }
            }
            Ok(None)
        }
    }
}

/// `change` made to the file of `place` under its lock: given the text read
/// there again (none: empty), it gives the new text, or none for no change,
/// and what to say. The file's path, and that.
pub fn edit<T>(
    place: &Place,
    change: impl FnOnce(&str) -> Result<(Option<String>, T), Refusal>,
) -> Result<(PathBuf, T), Refusal> {
    let path = write_path(place)?;
    let _held = hold(&path)?;
    let text = cache::read_own(&path, Others::Read).map_err(Refusal::config)?.unwrap_or_default();
    let (next, said) = change(&text)?;
    if let Some(next) = next {
        replace(&path, next.as_bytes()).map_err(|why| Refusal { message: why, code: sysexits::EX_CANTCREAT })?;
    }
    Ok((path, said))
}

/// Where a change of `place` is written: the file that has the shares, else
/// a new one in the first of the cache's directories that takes one.
fn write_path(place: &Place) -> Result<PathBuf, Refusal> {
    let name = match place {
        Place::File(path) => return Ok(path.clone()),
        Place::Cache(name) => name,
    };
    if let Some((path, _)) = read(place).map_err(Refusal::config)? {
        return Ok(path);
    }
    let dirs = cache::candidate_dirs();
    if dirs.is_empty() {
        return Err(Refusal::config(format!(
            "{}=none keeps no file, so a node's shares are in the file of --shares FILE, the node's and this one's",
            cache::DIR_ENV
        )));
    }
    let mut refused = Vec::new();
    for dir in &dirs {
        match cache::private_dir(dir) {
            Ok(()) => return Ok(dir.join(name)),
            Err(e) => refused.push(format!("{}: {e}", dir.display())),
        }
    }
    let message = format!("no directory of the cache would take {name} ({})", refused.join("; "));
    Err(Refusal { message, code: sysexits::EX_CANTCREAT })
}

/// The lock of `FILE.lock` beside `path`, held until it is dropped: none
/// where the file system takes no lock, and the change goes on without one,
/// as a `known_hosts` file is written there. Another change that keeps it
/// for [`WAIT`] fails this one (75): never a wait with no end.
fn hold(path: &Path) -> Result<Option<File>, Refusal> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let lock = PathBuf::from(name);
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let Ok(file) = options.open(&lock) else { return Ok(None) };
    let deadline = Instant::now() + WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Some(file)),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                let message = format!(
                    "{}: another change of these shares held its lock for {} s; run the command again",
                    lock.display(),
                    WAIT.as_secs()
                );
                return Err(Refusal { message, code: sysexits::EX_TEMPFAIL });
            }
            Err(std::fs::TryLockError::Error(_)) => return Ok(None),
        }
    }
}

/// `path` replaced whole by `body`: a private file beside it, then a rename,
/// so that a node that reads it meanwhile reads the one before or this one.
fn replace(path: &Path, body: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let result = (|| {
        let mut file = cache::create_new_private(&tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{}: {e}", path.display()));
    }
    Ok(())
}
