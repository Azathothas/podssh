//! E12: where a cached token lives, and the chain that resolves it.
//!
//! ⛔ **The chain is the operator's, and this file does not get to have an
//! opinion.** `docs/spec/08-tokens.md`, *answered by the operator 2026-10-01*:
//! *"tokens may live in $TEMP if $HOME/XDG aren't available/writeable, if even
//! $TEMP is not writable, try /dev/shm if even that's not possible, then use
//! whatever dir podssh was run from."* ⛔ The table in that document gives the
//! order this file walks, and a chain that is probed rather than assumed is the
//! whole of its rule.
//!
//! ⛔ **A previous session's record is a claim to verify.** `E12`'s entry said
//! *"in memory only, zeroized on drop"* as a **default taken without asking**,
//! and the operator's answer refuted it. ⛔ The `Decision` row still carries the
//! old wording, and it is kept there on purpose ⛔ because a disproved premise
//! keeps its title and gains the correction underneath.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::token::RelayToken;

/// ⛔ **One probe, one answer.** `RULES.md`: ⛔ *"never gate startup on a
/// capability that has not been probed."* ⛔ `$HOME` may not exist on the
/// constrained host (`docs/spec/04-constrained-env.md`: no `/etc/passwd`) and
/// `E05`'s `open()` for a writable `$HOME` **has never been run on any host**, so
/// ⛔ this walks the chain and asks the filesystem rather than assuming an entry
/// is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// ⛔ Every candidate, in the order the chain reaches them, with the reason
    /// each was accepted or refused. ⛔ **A chain that reports only the winner
    /// is a chain a reader cannot check**, and `docs/spec/08-tokens.md` says the
    /// choice is reported once so a user is never guessing where their token
    /// went.
    pub tried: Vec<Attempt>,
    pub chosen: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub path: PathBuf,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// ⛔ An explicit override always wins, so a user is never fighting the chain.
    Override,
    /// ⛔ The directory exists and the file could be opened for append.
    Writable,
    /// ⛔ The variable is unset, so the candidate was never formed.
    Unset,
    /// ⛔ The directory does not exist.
    NoDirectory,
    /// ⛔ The directory exists and the file could not be opened.
    NotWritable,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Override => "override",
            Outcome::Writable => "writable",
            Outcome::Unset => "unset",
            Outcome::NoDirectory => "no such directory",
            Outcome::NotWritable => "not writable",
        }
    }
}

/// ⛔ **What the chain is probed against.** ⛔ A trait rather than a direct call
/// to `std::env` and `std::fs` because ⛔ **the tests have to be able to run the
/// chain against a filesystem that does not exist on the test machine** — a
/// `/dev/shm` probe on Windows is a probe of Windows, not of the constrained
/// host, and a test that silently measured the wrong host is the defect this
/// repository has already shipped once.
pub trait Environment {
    fn var(&self, name: &str) -> Option<String>;
    fn current_dir(&self) -> PathBuf;
    /// ⛔ `Ok(())` when `path` could be opened for append, which is ⛔ **the
    /// specification's own test**: *"Each candidate is tried by opening it for
    /// append."*
    fn try_append(&self, path: &Path) -> Result<(), String>;
}

/// ⛔ **The real environment. Every `var` is a read and every `try_append` is a
/// real `open(2)` for append** ⛔ — which is what makes this a probe rather than
/// a predicate, and what `docs/spec/04-constrained-env.md` means by "probed".
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnv;

impl Environment for SystemEnv {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.is_empty())
    }

    fn current_dir(&self) -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    fn try_append(&self, path: &Path) -> Result<(), String> {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => return Err("the candidate has no parent directory".into()),
        };
        if !dir.is_dir() {
            return Err(format!("no such directory: {}", dir.display()));
        }
        match OpenOptions::new().append(true).create(true).open(path) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// ⛔ **The chain, in `docs/spec/08-tokens.md`'s order, and every step is
/// traceable to a row of its table.**
pub fn candidates(env: &dyn Environment) -> Vec<(PathBuf, Outcome)> {
    let mut out = Vec::new();
    if let Some(p) = env.var("PODSSH_TOKEN_FILE") {
        out.push((PathBuf::from(p), Outcome::Override));
        return out;
    }
    // ⛔ Every candidate carries a placeholder reason, and ⛔ **the placeholder
    // is never read**: [`probe`] overwrites it with what the filesystem said.
    // A variable that is unset does not form a candidate at all, so the list is
    // ⛔ shorter than the chain and the missing steps are visibly missing rather
    // than being paths that were tried and failed.
    macro_rules! step {
        ($var:expr, $path:expr) => {
            if let Some(v) = env.var($var) {
                out.push(($path(v), Outcome::Unset));
            }
        };
    }
    step!("XDG_CONFIG_HOME", |v: String| {
        Path::new(&v).join("podssh").join("token")
    });
    // ⛔ `$HOME` is frequently unset on the constrained host, so this is a
    // fallback rather than the default — the operator's own wording.
    step!("HOME", |v: String| {
        Path::new(&v).join(".config").join("podssh").join("token")
    });
    // ⛔ `$TEMP` is the operator's first choice when HOME and XDG fail.
    step!("TEMP", |v: String| Path::new(&v).join("podssh").join("token"));
    step!("TMPDIR", |v: String| Path::new(&v).join("podssh").join("token"));
    // ⛔ `/tmp` is checked as its own candidate, not merged with `$TMPDIR`:
    // ⛔ `TEMP` is the Windows spelling and `TMPDIR` the POSIX one, and
    // `docs/spec/08-tokens.md` says **both are checked because the constrained
    // host sets neither**.
    out.push((
        PathBuf::from("/tmp").join("podssh").join("token"),
        Outcome::Unset,
    ));
    // ⛔ tmpfs, so the token never touches a disk.
    out.push((
        PathBuf::from("/dev/shm").join("podssh").join("token"),
        Outcome::Unset,
    ));
    // ⛔ "the last resort, and only if that directory is writable" — the
    // directory podssh was run from, and ⛔ **not** resolved from `argv[0]`:
    // `E13`'s entry carries the sibling's own reason, and podssh is a
    // ProxyCommand, so `argv[0]` is frequently not a path at all.
    out.push((env.current_dir().join("podssh.token"), Outcome::Unset));
    out
}

/// ⛔ **Walk the chain and take the first that opens.**
pub fn probe(env: &dyn Environment) -> Probe {
    let mut tried = Vec::new();
    let mut chosen = None;
    for (path, kind) in candidates(env) {
        if path.as_os_str().is_empty() {
            continue;
        }
        // ⛔ An override is never second-guessed. If the operator named a file,
        // ⛔ asking whether it is writable and silently moving on would make the
        // override a suggestion, and the operator's row 1 says it "always
        // wins". ⛔ It is probed so the report says what is true, and chosen for
        // that reason alone.
        let outcome = if kind == Outcome::Override {
            match env.try_append(&path) {
                Ok(()) => Outcome::Override,
                Err(e) if !e.starts_with("no such directory") => Outcome::NotWritable,
                Err(_) => Outcome::NoDirectory,
            }
        } else {
            match env.try_append(&path) {
                Ok(()) => Outcome::Writable,
                Err(e) if e.starts_with("no such directory") => Outcome::NoDirectory,
                Err(_) => Outcome::NotWritable,
            }
        };
        if chosen.is_none()
            && matches!(outcome, Outcome::Override | Outcome::Writable)
        {
            chosen = Some(path.clone());
        }
        tried.push(Attempt { path, outcome });
    }
    Probe { tried, chosen }
}

/// ⛔ **Write the token, 0600, and ⛔ ignore the mode failure.**
///
/// ⛔ `docs/spec/08-tokens.md`, the operator's closing answer: *"Set the cached
/// token to `0600` and ignore the failure. A host where `chmod` works is worth
/// protecting; a host where it does not loses nothing. **And the write must not
/// fail because of it** — a token file that could not be written is a token
/// podssh cannot use, and that is strictly worse than a token file with loose
/// permissions on a filesystem that ignores modes anyway."*
pub fn write(path: &Path, token: &RelayToken) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(token.expose())?;
    file.write_all(b"\n")?;
    drop(file);
    // ⛔ After the write, never before: a `chmod` that failed would otherwise
    // have to abort the write, and the operator's answer is explicit ⛔ — *"the
    // write must not fail because of it"*.
    let _ = set_mode_0600(path);
    Ok(())
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) -> std::io::Result<()> {
    // ⛔ Windows has no mode bit, and ⛔ `docs/spec/08-tokens.md` already
    // records that the sibling's `chmod 600` **did not work on this
    // filesystem and the file stayed `-rw-r--r--`**. ⛔ Revocation, not the mode
    // bit, is what makes a token safe.
    Ok(())
}

/// ⛔ **Revoke by destroying the local copy.** ⛔ Not by asking the relay, and ⛔
/// never by reading the answer: `POST /v1/stop` was **MEASURED** returning
/// `{"stopped": false}` and **still destroying the credentials**
/// (`docs/research/verify/relay-spec-reverse.verify.md:411-415`).
pub fn revoke_local(path: &Path) -> Result<(), std::io::Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
