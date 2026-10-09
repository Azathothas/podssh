//! The copy by exec, when the server has no SFTP (T-135).
//!
//! **Each step is one command on a channel with no pty**: `sh -c 'SCRIPT' sh
//! PATH...`, so the login shell, POSIX or not, only starts `sh`, and each
//! path is one quoted word. A step that moves no file data waits
//! [`STEP_WAIT`] at most; a data step waits the SFTP road's data limit for
//! each piece; `--timeout` bounds the whole copy.
//!
//! **A marker comes before each answer**, so text that a login prints first (a
//! start-up file, a `ForceCommand` banner) is dropped, never taken as data.
//!
//! **Bytes go raw through `cat`** when a check finds that each of the 256 byte
//! values comes back unchanged; else through `base64`, which adds a third to
//! the bytes that count against the relay, or not at all.
//!
//! **The rest is the SFTP road's**: a temporary name beside the destination,
//! the digests compared (a digest command, else a second read), then `mv -f`
//! onto the destination, which `rename(2)` makes atomic on one file system.
//! A failure removes the temporary file. A copy down keeps mode 0600: no
//! portable command reads the far file's mode.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::Engine;
use podssh_ssh::exec::{self, ExecError};
use podssh_ssh::sftp::DATA_WAIT;
use podssh_ssh::{Connection, Log};
use sha2::{Digest, Sha256};

use super::digest::{self, Sum};
use super::transfer::{Cause, Failed};
use crate::exitmap::Fault;

mod files;

/// The limit of a step that moves no file data: the probe, a size, a rename.
pub const STEP_WAIT: Duration = Duration::from_secs(15);

/// The tools that the probe looks for.
pub const TOOLS: &[&str] = &["cat", "wc", "tail", "mv", "rm", "chmod", "base64", "sha256sum", "shasum", "openssl"];

/// The tools that a copy by exec cannot do without.
const NEEDED: &[&str] = &["cat", "wc", "mv", "rm"];

/// The most that a login may print before the marker.
const BEFORE_MARKER: usize = 64 * 1024;

/// Between two reads of the size of a far file that a broken connection's
/// writer may still be adding to, and the longest wait for it to stand still.
const SETTLE_STEP: Duration = Duration::from_secs(2);
const SETTLE_MAX: Duration = Duration::from_secs(30);

fn failed(fault: Fault, message: String) -> Failed {
    Failed::new(fault, message)
}

/// The failure of a step: a refused command means no exec at all; else the
/// connection broke, and a new one can go on (T-136).
fn step_failed(what: &str, e: ExecError) -> Failed {
    let (fault, cause) = match e {
        ExecError::Refused(_) => (Fault::RelayUnreachable, Cause::Answer),
        ExecError::Timeout(_) | ExecError::Lost(_) => (Fault::SessionFault, Cause::Broke),
    };
    Failed { fault, message: format!("{what}: {e}"), cause }
}

/// The command for the login shell: `sh -c 'SCRIPT' sh` and each argument
/// as one quoted word. A path with a newline or a NUL has no such word.
pub fn command(script: &str, args: &[&str]) -> Result<String, String> {
    debug_assert!(!script.contains('\''), "a script goes inside single quotes");
    let mut out = format!("sh -c '{script}' sh");
    for arg in args {
        let word = exec::shell_word(arg)
            .ok_or_else(|| format!("{arg:?} holds a newline or a NUL, which no word of a far shell can carry"))?;
        out.push(' ');
        out.push_str(&word);
    }
    Ok(out)
}

/// The probe's script: the marker, then the name of each tool found.
pub fn probe_script(marker: &str) -> String {
    format!(
        "printf \"%s\\n\" {marker}; for t in {}; do command -v \"$t\" >/dev/null 2>&1 && printf \"%s\\n\" \"$t\"; done; exit 0",
        TOOLS.join(" ")
    )
}

/// Where the bytes after the marker's line begin, if the marker came.
pub fn after_marker(bytes: &[u8], marker: &str) -> Option<usize> {
    let line = format!("{marker}\n");
    bytes.windows(line.len()).position(|w| w == line.as_bytes()).map(|at| at + line.len())
}

/// The tools named after the marker; `None` when no marker came, so no POSIX
/// `sh` ran the script.
pub fn parse_probe(stdout: &[u8], marker: &str) -> Option<BTreeSet<String>> {
    let at = after_marker(stdout, marker)?;
    let text = String::from_utf8_lossy(&stdout[at..]);
    Some(text.lines().map(str::trim).filter(|t| TOOLS.contains(t)).map(str::to_string).collect())
}

/// Drops what comes before the marker's line of a stream, and passes the rest
/// on.
pub struct Strip {
    line: Vec<u8>,
    held: Vec<u8>,
    open: bool,
}

impl Strip {
    pub fn new(marker: &str) -> Strip {
        Strip { line: format!("{marker}\n").into_bytes(), held: Vec::new(), open: false }
    }

    /// The bytes of `chunk` that come after the marker; an error when more
    /// than a login's text came without it.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<u8>, String> {
        if self.open {
            return Ok(chunk.to_vec());
        }
        self.held.extend_from_slice(chunk);
        if let Some(at) = self.held.windows(self.line.len()).position(|w| w == self.line.as_slice()) {
            self.open = true;
            return Ok(self.held.split_off(at + self.line.len()));
        }
        if self.held.len() > BEFORE_MARKER {
            return Err(format!("{} bytes came and no marker", self.held.len()));
        }
        Ok(Vec::new())
    }

    /// Whether the marker came.
    pub fn opened(&self) -> bool {
        self.open
    }
}

/// Base64 text decoded in pieces; whitespace between its groups is skipped.
#[derive(Default)]
struct Unbase64 {
    pending: Vec<u8>,
}

impl Unbase64 {
    fn feed(&mut self, text: &[u8]) -> Result<Vec<u8>, String> {
        self.pending.extend(text.iter().copied().filter(|b| !b.is_ascii_whitespace()));
        let whole = self.pending.len() / 4 * 4;
        let out =
            base64::engine::general_purpose::STANDARD.decode(&self.pending[..whole]).map_err(|e| e.to_string())?;
        self.pending.drain(..whole);
        Ok(out)
    }

    fn finish(&self) -> Result<(), String> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err("the base64 text ended inside a group".into())
        }
    }
}

/// What a path is on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Dir,
    File(u64),
    /// A regular file that the login cannot read: it has no size to give.
    Unreadable,
    Other,
    Missing,
}

/// The far side of a copy by exec.
#[derive(Debug, Clone)]
pub struct Far {
    marker: String,
    /// The tools that the probe found.
    pub tools: BTreeSet<String>,
    /// Whether `cat` carries each byte value unchanged.
    pub raw: bool,
}

impl Far {
    /// The tools of the far side, then whether `cat` carries each byte value.
    pub async fn probe(handle: &Connection, log: &Log) -> Result<Far, Failed> {
        let marker = format!("podssh-{:016x}", rand::random::<u64>());
        let cmd = command(&probe_script(&marker), &[]).map_err(|why| failed(Fault::Usage, why))?;
        let got = exec::capture(handle, &cmd, STEP_WAIT, 64 * 1024).await.map_err(|e| step_failed("the probe", e))?;
        let Some(tools) = parse_probe(&got.stdout, &marker) else {
            return Err(failed(
                Fault::RelayUnreachable,
                "the server has no SFTP, and no POSIX sh answered a copy by exec".into(),
            ));
        };
        let missing: Vec<&str> = NEEDED.iter().copied().filter(|t| !tools.contains(*t)).collect();
        if !missing.is_empty() {
            return Err(failed(
                Fault::RelayUnreachable,
                format!("the server has no SFTP, and no {} for a copy by exec", missing.join(", ")),
            ));
        }
        let mut far = Far { marker, tools, raw: true };
        far.raw = far.clean(handle).await?;
        if !far.raw && !far.tools.contains("base64") {
            return Err(failed(
                Fault::RelayUnreachable,
                "the server's channel changes bytes, and the server has no base64 to carry them".into(),
            ));
        }
        let tools: Vec<&str> = far.tools.iter().map(String::as_str).collect();
        log.verbose(&format!(
            "copy by exec: the far side has {}; the bytes go {}",
            tools.join(" "),
            if far.raw { "raw through cat" } else { "through base64" }
        ));
        Ok(far)
    }

    /// The script `script` with this side's marker first.
    fn marked(&self, script: &str) -> String {
        format!("printf \"%s\\n\" {}; {script}", self.marker)
    }

    /// Whether each of the 256 byte values comes back through `cat`.
    async fn clean(&self, handle: &Connection) -> Result<bool, Failed> {
        let all: Vec<u8> = (0..=255u8).collect();
        let cmd = command(&self.marked("exec cat"), &[]).map_err(|why| failed(Fault::Usage, why))?;
        let mut strip = Strip::new(&self.marker);
        let mut back = Vec::new();
        let mut given = false;
        let mut fill = |piece: &mut Vec<u8>| {
            if !given {
                piece.extend_from_slice(&all);
                given = true;
            }
            Ok(())
        };
        let mut sink = |data: &[u8]| {
            back.extend(strip.feed(data).map_err(std::io::Error::other)?);
            Ok(())
        };
        let got = exec::send(handle, &cmd, STEP_WAIT, 4096, &mut fill, &mut sink)
            .await
            .map_err(|e| step_failed("the check of the bytes", e))?;
        Ok(got.status == Some(0) && back == all)
    }

    /// What `path` is, and a file's size.
    pub(super) async fn kind(&self, handle: &Connection, path: &str) -> Result<Kind, Failed> {
        let script = self.marked(
            "if [ -d \"$1\" ]; then echo dir; elif [ -f \"$1\" ] && [ ! -r \"$1\" ]; then echo unreadable; \
             elif [ -f \"$1\" ]; then wc -c < \"$1\"; elif [ -e \"$1\" ]; then echo other; else echo missing; fi",
        );
        let cmd = command(&script, &[path]).map_err(|why| failed(Fault::Usage, why))?;
        let got = exec::capture(handle, &cmd, STEP_WAIT, 64 * 1024).await.map_err(|e| step_failed(path, e))?;
        let answer = after_marker(&got.stdout, &self.marker)
            .map(|at| String::from_utf8_lossy(&got.stdout[at..]).trim().to_string())
            .unwrap_or_default();
        Ok(match answer.as_str() {
            "dir" => Kind::Dir,
            "unreadable" => Kind::Unreadable,
            "other" => Kind::Other,
            "missing" => Kind::Missing,
            size => match size.parse() {
                Ok(n) => Kind::File(n),
                Err(_) => return Err(failed(Fault::SessionFault, format!("{path}: the far side gave no size"))),
            },
        })
    }

    /// Where a file named `name` goes on the server, as the SFTP road says.
    pub(super) async fn target(
        &self,
        handle: &Connection,
        dest: &str,
        name: &str,
        many: bool,
    ) -> Result<String, Failed> {
        if dest.is_empty() {
            return Ok(name.to_string());
        }
        if dest.ends_with('/') {
            return Ok(format!("{dest}{name}"));
        }
        match self.kind(handle, dest).await? {
            Kind::Dir => Ok(format!("{dest}/{name}")),
            _ if many => {
                Err(failed(Fault::CantCreate, format!("{dest} is not a directory, and there are several sources")))
            }
            Kind::Other => Err(failed(Fault::CantCreate, format!("{dest}: not a regular file"))),
            Kind::File(_) | Kind::Unreadable | Kind::Missing => Ok(dest.to_string()),
        }
    }

    /// The far digest of `path`: by a command, else by reading it again.
    async fn digest(&self, handle: &Connection, path: &str, size: u64) -> Result<(Sum, String), Failed> {
        let named = if path.starts_with('/') { path.to_string() } else { format!("./{path}") };
        if let Some(found) = digest::by_command(handle, &named, size).await {
            return Ok(found);
        }
        let mut hasher = Sha256::new();
        self.read(handle, path, 0, &mut |bytes| {
            hasher.update(bytes);
            Ok(())
        })
        .await?;
        Ok((hasher.finalize().into(), digest::READ_AGAIN.to_string()))
    }

    /// The bytes of `path` from `offset` on, after the marker, given to
    /// `sink`; their count. Past the first byte, `tail` reads them.
    async fn read(
        &self,
        handle: &Connection,
        path: &str,
        offset: u64,
        sink: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
    ) -> Result<u64, Failed> {
        let from = (offset + 1).to_string();
        let (script, args) = match (offset, self.raw) {
            (0, true) => ("exec cat -- \"$1\"", vec![path]),
            (0, false) => ("exec base64 < \"$1\"", vec![path]),
            (_, true) => ("exec tail -c \"+$2\" -- \"$1\"", vec![path, from.as_str()]),
            (_, false) => ("tail -c \"+$2\" -- \"$1\" | base64", vec![path, from.as_str()]),
        };
        let cmd = command(&self.marked(script), &args).map_err(|why| failed(Fault::Usage, why))?;
        let raw = self.raw;
        let mut strip = Strip::new(&self.marker);
        let mut text = Unbase64::default();
        let mut count = 0u64;
        let mut each = |data: &[u8]| {
            let after = strip.feed(data).map_err(std::io::Error::other)?;
            let bytes = if raw { after } else { text.feed(&after).map_err(std::io::Error::other)? };
            count += bytes.len() as u64;
            sink(&bytes)
        };
        let got = exec::receive(handle, &cmd, DATA_WAIT, 4096, &mut each).await.map_err(|e| step_failed(path, e))?;
        if !strip.opened() {
            return Err(failed(Fault::SessionFault, format!("{path}: the far shell printed no marker")));
        }
        text.finish().map_err(|why| failed(Fault::SessionFault, format!("{path}: {why}")))?;
        if got.status != Some(0) {
            let why = String::from_utf8_lossy(&got.stderr);
            return Err(failed(Fault::NoInput, format!("{path}: the far side could not read it: {}", why.trim())));
        }
        Ok(count)
    }

    /// Give `temp` the mode `mode` when the server has `chmod`, then rename
    /// it onto `target`. A directory of that name is refused: `mv` would put
    /// the file inside it, where the SFTP road's rename fails.
    pub(super) async fn rename(
        &self,
        handle: &Connection,
        temp: &str,
        target: &str,
        mode: Option<u32>,
    ) -> Result<(), Failed> {
        let octal = mode.map(|m| format!("{m:o}"));
        // `--` before the mode: a strict POSIX chmod takes a later `--` as a
        // file.
        let (script, args): (&str, Vec<&str>) = match &octal {
            Some(m) if self.tools.contains("chmod") => (
                "if [ -d \"$3\" ]; then echo \"a directory has that name\" >&2; exit 1; fi; \
                 chmod -- \"$1\" \"$2\" && exec mv -f -- \"$2\" \"$3\"",
                vec![m.as_str(), temp, target],
            ),
            _ => (
                "if [ -d \"$2\" ]; then echo \"a directory has that name\" >&2; exit 1; fi; \
                 exec mv -f -- \"$1\" \"$2\"",
                vec![temp, target],
            ),
        };
        let cmd = command(script, &args).map_err(|why| failed(Fault::Usage, why))?;
        let got = exec::capture(handle, &cmd, STEP_WAIT, 4096).await.map_err(|e| step_failed(target, e))?;
        if got.status != Some(0) {
            let why = String::from_utf8_lossy(&got.stderr);
            return Err(failed(Fault::CantCreate, format!("{target}: the rename failed: {}", why.trim())));
        }
        Ok(())
    }

    /// The size of the far file `path` once it stands still: a writer that a
    /// broken connection left may still add to it. Two reads [`SETTLE_STEP`]
    /// apart agree, [`SETTLE_MAX`] at most; `None` when the file is gone or
    /// never stands still.
    pub(super) async fn settled(&self, handle: &Connection, path: &str) -> Result<Option<u64>, Failed> {
        let started = std::time::Instant::now();
        let mut last = None;
        loop {
            let size = match self.kind(handle, path).await? {
                Kind::File(n) => n,
                _ => return Ok(None),
            };
            if last == Some(size) {
                return Ok(Some(size));
            }
            if started.elapsed() >= SETTLE_MAX {
                return Ok(None);
            }
            last = Some(size);
            tokio::time::sleep(SETTLE_STEP).await;
        }
    }

    /// Remove `path`, as well as the server lets it.
    pub(super) async fn remove(&self, handle: &Connection, path: &str) {
        if let Ok(cmd) = command("exec rm -f -- \"$1\"", &[path]) {
            let _ = exec::capture(handle, &cmd, STEP_WAIT, 4096).await;
        }
    }

    /// What `ls -lnid` says of `path`: its inode, mode, links, owner, size
    /// and time of change, to tell later whether it is still the same file.
    pub(super) async fn listing(&self, handle: &Connection, path: &str) -> Result<String, Failed> {
        let cmd = command(&self.marked("exec ls -lnid -- \"$1\""), &[path]).map_err(|why| failed(Fault::Usage, why))?;
        let got = exec::capture(handle, &cmd, STEP_WAIT, 64 * 1024).await.map_err(|e| step_failed(path, e))?;
        let line = after_marker(&got.stdout, &self.marker)
            .map(|at| String::from_utf8_lossy(&got.stdout[at..]).trim().to_string())
            .unwrap_or_default();
        if got.status != Some(0) || line.is_empty() {
            let why = String::from_utf8_lossy(&got.stderr);
            return Err(failed(Fault::NoInput, format!("{path}: {}", why.trim())));
        }
        Ok(line)
    }

    /// Whether `a` and `b` name one file (`test -ef`). A `test` with no
    /// `-ef` says no, and `mv` then judges the rename.
    pub(super) async fn same_file(&self, handle: &Connection, a: &str, b: &str) -> Result<bool, Failed> {
        let script = self.marked("if [ \"$1\" -ef \"$2\" ]; then echo same; else echo other; fi");
        let cmd = command(&script, &[a, b]).map_err(|why| failed(Fault::Usage, why))?;
        let got = exec::capture(handle, &cmd, STEP_WAIT, 4096).await.map_err(|e| step_failed(a, e))?;
        let at = after_marker(&got.stdout, &self.marker);
        Ok(at.is_some_and(|at| String::from_utf8_lossy(&got.stdout[at..]).trim() == "same"))
    }

    /// Remove `path`, and say why when the server does not.
    pub(super) async fn delete(&self, handle: &Connection, path: &str) -> Result<(), String> {
        let cmd = command("exec rm -- \"$1\"", &[path])?;
        let got = exec::capture(handle, &cmd, STEP_WAIT, 4096).await.map_err(|e| e.to_string())?;
        if got.status == Some(0) {
            return Ok(());
        }
        let why = String::from_utf8_lossy(&got.stderr).trim().to_string();
        Err(if why.is_empty() { format!("rm ended with {:?}", got.status) } else { why })
    }
}
