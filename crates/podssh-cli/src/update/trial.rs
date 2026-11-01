//! The new binary, run once before it takes the old one's place (T-396): a
//! file that does not start on this host (a libc, a CPU feature, a defect)
//! would end an installed node at its next start, and the server that only
//! the node reaches would be locked out. The file runs with `--version`
//! alone, its stdin empty, within [`LIMIT`]; its exit code is read directly,
//! and its first line must be `podssh VERSION`, of the release asked for.
//! Its signature and its sum were checked first, so running it trusts
//! nothing new.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::release::Version;

/// The bound on a run of `--version`.
pub const LIMIT: Duration = Duration::from_secs(10);

/// How a new binary is tried for a release: [`by_version`]. A test on a
/// system with no small program of its own to run gives another.
pub type Check = fn(&Path, &Version) -> Result<String, String>;

/// [`check`] for the release `want`, within [`LIMIT`]: what an update runs.
pub fn by_version(file: &Path, want: &Version) -> Result<String, String> {
    check(file, Some(want), LIMIT)
}

/// Run `file --version` within `limit`: its line, `podssh VERSION`, when it
/// ended with 0 and named `want` (any version, with none); else why not.
pub fn check(file: &Path, want: Option<&Version>, limit: Duration) -> Result<String, String> {
    let mut child = spawn(file)?;
    // Read as it writes, so that a long answer cannot hold it.
    let reader = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = reader(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let stderr = reader(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("it did not end within {} s", limit.as_secs()));
            }
            Err(e) => return Err(format!("its wait: {e}")),
        }
    };
    let out = String::from_utf8_lossy(&stdout.join().unwrap_or_default()).into_owned();
    if !status.success() {
        let said = String::from_utf8_lossy(&stderr.join().unwrap_or_default()).into_owned();
        let said = said.lines().map(str::trim).find(|l| !l.is_empty()).map(podssh_ws::text::one_line);
        return Err(match said {
            Some(said) => format!("it ended with {status}: {said}"),
            None => format!("it ended with {status}"),
        });
    }
    let line = out.lines().next().unwrap_or("").trim().to_string();
    // `podssh VERSION`, and ` (COMMIT)` after it in a release build.
    let named = line.strip_prefix("podssh ").and_then(|rest| rest.split_whitespace().next()).and_then(Version::parse);
    match (named, want) {
        (None, _) => Err(format!("it said {:?}, not podssh VERSION", podssh_ws::text::one_line(&line))),
        (Some(named), Some(want)) if &named != want => Err(format!("it is podssh {named}, not {want}")),
        (Some(_), _) => Ok(line),
    }
}

/// `file --version`, started again for a while when another thread of this
/// process holds the new file open between its fork and its exec (ETXTBSY).
fn spawn(file: &Path) -> Result<Child, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut cmd = Command::new(file);
        cmd.arg("--version").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        match cmd.spawn() {
            Ok(child) => return Ok(child),
            Err(e) if busy(&e) && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("it does not start here: {e}")),
        }
    }
}

#[cfg(unix)]
fn busy(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ETXTBSY)
}

#[cfg(not(unix))]
fn busy(_: &std::io::Error) -> bool {
    false
}
