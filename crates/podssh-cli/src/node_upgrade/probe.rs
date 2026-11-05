//! The probe of the binary that would take a node's place (T-668), before
//! anything of the node stops: it runs once, as `podssh --version` with the
//! variable of the handover set to `probe`, its stdin empty, within
//! [`LIMIT`]. A binary that takes a node's sessions says so in a line of
//! its own after its version; one that does not (a build of before, another
//! program, a file that does not start here) leaves the node as it is, with
//! why. This binary started again at the user's request is no helper (Q61).

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The bound on the probe.
pub const LIMIT: Duration = Duration::from_secs(10);

/// The line of the binary at `path`, `podssh VERSION`, once it said that it
/// takes a node's sessions of this build's version of the handover.
pub fn probe(path: &Path) -> Result<String, String> {
    let mut child = spawn(path)?;
    let stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(out) = stdout {
            let _ = out.take(64 * 1024).read_to_end(&mut bytes);
        }
        bytes
    });
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("it did not end within {} s", LIMIT.as_secs()));
            }
            Err(e) => return Err(format!("its wait: {e}")),
        }
    };
    let said = String::from_utf8_lossy(&reader.join().unwrap_or_default()).into_owned();
    if !status.success() {
        return Err(format!("it ended with {status}"));
    }
    takes(&said)
}

/// What a probe said: its first line, `podssh VERSION`, and the handover's
/// line of this build's version among the next.
pub fn takes(said: &str) -> Result<String, String> {
    let mut lines = said.lines().map(str::trim);
    let first = lines.next().unwrap_or_default().to_string();
    if !first.starts_with("podssh ") {
        return Err(format!("it said {:?}, not podssh VERSION", podssh_ws::text::one_line(&first)));
    }
    let named: Vec<&str> = lines.filter_map(|line| line.strip_prefix(super::PROBE_WORD)).collect();
    match named.as_slice() {
        [] => Err(format!("{first} takes no node's sessions: a build of before this one's upgrade in place")),
        versions if versions.iter().any(|v| v.trim() == super::HANDOVER_VERSION) => Ok(first),
        versions => Err(format!(
            "{first} reads the handover of version {}, and this binary writes {}",
            versions.join(", ").trim(),
            super::HANDOVER_VERSION
        )),
    }
}

/// The binary, started again for a moment while a write of its file ends
/// (ETXTBSY), as `podssh update` renames the file once written.
fn spawn(path: &Path) -> Result<std::process::Child, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut cmd = Command::new(path);
        cmd.arg("--version").env(super::VARIABLE, super::PROBE);
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binary_that_takes_the_sessions_says_so_after_its_version() {
        let line = format!("podssh 1.1.0 (abc1234)\n{}{}\n", super::super::PROBE_WORD, super::super::HANDOVER_VERSION);
        assert_eq!(takes(&line).unwrap(), "podssh 1.1.0 (abc1234)");
        let before = takes("podssh 1.0.1\n").unwrap_err();
        assert!(before.contains("takes no node's sessions"), "{before}");
        let other = takes(&format!("podssh 9.0.0\n{}99\n", super::super::PROBE_WORD)).unwrap_err();
        assert!(other.contains("version 99"), "{other}");
        assert!(takes("bash: podssh: not found\n").unwrap_err().contains("not podssh VERSION"));
    }
}
