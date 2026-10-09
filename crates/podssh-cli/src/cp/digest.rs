//! The digests of a copy: the SHA-256 of what was sent, and of what the far
//! side holds.
//!
//! The far digest comes from a digest command over exec when the server has
//! one (`sha256sum`, `shasum -a 256`, `openssl dgst -sha256`), so the bytes
//! are not read twice; else from a second read of the file over SFTP, which
//! counts again against the relay's 64 MiB (T-137). The size and the MAC of
//! SSH alone miss a wrong offset, a short write, and a source that changed
//! while it was read.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use podssh_ssh::sftp::{FileAttributes, OpenFlags, Sftp, SftpError};
use podssh_ssh::Connection;
use sha2::{Digest, Sha256};

/// A SHA-256.
pub type Sum = [u8; 32];

/// How the far digest was taken, when no command did it.
pub const READ_AGAIN: &str = "read again";

/// For a POSIX shell: the name of the first digest tool that the server has,
/// on a line, then the digest of `$1` by it.
const SCRIPT: &str = "if command -v sha256sum >/dev/null 2>&1; then echo sha256sum; exec sha256sum \"$1\"; \
elif command -v shasum >/dev/null 2>&1; then echo shasum; exec shasum -a 256 \"$1\"; \
elif command -v openssl >/dev/null 2>&1; then echo openssl; exec openssl dgst -sha256 -r \"$1\"; fi; exit 127";

/// A digest in lower-case hex.
pub fn hex(sum: &Sum) -> String {
    sum.iter().map(|b| format!("{b:02x}")).collect()
}

/// A digest from 64 hex digits.
fn from_hex(text: &str) -> Option<Sum> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut sum = [0u8; 32];
    for (i, byte) in sum.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(sum)
}

/// The tool's name and the digest, from what [`SCRIPT`] printed: the line
/// that names a tool, and the digest on the line after it. Text that a login
/// prints first (a `ForceCommand` banner) comes before them.
fn read_answer(stdout: &[u8]) -> Option<(Sum, String)> {
    let text = String::from_utf8_lossy(stdout);
    let lines: Vec<&str> = text.lines().collect();
    lines.windows(2).rev().find_map(|pair| {
        let tool = pair[0].trim();
        // `sha256sum` and `shasum` print "HEX  NAME", `openssl -r` "HEX *NAME".
        let sum = from_hex(pair[1].split_whitespace().next()?)?;
        matches!(tool, "sha256sum" | "shasum" | "openssl").then(|| (sum, tool.to_string()))
    })
}

/// The digest of `path` by a command on the server, when the server runs
/// commands, has a tool, and the path has a spelling for its shell. `None`
/// when it cannot, for a second read instead. The path is absolute, or `./`
/// and a relative one, so that no name reads as an option of the tool.
pub async fn by_command(handle: &Connection, path: &str, size: u64) -> Option<(Sum, String)> {
    let word = podssh_ssh::exec::shell_word(path)?;
    let command = format!("sh -c '{SCRIPT}' sh {word}");
    // A digest reads the file once: 30 s, and 1 s more for each 32 MiB.
    let limit = Duration::from_secs(30 + size / (32 << 20));
    let got = podssh_ssh::exec::capture(handle, &command, limit, 4096).await.ok()?;
    if got.status != Some(0) {
        return None;
    }
    read_answer(&got.stdout)
}

/// The digest of `path` on the server, by reading it again over SFTP.
pub async fn by_reading(sftp: &Sftp, path: &str) -> Result<Sum, SftpError> {
    let file = sftp.open_file(path, OpenFlags::READ, FileAttributes::default()).await?;
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    let read = loop {
        match sftp.read(&file, offset, sftp.read_len()).await {
            Ok(Some(data)) if !data.is_empty() => {
                hasher.update(&data);
                offset += data.len() as u64;
            }
            // An empty reply would loop for ever: it ends the read, and a
            // short digest then fails the comparison.
            Ok(_) => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    let _ = sftp.close(&file).await;
    read?;
    Ok(hasher.finalize().into())
}

/// The digest of a local file, as it is on the disk now.
pub fn of_file(path: &Path) -> std::io::Result<Sum> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buf[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn each_tool_s_answer_is_read() {
        let want = from_hex(EMPTY).expect("hex");
        for (out, tool) in [
            (format!("sha256sum\n{EMPTY}  /srv/a b\n"), "sha256sum"),
            (format!("shasum\n{EMPTY}  /srv/a\n"), "shasum"),
            (format!("openssl\n{EMPTY} */srv/a\n"), "openssl"),
        ] {
            assert_eq!(read_answer(out.as_bytes()), Some((want, tool.to_string())), "{out}");
        }
        assert_eq!(hex(&want), EMPTY);
    }

    #[test]
    fn a_banner_before_the_answer_is_skipped() {
        let want = from_hex(EMPTY).expect("hex");
        let out = format!("Welcome to the box\nsha256sum\n{EMPTY}  ./a\n");
        assert_eq!(read_answer(out.as_bytes()), Some((want, "sha256sum".to_string())));
    }

    #[test]
    fn an_answer_that_is_not_a_digest_is_none() {
        assert_eq!(read_answer(b""), None);
        assert_eq!(read_answer(b"sha256sum\nnot-hex  /a\n"), None);
        assert_eq!(read_answer(format!("md5sum\n{EMPTY}  /a\n").as_bytes()), None);
        assert_eq!(read_answer(format!("sha256sum\n{}  /a\n", &EMPTY[..62]).as_bytes()), None);
    }

    #[test]
    fn the_script_has_no_single_quote() {
        // It goes inside single quotes for the login shell.
        assert!(!SCRIPT.contains('\''));
    }
}
