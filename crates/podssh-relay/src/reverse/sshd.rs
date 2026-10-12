//! The check of a roost (T-166): a node in front of a standard sshd. An SSH
//! server sends its version line first (RFC 4253, section 4.2), so a TARGET
//! whose first line is another, or that sends none in time, is not one. The
//! check peeks at the bytes and takes none of them: the session's SSH client
//! still reads the line itself.

use std::fmt;
use std::time::Duration;

use tokio::net::TcpStream;

/// How long sshd may take to send its version line.
pub const BANNER_LIMIT: Duration = Duration::from_secs(10);
/// The most of the first line that is looked at: RFC 4253 gives the version
/// line 255 bytes, its CR LF included.
const LINE_MAX: usize = 255;
/// How long a peek that saw part of a line waits before it looks again: the
/// bytes stay in the stream, so a peek at once would see the same.
const PEEK_AGAIN: Duration = Duration::from_millis(20);
/// The most of a line that a message shows.
const SHOWN: usize = 80;
/// The starts of a version line of SSH 2: `SSH-1.99-` is a server that also
/// speaks SSH 1, which RFC 4253 (section 5.1) lets an SSH 2 client use.
const VERSIONS: [&[u8]; 2] = [b"SSH-2.0-", b"SSH-1.99-"];

/// Why a TARGET is not a standard sshd. Each says what came back, after
/// "it".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotSshd {
    /// Its first line is not an SSH version line: another service.
    Other(String),
    /// No whole line within the limit, and what came, if anything.
    Silent { after: Duration, seen: String },
    /// It closed the connection before its first line.
    Closed,
    /// The connection failed before its first line.
    Failed(String),
}

impl NotSshd {
    /// Whether another service answered: no wait mends that, as TARGET is
    /// set up wrong.
    pub fn is_other(&self) -> bool {
        matches!(self, NotSshd::Other(_))
    }
}

impl fmt::Display for NotSshd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotSshd::Other(line) => write!(f, "sent {line:?} first, not a version line SSH-2.0-..."),
            NotSshd::Silent { after, seen } if seen.is_empty() => {
                write!(f, "sent no line within {} s", after.as_secs())
            }
            NotSshd::Silent { after, seen } => {
                write!(f, "sent {seen:?} and no whole line within {} s", after.as_secs())
            }
            NotSshd::Closed => write!(f, "closed the connection before its first line"),
            NotSshd::Failed(why) => write!(f, "failed before its first line: {why}"),
        }
    }
}

impl std::error::Error for NotSshd {}

/// The version line of the sshd at the other end of `stream`, within
/// `limit`. Each byte stays in the stream for the session.
pub async fn check(stream: &TcpStream, limit: Duration) -> Result<String, NotSshd> {
    let mut seen = String::new();
    let result = tokio::time::timeout(limit, first_line(stream, &mut seen)).await;
    match result {
        Ok(verdict) => verdict,
        Err(_) => Err(NotSshd::Silent { after: limit, seen }),
    }
}

async fn first_line(stream: &TcpStream, seen: &mut String) -> Result<String, NotSshd> {
    let mut buf = [0u8; LINE_MAX];
    // Another start than SSH's is looked at once more, so that the message
    // shows the whole line when it came in two parts.
    let mut again = true;
    loop {
        let n = stream.peek(&mut buf).await.map_err(|e| NotSshd::Failed(e.to_string()))?;
        if n == 0 {
            return Err(NotSshd::Closed);
        }
        let bytes = &buf[..n];
        *seen = shown(line_of(bytes));
        match judge(bytes) {
            Some(Err(NotSshd::Other(_))) if again && !bytes.contains(&b'\n') && n < LINE_MAX => again = false,
            Some(verdict) => return verdict,
            None => {}
        }
        tokio::time::sleep(PEEK_AGAIN).await;
    }
}

/// The verdict on the first bytes of a TARGET, once they decide it: a whole
/// first line, or a start that no version line has. `None`: wait for more.
pub fn judge(bytes: &[u8]) -> Option<Result<String, NotSshd>> {
    let whole = bytes.contains(&b'\n');
    let line = line_of(bytes);
    let version = VERSIONS.iter().any(|v| line.starts_with(v));
    let may_be = VERSIONS.iter().any(|v| v.starts_with(line) || line.starts_with(v));
    match (whole, version) {
        (true, true) => Some(Ok(shown(line))),
        (true, false) => Some(Err(NotSshd::Other(shown(line)))),
        (false, _) if !may_be => Some(Err(NotSshd::Other(shown(line)))),
        (false, _) => None,
    }
}

/// The first line of `bytes`, with no line end.
fn line_of(bytes: &[u8]) -> &[u8] {
    let line = bytes.split(|b| *b == b'\n').next().unwrap_or(bytes);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// A line from a peer, safe to print, and short.
fn shown(line: &[u8]) -> String {
    podssh_ws::text::one_line(&String::from_utf8_lossy(line)).chars().take(SHOWN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_line_of_ssh_2_passes() {
        assert_eq!(judge(b"SSH-2.0-OpenSSH_9.6\r\n"), Some(Ok("SSH-2.0-OpenSSH_9.6".into())));
        assert_eq!(judge(b"SSH-2.0-dropbear_2024.86\n"), Some(Ok("SSH-2.0-dropbear_2024.86".into())));
        assert_eq!(judge(b"SSH-1.99-Cisco-1.25\r\nmore"), Some(Ok("SSH-1.99-Cisco-1.25".into())));
    }

    #[test]
    fn another_first_line_is_named() {
        let http = judge(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(http, Some(Err(NotSshd::Other("HTTP/1.1 400 Bad Request".into()))));
        assert_eq!(judge(b"SSH-1.5-old\r\n"), Some(Err(NotSshd::Other("SSH-1.5-old".into()))));
        assert_eq!(judge(b"SSH-2.0\r\n"), Some(Err(NotSshd::Other("SSH-2.0".into()))));
        // A start that no version line has decides at once.
        assert_eq!(judge(b"\x1b[2J"), Some(Err(NotSshd::Other("[2J".into()))));
    }

    #[test]
    fn part_of_a_version_line_waits_for_more() {
        for part in [&b"S"[..], b"SSH-", b"SSH-2.0", b"SSH-2.0-OpenSSH", b"SSH-1.9"] {
            assert_eq!(judge(part), None, "{part:?}");
        }
    }
}
