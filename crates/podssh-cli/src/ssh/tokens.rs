//! The `%` tokens of ssh_config(5) in file names (`IdentityFile`,
//! `UserKnownHostsFile`, `GlobalKnownHostsFile`, `IdentityAgent`), with the
//! values that OpenSSH 10.3p1 gives them (`DEFAULT_CLIENT_PERCENT_EXPAND_ARGS`
//! in its `sshconnect.h`). An unknown token is refused, as OpenSSH refuses
//! it: a path that silently means another file is worse than an error.

use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};

/// The tokens, for the refusal of an unknown one.
pub const TOKENS: &str = "%%, %C, %d, %h, %i, %j, %k, %L, %l, %n, %p, %r and %u";

/// The values of the tokens for one connection.
#[derive(Debug, Clone, Default)]
pub struct Tokens {
    /// `%d`: the local home directory.
    pub home: Option<PathBuf>,
    /// `%h`: the host to connect to, after `HostName`.
    pub host: String,
    /// `%n`: the host as the command line gave it.
    pub original: String,
    /// `%p`
    pub port: u16,
    /// `%r`: the remote user.
    pub remote_user: String,
    /// `%u`: the local user (`USER`, `LOGNAME` or `USERNAME`).
    pub local_user: Option<String>,
    /// `%l`: the local host name; `%L` is its first label.
    pub local_host: Option<String>,
    /// `%i`: the local user id.
    pub uid: Option<u32>,
    /// `%k`: `HostKeyAlias`, else `%n`.
    pub alias: String,
    /// `%j`: the host of the last `ProxyJump` hop, else empty.
    pub jump: String,
}

/// OpenSSH lowercases a host name for `%h` and `%k`, but not an address.
pub fn lower_host(host: &str) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() || host.contains(':') {
        host.to_string()
    } else {
        host.to_ascii_lowercase()
    }
}

impl Tokens {
    /// `%C`: SHA-1 of `%l%h%p%r%j`, in lowercase hexadecimal.
    pub fn hash(&self) -> Option<String> {
        let mut sha = Sha1::new();
        for part in [self.local_host.as_deref()?, &self.host, &self.port.to_string(), &self.remote_user, &self.jump] {
            sha.update(part.as_bytes());
        }
        Some(sha.finalize().iter().map(|b| format!("{b:02x}")).collect())
    }

    /// `path` with each token replaced, then a leading `~` made the home
    /// directory. `setting` names the option in a refusal, as `-i ` or
    /// `-o IdentityFile=`.
    pub fn expand(&self, setting: &str, path: &str) -> Result<PathBuf, String> {
        let refuse = |why: String| format!("{setting}{path}: {why}");
        let missing = |token: &str, what: &str| refuse(format!("{token} needs {what}"));
        let mut out = String::new();
        let mut chars = path.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            let Some(token) = chars.next() else {
                return Err(refuse("a % at the end; write %% for a %".into()));
            };
            match token {
                '%' => out.push('%'),
                'C' => {
                    out.push_str(&self.hash().ok_or_else(|| missing("%C", "the local host name, which is unknown"))?)
                }
                'd' => {
                    let home =
                        self.home.as_deref().ok_or_else(|| missing("%d", "the home directory, and HOME is not set"))?;
                    out.push_str(&home.display().to_string());
                }
                'h' => out.push_str(&self.host),
                'i' => out.push_str(
                    &self.uid.ok_or_else(|| missing("%i", "a user id, which this system has not"))?.to_string(),
                ),
                'j' => out.push_str(&self.jump),
                'k' => out.push_str(&self.alias),
                'L' | 'l' => {
                    let host = self
                        .local_host
                        .as_deref()
                        .ok_or_else(|| missing("%l", "the local host name, which is unknown"))?;
                    out.push_str(if token == 'L' { host.split('.').next().unwrap_or(host) } else { host });
                }
                'n' => out.push_str(&self.original),
                'p' => out.push_str(&self.port.to_string()),
                'r' => out.push_str(&self.remote_user),
                'u' => {
                    out.push_str(self.local_user.as_deref().ok_or_else(|| {
                        missing("%u", "the local user name, and USER, LOGNAME and USERNAME are not set")
                    })?)
                }
                other => return Err(refuse(format!("%{other} is not a token; the tokens are {TOKENS}"))),
            }
        }
        Ok(tilde(&out, self.home.as_deref()))
    }
}

/// `~` or a leading `~/` as the home directory, as OpenSSH reads it.
fn tilde(path: &str, home: Option<&Path>) -> PathBuf {
    match (path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")), home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ if path == "~" => home.map(PathBuf::from).unwrap_or_else(|| PathBuf::from(path)),
        _ => PathBuf::from(path),
    }
}

/// The local host name, for `%l`, `%L` and `%C`: the system's, never the
/// user database's.
#[cfg(unix)]
pub fn local_host_name() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer's length is passed with it.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(not(unix))]
pub fn local_host_name() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().filter(|h| !h.trim().is_empty())
}

/// The local user id, for `%i`.
#[cfg(unix)]
pub fn local_uid() -> Option<u32> {
    // SAFETY: getuid has no preconditions.
    Some(unsafe { libc::getuid() })
}

#[cfg(not(unix))]
pub fn local_uid() -> Option<u32> {
    None
}
