//! SFTP version 3 over a session channel: the base of `cp`, `mv`, `scp` and
//! `sftp`.
//!
//! **Each wait has a limit.** A client that waits for a reply with no limit
//! can stop a script for ever (tty7's issue 1126, read in GitHub #20; GitHub
//! #15 was this class). Opening the channel, the subsystem request, the
//! version exchange and each metadata request wait [`METADATA_WAIT`] at most,
//! as a pty or exec reply does; a read or a write waits [`DATA_WAIT`], as a
//! stuck write does on the relay. A command's own deadline (`--timeout`) goes
//! around the whole run, authentication included.
//!
//! **The protocol is russh-sftp's** (Apache-2.0, pure Rust, requests in flight
//! together). What it does not check, this module does: a `READ` reply longer
//! than its request is an error. A reply whose id no request waits for, it
//! drops, since the reply may belong to a request that timed out; the request
//! that waited for it then fails at its own limit.
//!
//! **Names are text.** russh-sftp reads a name that is not UTF-8 with U+FFFD in
//! place of each bad byte, so such a name can be listed but not named back.

mod error;

pub use error::{sentence, SftpError};
pub use russh_sftp::protocol::{FileAttributes, OpenFlags};

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use russh::client::Handle;
use russh_sftp::client::error::Error as Raw;
use russh_sftp::client::{Config, RawSftpSession};
use russh_sftp::protocol::StatusCode;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::handler::Client;

/// The limit on each reply that carries no file data: the open, the version
/// exchange, and each metadata request. The same as a pty or exec reply.
pub const METADATA_WAIT: Duration = Duration::from_secs(30);
/// The limit on a read or a write with no data acknowledged.
pub const DATA_WAIT: Duration = Duration::from_secs(60);
/// The size of a read or a write when the server names no limit.
pub const CHUNK: u32 = 32 * 1024;
/// The largest read or write asked for whatever the server names: a reply
/// stays under the 256 KiB packet that the client accepts.
pub const MAX_CHUNK: u32 = 255 * 1024;

/// The two limits of a session. The defaults are [`METADATA_WAIT`] and
/// [`DATA_WAIT`]; a test shortens them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Each reply that carries no file data.
    pub metadata: Duration,
    /// Each read or write.
    pub data: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { metadata: METADATA_WAIT, data: DATA_WAIT }
    }
}

/// An open file on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle(String);

/// One entry of a directory.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The name in the directory, `.` and `..` included.
    pub name: String,
    /// What the server told of it.
    pub attrs: FileAttributes,
}

/// What `statvfs@openssh.com` tells of a file system: the unit of its
/// counts (`f_frsize`), its blocks and its inodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statvfs {
    pub unit: u64,
    pub blocks: u64,
    pub free: u64,
    /// Free to a user who is not root.
    pub available: u64,
    pub files: u64,
    pub files_free: u64,
    pub files_available: u64,
}

/// An SFTP session.
pub struct Sftp {
    raw: RawSftpSession,
    limits: Limits,
    extensions: BTreeMap<String, String>,
    read_len: u32,
    write_len: u32,
}

impl std::fmt::Debug for Sftp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sftp")
            .field("limits", &self.limits)
            .field("extensions", &self.extensions.keys().collect::<Vec<_>>())
            .field("read_len", &self.read_len)
            .field("write_len", &self.write_len)
            .finish_non_exhaustive()
    }
}

/// The future, within `limit`; each failure named by `what`.
async fn within<T>(limit: Duration, what: &str, future: impl Future<Output = Result<T, Raw>>) -> Result<T, SftpError> {
    match tokio::time::timeout(limit, future).await {
        Err(_) => Err(SftpError::Timeout { what: what.to_string(), limit }),
        Ok(Err(e)) => Err(SftpError::from_raw(what, e, limit)),
        Ok(Ok(v)) => Ok(v),
    }
}

/// Two strings as SSH writes them, for an extension's request.
fn ssh_strings(parts: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part.as_bytes());
    }
    out
}

impl Sftp {
    /// The `sftp` subsystem on a new session channel of `handle`. A refusal,
    /// or no answer to the request, is [`SftpError::NoSftp`].
    pub async fn open(handle: &Handle<Client>, limits: Limits) -> Result<Sftp, SftpError> {
        Sftp::open_named(handle, "sftp", limits).await
    }

    /// The subsystem `name` as an SFTP server (`sftp -s NAME`).
    pub async fn open_named(handle: &Handle<Client>, name: &str, limits: Limits) -> Result<Sftp, SftpError> {
        let what = "open a session channel for SFTP";
        let mut channel = match tokio::time::timeout(limits.metadata, handle.channel_open_session()).await {
            Err(_) => return Err(SftpError::Timeout { what: what.into(), limit: limits.metadata }),
            Ok(Err(e)) => return Err(SftpError::Closed(format!("{what}: {e}"))),
            Ok(Ok(channel)) => channel,
        };
        let asked = tokio::time::timeout(limits.metadata, channel.request_subsystem(true, name)).await;
        match asked {
            Err(_) => {
                return Err(SftpError::Timeout {
                    what: format!("ask for the {name} subsystem"),
                    limit: limits.metadata,
                })
            }
            Ok(Err(e)) => return Err(SftpError::Closed(format!("ask for the {name} subsystem: {e}"))),
            Ok(Ok(())) => {}
        }
        // Nothing comes before the subsystem's reply that SFTP needs.
        let mut early = Vec::new();
        if !crate::session::wait_reply(&mut channel, &mut early).await.map_err(SftpError::Closed)? {
            return Err(SftpError::NoSftp);
        }
        Sftp::over(channel.into_stream(), limits).await
    }

    /// SFTP over any stream: a channel's, or a server's pipes in a test. The
    /// version exchange, then the server's limits when it names them.
    pub async fn over<S>(stream: S, limits: Limits) -> Result<Sftp, SftpError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // The library's own limit on each request is the longer one; each
        // metadata request gets the shorter one here.
        let config = Config { request_timeout_secs: limits.data.as_secs().max(1), ..Config::default() };
        let mut raw = RawSftpSession::new_with_config(stream, config);
        let version = within(limits.metadata, "the SFTP version exchange", raw.init()).await?;
        if version.version != 3 {
            return Err(SftpError::Protocol(format!(
                "the server answered SFTP version {}, and podssh speaks version 3",
                version.version
            )));
        }
        let extensions: BTreeMap<String, String> = version.extensions.into_iter().collect();
        let (mut read_len, mut write_len) = (CHUNK, CHUNK);
        if extensions.contains_key("limits@openssh.com") {
            let named = within(limits.metadata, "the server's limits", raw.limits()).await?;
            let fit = |n: u64| if n == 0 { CHUNK } else { n.min(u64::from(MAX_CHUNK)) as u32 };
            read_len = fit(named.max_read_len);
            write_len = fit(named.max_write_len);
            raw.set_limits(named.into());
        }
        Ok(Sftp { raw, limits, extensions, read_len, write_len })
    }

    /// The extensions that the server named, with their versions.
    pub fn extensions(&self) -> &BTreeMap<String, String> {
        &self.extensions
    }

    /// The size of each read: the server's limit, else [`CHUNK`].
    pub fn read_len(&self) -> u32 {
        self.read_len
    }

    /// The size of each write: the server's limit, else [`CHUNK`].
    pub fn write_len(&self) -> u32 {
        self.write_len
    }

    /// What the server knows of `path`, following a link.
    pub async fn stat(&self, path: &str) -> Result<FileAttributes, SftpError> {
        let what = format!("stat {path}");
        Ok(within(self.limits.metadata, &what, self.raw.stat(path)).await?.attrs)
    }

    /// What the server knows of `path` itself, a link included.
    pub async fn lstat(&self, path: &str) -> Result<FileAttributes, SftpError> {
        let what = format!("lstat {path}");
        Ok(within(self.limits.metadata, &what, self.raw.lstat(path)).await?.attrs)
    }

    /// The absolute name of `path` on the server.
    pub async fn realpath(&self, path: &str) -> Result<String, SftpError> {
        let what = format!("realpath {path}");
        let name = within(self.limits.metadata, &what, self.raw.realpath(path)).await?;
        match name.files.as_slice() {
            [one] => Ok(one.filename.clone()),
            other => Err(SftpError::Protocol(format!("{what}: {} names, not one", other.len()))),
        }
    }

    /// Open `path` with `flags`; `attrs` give a new file its mode.
    pub async fn open_file(
        &self,
        path: &str,
        flags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<FileHandle, SftpError> {
        let what = format!("open {path}");
        Ok(FileHandle(within(self.limits.metadata, &what, self.raw.open(path, flags, attrs)).await?.handle))
    }

    /// Close an open file or directory.
    pub async fn close(&self, file: &FileHandle) -> Result<(), SftpError> {
        within(self.limits.metadata, "close a file", self.raw.close(file.0.as_str())).await.map(|_| ())
    }

    /// Up to `len` bytes at `offset`; `None` at the end of the file. A reply
    /// longer than `len` breaks the protocol.
    pub async fn read(&self, file: &FileHandle, offset: u64, len: u32) -> Result<Option<Vec<u8>>, SftpError> {
        let what = format!("read at {offset}");
        match within(self.limits.data, &what, self.raw.read(file.0.as_str(), offset, len)).await {
            Ok(data) if data.data.len() > len as usize => {
                Err(SftpError::Protocol(format!("{what}: {} bytes in reply to a read of {len}", data.data.len())))
            }
            Ok(data) => Ok(Some(data.data)),
            Err(SftpError::Status { code, .. }) if code == StatusCode::Eof as u32 => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `data` at `offset`, in writes of [`Sftp::write_len`] at most.
    pub async fn write(&self, file: &FileHandle, offset: u64, data: &[u8]) -> Result<(), SftpError> {
        let mut at = offset;
        for part in data.chunks(self.write_len as usize) {
            let what = format!("write at {at}");
            within(self.limits.data, &what, self.raw.write(file.0.as_str(), at, part.to_vec())).await?;
            at += part.len() as u64;
        }
        Ok(())
    }

    /// Copy `from` from its start to `to` on the server (`copy-data`), so
    /// that no byte comes through here; `limit` scales with the size, since
    /// the one reply comes when the copy ends.
    pub async fn copy_data(&self, from: &FileHandle, to: &FileHandle, limit: Duration) -> Result<(), SftpError> {
        // string handle, uint64 from-offset, uint64 length (0: to the end),
        // string handle, uint64 to-offset.
        let mut data = ssh_strings(&[from.0.as_str()]);
        data.extend_from_slice(&0u64.to_be_bytes());
        data.extend_from_slice(&0u64.to_be_bytes());
        data.extend_from_slice(&ssh_strings(&[to.0.as_str()]));
        data.extend_from_slice(&0u64.to_be_bytes());
        let what = "copy-data";
        match within(limit, what, self.raw.extended("copy-data", data)).await? {
            russh_sftp::protocol::Packet::Status(s) if s.status_code == StatusCode::Ok => Ok(()),
            russh_sftp::protocol::Packet::Status(s) => Err(SftpError::from_raw(what, Raw::Status(s), limit)),
            _ => Err(SftpError::Protocol(format!("{what}: a reply of the wrong type"))),
        }
    }

    /// The file system of `path` (`statvfs@openssh.com`), for `df`.
    pub async fn statvfs(&self, path: &str) -> Result<Statvfs, SftpError> {
        let what = format!("statvfs {path}");
        if !self.extensions.contains_key("statvfs@openssh.com") {
            let message = "the server has no statvfs@openssh.com".to_string();
            return Err(SftpError::Status { what, code: StatusCode::OpUnsupported as u32, message });
        }
        let request = self.raw.extended("statvfs@openssh.com", ssh_strings(&[path]));
        match within(self.limits.metadata, &what, request).await? {
            // Eleven uint64: bsize, frsize, blocks, bfree, bavail, files,
            // ffree, favail, fsid, flag, namemax.
            russh_sftp::protocol::Packet::ExtendedReply(r) if r.data.len() >= 88 => {
                let n = |i: usize| {
                    let mut eight = [0u8; 8];
                    eight.copy_from_slice(&r.data[i * 8..i * 8 + 8]);
                    u64::from_be_bytes(eight)
                };
                Ok(Statvfs {
                    unit: n(1),
                    blocks: n(2),
                    free: n(3),
                    available: n(4),
                    files: n(5),
                    files_free: n(6),
                    files_available: n(7),
                })
            }
            russh_sftp::protocol::Packet::Status(s) => {
                Err(SftpError::from_raw(&what, Raw::Status(s), self.limits.metadata))
            }
            _ => Err(SftpError::Protocol(format!("{what}: a reply of the wrong type"))),
        }
    }

    /// Flush a file to the server's disk, when the server can
    /// (`fsync@openssh.com`). Whether it could.
    pub async fn fsync(&self, file: &FileHandle) -> Result<bool, SftpError> {
        if !self.extensions.contains_key("fsync@openssh.com") {
            return Ok(false);
        }
        within(self.limits.data, "fsync a file", self.raw.fsync(file.0.as_str())).await.map(|_| true)
    }

    /// Set what `attrs` names on `path`: the permission bits of a copy.
    pub async fn setstat(&self, path: &str, attrs: FileAttributes) -> Result<(), SftpError> {
        within(self.limits.metadata, &format!("set the attributes of {path}"), self.raw.setstat(path, attrs))
            .await
            .map(|_| ())
    }

    /// Whether the server names the extension `name`.
    pub fn has(&self, name: &str) -> bool {
        self.extensions.contains_key(name)
    }

    /// Remove a file.
    pub async fn remove(&self, path: &str) -> Result<(), SftpError> {
        within(self.limits.metadata, &format!("remove {path}"), self.raw.remove(path)).await.map(|_| ())
    }

    /// Rename `from` to `to`, over `to` when the server can
    /// (`posix-rename@openssh.com`); version 3 alone refuses an existing `to`.
    pub async fn rename(&self, from: &str, to: &str) -> Result<(), SftpError> {
        let what = format!("rename {from} to {to}");
        if self.extensions.contains_key("posix-rename@openssh.com") {
            let request = self.raw.extended("posix-rename@openssh.com", ssh_strings(&[from, to]));
            return match within(self.limits.metadata, &what, request).await? {
                russh_sftp::protocol::Packet::Status(s) if s.status_code == StatusCode::Ok => Ok(()),
                russh_sftp::protocol::Packet::Status(s) => {
                    Err(SftpError::from_raw(&what, Raw::Status(s), self.limits.metadata))
                }
                _ => Err(SftpError::Protocol(format!("{what}: a reply of the wrong type"))),
            };
        }
        within(self.limits.metadata, &what, self.raw.rename(from, to)).await.map(|_| ())
    }

    /// Make a directory.
    pub async fn mkdir(&self, path: &str, attrs: FileAttributes) -> Result<(), SftpError> {
        within(self.limits.metadata, &format!("mkdir {path}"), self.raw.mkdir(path, attrs)).await.map(|_| ())
    }

    /// Remove an empty directory.
    pub async fn rmdir(&self, path: &str) -> Result<(), SftpError> {
        within(self.limits.metadata, &format!("rmdir {path}"), self.raw.rmdir(path)).await.map(|_| ())
    }

    /// Each entry of a directory, `.` and `..` included.
    pub async fn read_dir(&self, path: &str) -> Result<Vec<Entry>, SftpError> {
        let what = format!("list {path}");
        let dir = within(self.limits.metadata, &what, self.raw.opendir(path)).await?.handle;
        let mut out = Vec::new();
        let listed = loop {
            match within(self.limits.metadata, &what, self.raw.readdir(dir.as_str())).await {
                Ok(name) => out.extend(name.files.into_iter().map(|f| Entry { name: f.filename, attrs: f.attrs })),
                Err(SftpError::Status { code, .. }) if code == StatusCode::Eof as u32 => break Ok(out),
                Err(e) => break Err(e),
            }
        };
        let closed = within(self.limits.metadata, &what, self.raw.close(dir.as_str())).await;
        let out = listed?;
        closed?;
        Ok(out)
    }

    /// End the session: the end of input to the server, after each reply.
    pub fn close_session(self) -> Result<(), SftpError> {
        self.raw.close_session().map_err(|e| SftpError::from_raw("end the SFTP session", e, self.limits.metadata))
    }
}
