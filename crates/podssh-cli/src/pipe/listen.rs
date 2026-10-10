//! The listening side of `podssh pipe` (T-177): `unix-listen:PATH` and
//! `tcp-listen:[ADDR:]PORT`. podssh listens only on such an address that the
//! user gives, and never when `PODSSH_LISTEN` turns listening off (the
//! operator's ruling of 2026-10-08). The attempt, socket, bind and listen,
//! is the probe: a refusal names the error, and the addresses that need no
//! listener.
//!
//! A Unix socket is made mode 0600, so its file is the user's alone, and
//! each peer of another user is closed: the abstract namespace of Linux
//! has no file, and the peer check is its guard. A TCP port takes any local
//! user, or any host for an address that is not loopback, and podssh says
//! so. The socket's file goes when the listener drops; `serve` drops it at
//! SIGINT and SIGTERM too.

use std::io;

use super::address::Address;
use super::pump::End;
use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;

/// The variable that turns listening off.
pub const LISTEN_ENV: &str = "PODSSH_LISTEN";

/// What needs no listener, for the line of a refused one.
const INSTEAD: &str = "stdio, fd:N and exec:CMD need no listener";

/// Whether listening is allowed: `PODSSH_LISTEN=no` turns it off (78),
/// before anything binds.
pub fn allowed() -> Result<(), Refusal> {
    let Ok(value) = std::env::var(LISTEN_ENV) else { return Ok(()) };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Ok(()),
        "no" | "off" | "false" | "0" => {
            Err(Refusal::config(format!("{LISTEN_ENV}={value} turns listening off, so nothing listens; {INSTEAD}")))
        }
        _ => Err(Refusal::config(format!("{LISTEN_ENV}={value}: yes or no"))),
    }
}

/// A refused bind is a refusal of this host (77); the others are out of
/// reach (69).
pub(super) fn code(e: &io::Error) -> i32 {
    match e.kind() {
        io::ErrorKind::PermissionDenied => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

/// The line of a failed bind: the error, and what needs no listener when
/// the host refused it.
pub(super) fn refused(shown: &str, e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::PermissionDenied => format!("{shown}: {e}; this host refuses the listener: {INSTEAD}"),
        _ => format!("{shown}: {e}"),
    }
}

/// A listener, bound and listening.
pub struct Listener {
    kind: Kind,
}

enum Kind {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix(unix::Bound),
    #[cfg(windows)]
    Win(super::listen_win::Bound),
}

/// Why a listener did not bind: the exit code, and the line.
pub type Unbound = (i32, String);

impl Listener {
    /// Bind `address` and listen. `say` hears who can connect; a failure
    /// gives its code and line.
    pub async fn bind(address: &Address, say: &mut dyn FnMut(&str)) -> Result<Listener, Unbound> {
        let kind = match address {
            Address::TcpListen { host, port } => Kind::Tcp(tcp(host, *port, say).await?),
            #[cfg(unix)]
            Address::UnixListen(path) => Kind::Unix(unix::bind(path, say)?),
            #[cfg(windows)]
            Address::UnixListen(path) => Kind::Win(super::listen_win::bind(path, say)?),
            _ => unreachable!("not a listening address"),
        };
        Ok(Listener { kind })
    }

    /// The next client: a peer of another user is closed with a line, and
    /// the wait goes on.
    pub async fn accept(&mut self, say: &mut dyn FnMut(&str)) -> io::Result<End> {
        match &mut self.kind {
            Kind::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                let _ = stream.set_nodelay(true);
                say(&format!("a client connected from {peer}"));
                let (read, write) = stream.into_split();
                Ok(End::plain(Box::new(read), Box::new(write)))
            }
            #[cfg(unix)]
            Kind::Unix(bound) => bound.accept(say).await,
            #[cfg(windows)]
            Kind::Win(bound) => bound.accept(say).await,
        }
    }
}

/// `tcp-listen:`: one line of who can connect, with the port that the
/// system chose for port 0.
async fn tcp(host: &str, port: u16, say: &mut dyn FnMut(&str)) -> Result<tokio::net::TcpListener, Unbound> {
    let shown = podssh_ws::dial::authority(host, port);
    let listener = match tokio::net::TcpListener::bind((host, port)).await {
        Ok(listener) => listener,
        Err(e) => return Err((code(&e), refused(&format!("tcp-listen:{shown}"), &e))),
    };
    let at = listener.local_addr().map(|a| a.to_string()).unwrap_or(shown);
    let loopback = host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if loopback {
        say(&format!("listening on {at}: each user of this host can connect"));
    } else {
        say(&format!("listening on {at}: other hosts can connect, as each user of this host can"));
    }
    Ok(listener)
}

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::unix::fs::FileTypeExt;
    use std::path::{Path, PathBuf};

    use super::super::pump::End;
    use super::{code, refused, Unbound};
    use crate::exitmap::sysexits::{EX_UNAVAILABLE, EX_USAGE};

    /// A Unix socket, listening; its file, when it has one, goes with it.
    pub struct Bound {
        listener: tokio::net::UnixListener,
        file: Option<PathBuf>,
        uid: u32,
    }

    impl Drop for Bound {
        fn drop(&mut self) {
            if let Some(file) = &self.file {
                let _ = std::fs::remove_file(file);
            }
        }
    }

    /// Listen on `path`, or on `@NAME` in Linux's abstract namespace.
    pub fn bind(path: &str, say: &mut dyn FnMut(&str)) -> Result<Bound, Unbound> {
        let shown = format!("unix-listen:{path}");
        // SAFETY: geteuid cannot fail.
        let uid = unsafe { libc::geteuid() };
        #[cfg(target_os = "linux")]
        if let Some(name) = path.strip_prefix('@') {
            let listener = abstract_name(name).map_err(|e| (code(&e), refused(&shown, &e)))?;
            say(&format!("listening on {shown}: for this user's programs only"));
            return Ok(Bound { listener, file: None, uid });
        }
        let file = PathBuf::from(path);
        stale(&file).map_err(|(rc, line)| (rc, format!("{shown}: {line}")))?;
        match listen_file(&file) {
            Ok(listener) => {
                say(&format!("listening on {shown}: mode 0600, for this user's programs only"));
                Ok(Bound { listener, file: Some(file), uid })
            }
            Err(e) => {
                // The path was free before the bind: what is there is ours.
                let _ = std::fs::remove_file(&file);
                Err((code(&e), refused(&shown, &e)))
            }
        }
    }

    /// Socket, bind and listen on a file, under umask 0177, as ssh-agent
    /// makes its socket: the file is made mode 0600, never open to another
    /// user, not even for a moment.
    fn listen_file(file: &Path) -> io::Result<tokio::net::UnixListener> {
        // SAFETY: umask only swaps the process's mask; it is put back below.
        let before = unsafe { libc::umask(0o177) };
        let bound = std::os::unix::net::UnixListener::bind(file);
        // SAFETY: as above.
        unsafe { libc::umask(before) };
        let listener = bound?;
        listener.set_nonblocking(true)?;
        tokio::net::UnixListener::from_std(listener)
    }

    #[cfg(target_os = "linux")]
    fn abstract_name(name: &str) -> io::Result<tokio::net::UnixListener> {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        let listener = std::os::unix::net::UnixListener::bind_addr(&addr)?;
        listener.set_nonblocking(true)?;
        tokio::net::UnixListener::from_std(listener)
    }

    /// A free path: nothing there, or a socket that nobody serves, which is
    /// removed. A file that is not a socket is never removed (64); a socket
    /// that answers is another program's (69).
    fn stale(file: &Path) -> Result<(), (i32, String)> {
        let meta = match std::fs::symlink_metadata(file) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err((code(&e), e.to_string())),
            Ok(meta) => meta,
        };
        if !meta.file_type().is_socket() {
            return Err((
                EX_USAGE,
                "it exists and is not a socket; podssh removes only a socket that nobody serves".into(),
            ));
        }
        match std::os::unix::net::UnixStream::connect(file) {
            Ok(_) => Err((EX_UNAVAILABLE, "a program listens on it already".into())),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(file).map_err(|e| (code(&e), format!("a socket that nobody serves: {e}")))
            }
            Err(e) => Err((code(&e), e.to_string())),
        }
    }

    impl Bound {
        /// The next client of this user; another user's is closed.
        pub async fn accept(&mut self, say: &mut dyn FnMut(&str)) -> io::Result<End> {
            loop {
                let (stream, _) = self.listener.accept().await?;
                match stream.peer_cred() {
                    Ok(cred) if cred.uid() == self.uid => {
                        say("a client connected");
                        let (read, write) = stream.into_split();
                        return Ok(End::plain(Box::new(read), Box::new(write)));
                    }
                    Ok(cred) => {
                        say(&format!("closed a client of uid {}: this socket is for uid {}", cred.uid(), self.uid))
                    }
                    Err(e) => say(&format!("closed a client whose user is not known: {e}")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_listener_is_77_and_names_what_needs_none() {
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(code(&denied), 77);
        assert!(refused("tcp-listen:127.0.0.1:22", &denied).contains("exec:CMD need no listener"));
        let used = io::Error::from(io::ErrorKind::AddrInUse);
        assert_eq!(code(&used), 69);
        assert!(!refused("tcp-listen:127.0.0.1:22", &used).contains("need no listener"));
    }
}
