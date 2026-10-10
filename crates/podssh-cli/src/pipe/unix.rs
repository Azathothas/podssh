//! The local socket's end of a pipe (T-176): `unix-connect:PATH`, a
//! service that listens on a Unix socket (a database, a container runtime,
//! an agent). A connect is not a listener, so the rule of no listener
//! allows it. On Linux, `@NAME` is a name in the abstract namespace.
//!
//! On Windows, a `\\.\pipe\` path is a named pipe, and any other path an
//! AF_UNIX socket (Windows 10 1803 and later); each is tried when the pipe
//! starts, and a failure names the reason (the operator's ruling of
//! 2026-10-08). The attempt is the probe.
//!
//! At the end of input, the write side is shut down, so that a server that
//! answers after it still answers. A named pipe has no half-close: the
//! server's bytes come until it closes.

use std::io;

use super::pump::End;
use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};

/// The longest name, with its NUL, that a Unix socket's address holds.
#[cfg(any(target_os = "linux", windows))]
pub const SUN_PATH: usize = 108;
#[cfg(not(any(target_os = "linux", windows)))]
pub const SUN_PATH: usize = 104;

/// Connect to `path`: the end, or the exit code once `say` has the line.
pub async fn open(path: &str, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    match connect(path).await {
        Ok(end) => Ok(end),
        Err(e) => {
            say(&format!("unix-connect:{path}: {e}"));
            Err(code(&e))
        }
    }
}

/// A missing socket or one that nobody serves is out of reach (69); a
/// socket that this user may not use is a refusal (77).
fn code(e: &io::Error) -> i32 {
    match e.kind() {
        io::ErrorKind::PermissionDenied => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

#[cfg(unix)]
async fn connect(path: &str) -> io::Result<End> {
    let stream = stream(path).await?;
    let (read, write) = stream.into_split();
    Ok(End::plain(Box::new(read), Box::new(write)))
}

#[cfg(unix)]
async fn stream(path: &str) -> io::Result<tokio::net::UnixStream> {
    #[cfg(target_os = "linux")]
    if let Some(name) = path.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        // A local connect does not wait on a peer's network.
        let stream = std::os::unix::net::UnixStream::connect_addr(&addr)?;
        stream.set_nonblocking(true)?;
        return tokio::net::UnixStream::from_std(stream);
    }
    tokio::net::UnixStream::connect(path).await
}

#[cfg(windows)]
async fn connect(path: &str) -> io::Result<End> {
    if is_named_pipe(path) {
        let client = named_pipe(path).await?;
        let (read, write) = tokio::io::split(client);
        return Ok(End::plain(Box::new(read), Box::new(write)));
    }
    let stream = af_unix(path)?;
    stream.set_nonblocking(true)?;
    let stream = tokio::net::TcpStream::from_std(stream)?;
    let (read, write) = stream.into_split();
    Ok(End::plain(Box::new(read), Box::new(write)))
}

/// `\\.\pipe\NAME`, either slash.
#[cfg(windows)]
pub(super) fn is_named_pipe(path: &str) -> bool {
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    lower.starts_with(r"\\.\pipe\")
}

/// A named pipe's client; a pipe whose instances are all busy is asked
/// again for 5 s.
#[cfg(windows)]
async fn named_pipe(path: &str) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            opened => return opened,
        }
    }
}

/// WinSock, started for this process: WSAStartup counts its callers; the
/// standard library calls it too, and a second call is harmless.
#[cfg(windows)]
pub(super) fn wsa_start() -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock as ws;
    // SAFETY: an all-zero WSADATA is valid for WSAStartup to fill.
    let mut data: ws::WSADATA = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let rc = unsafe { ws::WSAStartup(0x0202, &mut data) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(())
}

/// The address of an AF_UNIX socket at `path`, whose name was checked to
/// fit.
#[cfg(windows)]
pub(super) fn sockaddr(path: &str) -> windows_sys::Win32::Networking::WinSock::SOCKADDR_UN {
    use windows_sys::Win32::Networking::WinSock as ws;
    // SAFETY: an all-zero SOCKADDR_UN is valid.
    let mut addr: ws::SOCKADDR_UN = unsafe { std::mem::zeroed() };
    addr.sun_family = ws::AF_UNIX;
    for (slot, byte) in addr.sun_path.iter_mut().zip(path.as_bytes()) {
        *slot = *byte as _;
    }
    addr
}

/// An AF_UNIX stream socket connected to `path`, by WinSock: Rust's
/// standard library has none on Windows. A connected socket of any family
/// carries bytes as a TCP one does, so it is handed on as one.
#[cfg(windows)]
pub(super) fn af_unix(path: &str) -> io::Result<std::net::TcpStream> {
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock as ws;
    wsa_start()?;
    // SAFETY: a plain socket call; the handle is owned below, or closed.
    let socket = unsafe { ws::socket(ws::AF_UNIX as i32, ws::SOCK_STREAM, 0) };
    if socket == ws::INVALID_SOCKET {
        return Err(io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() }));
    }
    let addr = sockaddr(path);
    let len = std::mem::size_of::<ws::SOCKADDR_UN>() as i32;
    // SAFETY: `addr` is a SOCKADDR_UN of `len` bytes.
    let rc = unsafe { ws::connect(socket, (&addr as *const ws::SOCKADDR_UN).cast(), len) };
    if rc != 0 {
        let e = io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() });
        // SAFETY: the socket was opened above and is closed once.
        unsafe { ws::closesocket(socket) };
        return Err(e);
    }
    // SAFETY: a connected stream socket, owned from here by the stream.
    Ok(unsafe { std::net::TcpStream::from_raw_socket(socket as u64) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_socket_is_out_of_reach_and_no_permission_is_a_refusal() {
        assert_eq!(code(&io::Error::from(io::ErrorKind::NotFound)), 69);
        assert_eq!(code(&io::Error::from(io::ErrorKind::ConnectionRefused)), 69);
        assert_eq!(code(&io::Error::from(io::ErrorKind::PermissionDenied)), 77);
    }

    #[cfg(windows)]
    #[test]
    fn a_named_pipe_is_known_by_its_prefix_either_slash() {
        assert!(is_named_pipe(r"\\.\pipe\openssh-ssh-agent"));
        assert!(is_named_pipe("//./pipe/docker_engine"));
        assert!(!is_named_pipe(r"C:\Users\x\agent.sock"));
    }
}
