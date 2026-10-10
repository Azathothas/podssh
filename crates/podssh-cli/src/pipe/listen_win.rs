//! The listening side of `podssh pipe` on Windows (T-177): an AF_UNIX
//! socket by WinSock, or a named pipe (`\\.\pipe\NAME`). Each client's
//! process must run as this user: its token's user is compared with this
//! process's, and a client of another user, or one whose user cannot be
//! read, is closed before a byte passes. The socket's file goes when the
//! listener drops.
//!
//! The standard library cannot accept on an AF_UNIX socket (it reads each
//! peer's address as an internet one), so one thread accepts, for the
//! listener's whole life, and hands each socket on through a channel: a
//! wait that is given up loses no client. A named pipe has no half-close:
//! the end of this side's input closes it, and the client reads what is
//! left, then its end.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawSocket};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Networking::WinSock as ws;
use windows_sys::Win32::Security::{EqualSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::listen::{code, refused, Unbound};
use super::pump::End;
use crate::exitmap::sysexits::{EX_UNAVAILABLE, EX_USAGE};

/// `_WSAIOR(IOC_VENDOR, 256)` of afunix.h: the process at the other end of
/// an AF_UNIX socket.
const SIO_AF_UNIX_GETPEERPID: u32 = 0x5800_0100;
/// A file's attribute of a reparse point, as an AF_UNIX socket's file is.
const REPARSE_POINT: u32 = 0x400;

/// A listener of either kind, with this process's user.
pub struct Bound {
    kind: Kind,
    /// This process's `TOKEN_USER`, in words for its alignment.
    ours: Vec<u64>,
}

enum Kind {
    Socket { socket: ws::SOCKET, file: PathBuf, accepted: mpsc::UnboundedReceiver<io::Result<ws::SOCKET>> },
    Pipe { name: String, next: Option<NamedPipeServer> },
}

impl Drop for Bound {
    fn drop(&mut self) {
        if let Kind::Socket { socket, file, .. } = &self.kind {
            // SAFETY: the listening socket was opened by `bind`, and is
            // closed once; an accept that waits on it returns.
            unsafe { ws::closesocket(*socket) };
            let _ = std::fs::remove_file(file);
        }
    }
}

/// Listen on `path`: a named pipe by its prefix, else an AF_UNIX socket.
pub fn bind(path: &str, say: &mut dyn FnMut(&str)) -> Result<Bound, Unbound> {
    let shown = format!("unix-listen:{path}");
    // SAFETY: the pseudo-handle of this process needs no closing.
    let ours = token_user(unsafe { GetCurrentProcess() }).map_err(|e| {
        (EX_UNAVAILABLE, format!("{shown}: this process's user cannot be read, so no peer could be checked: {e}"))
    })?;
    if super::unix::is_named_pipe(path) {
        let server = ServerOptions::new().first_pipe_instance(true).reject_remote_clients(true).create(path);
        let server = server.map_err(|e| {
            (EX_UNAVAILABLE, format!("{shown}: a pipe of that name exists, or this user may not make it: {e}"))
        })?;
        say(&format!("listening on {shown}: for this user's programs only"));
        return Ok(Bound { kind: Kind::Pipe { name: path.to_string(), next: Some(server) }, ours });
    }
    let file = PathBuf::from(path);
    stale(path, &file).map_err(|(rc, line)| (rc, format!("{shown}: {line}")))?;
    match listen(path) {
        Ok(socket) => {
            say(&format!("listening on {shown}: for this user's programs only"));
            let accepted = acceptor(socket);
            Ok(Bound { kind: Kind::Socket { socket, file, accepted }, ours })
        }
        Err(e) => {
            // The path was free before the bind: what is there is ours.
            let _ = std::fs::remove_file(&file);
            Err((code(&e), refused(&shown, &e)))
        }
    }
}

/// A free path: nothing there, or a socket that nobody serves, which is
/// removed. A file that is not a socket is never removed (64); a socket
/// that answers is another program's (69).
fn stale(path: &str, file: &std::path::Path) -> Result<(), (i32, String)> {
    use std::os::windows::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(file) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err((code(&e), e.to_string())),
        Ok(meta) => meta,
    };
    if meta.file_attributes() & REPARSE_POINT == 0 {
        return Err((
            EX_USAGE,
            "it exists and is not a socket; podssh removes only a socket that nobody serves".into(),
        ));
    }
    match super::unix::af_unix(path) {
        Ok(_) => Err((EX_UNAVAILABLE, "a program listens on it already".into())),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(file).map_err(|e| (code(&e), format!("a socket that nobody serves: {e}")))
        }
        Err(e) => Err((code(&e), e.to_string())),
    }
}

/// Socket, bind and listen, by WinSock.
fn listen(path: &str) -> io::Result<ws::SOCKET> {
    super::unix::wsa_start()?;
    // SAFETY: a plain socket call; the handle is kept below, or closed.
    let socket = unsafe { ws::socket(ws::AF_UNIX as i32, ws::SOCK_STREAM, 0) };
    if socket == ws::INVALID_SOCKET {
        return Err(wsa_error());
    }
    let addr = super::unix::sockaddr(path);
    let len = std::mem::size_of::<ws::SOCKADDR_UN>() as i32;
    // SAFETY: `addr` is a SOCKADDR_UN of `len` bytes; the socket is ours.
    let failed =
        unsafe { ws::bind(socket, (&addr as *const ws::SOCKADDR_UN).cast(), len) != 0 || ws::listen(socket, 8) != 0 };
    if failed {
        let e = wsa_error();
        // SAFETY: the socket was opened above and is closed once.
        unsafe { ws::closesocket(socket) };
        return Err(e);
    }
    Ok(socket)
}

/// The thread that accepts on `listening` until it closes, or until nobody
/// takes its sockets; a socket that nobody took is closed.
fn acceptor(listening: ws::SOCKET) -> mpsc::UnboundedReceiver<io::Result<ws::SOCKET>> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || loop {
        // SAFETY: the listening socket lives until the listener drops, and
        // a socket closed under the wait makes it fail.
        let s = unsafe { ws::accept(listening, std::ptr::null_mut(), std::ptr::null_mut()) };
        if s == ws::INVALID_SOCKET {
            let _ = tx.send(Err(wsa_error()));
            return;
        }
        if let Err(unsent) = tx.send(Ok(s)) {
            if let Ok(s) = unsent.0 {
                // SAFETY: accepted above, taken by nobody, closed once.
                unsafe { ws::closesocket(s) };
            }
            return;
        }
    });
    rx
}

fn wsa_error() -> io::Error {
    // SAFETY: a read of this thread's last WinSock error.
    io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() })
}

impl Bound {
    /// The next client of this user; another user's is closed.
    pub async fn accept(&mut self, say: &mut dyn FnMut(&str)) -> io::Result<End> {
        loop {
            match &mut self.kind {
                Kind::Socket { accepted, .. } => {
                    let Some(accepted) = accepted.recv().await else {
                        return Err(io::Error::other("the listener's thread ended"));
                    };
                    let accepted = accepted?;
                    match peer_pid(accepted).and_then(|pid| same_user(&self.ours, pid)) {
                        Ok(true) => {
                            say("a client connected");
                            // SAFETY: a connected stream socket, owned from
                            // here by the stream.
                            let stream = unsafe { std::net::TcpStream::from_raw_socket(accepted as u64) };
                            stream.set_nonblocking(true)?;
                            let (read, write) = tokio::net::TcpStream::from_std(stream)?.into_split();
                            return Ok(End::plain(Box::new(read), Box::new(write)));
                        }
                        Ok(false) => say("closed a client of another user: this socket is for this user"),
                        Err(e) => say(&format!("closed a client whose user is not known: {e}")),
                    }
                    // SAFETY: the accepted socket is closed once, unused.
                    unsafe { ws::closesocket(accepted) };
                }
                Kind::Pipe { name, next } => {
                    if next.is_none() {
                        // The last one could not be made: try again.
                        *next = Some(ServerOptions::new().reject_remote_clients(true).create(name.as_str())?);
                    }
                    // The instance stays while the wait goes on: a wait
                    // that is given up loses no client.
                    next.as_ref().expect("made above").connect().await?;
                    let server = next.take().expect("connected above");
                    // The next instance at once: a client that comes
                    // meanwhile finds it; one that cannot be made is made
                    // at the next accept.
                    *next = ServerOptions::new().reject_remote_clients(true).create(name.as_str()).ok();
                    match pipe_pid(&server).and_then(|pid| same_user(&self.ours, pid)) {
                        Ok(true) => {
                            say("a client connected");
                            let closing =
                                Arc::new(Closing { pipe: Mutex::new(Some(server)), reader: Mutex::new(None) });
                            return Ok(End::plain(
                                Box::new(ClosingRead(closing.clone())),
                                Box::new(ClosingWrite(closing)),
                            ));
                        }
                        Ok(false) => say("closed a client of another user: this pipe is for this user"),
                        Err(e) => say(&format!("closed a client whose user is not known: {e}")),
                    }
                }
            }
        }
    }
}

/// A named pipe's server end that the end of this side's input closes,
/// whole: the client reads the bytes that are left, then its end. The read
/// half then ends too.
struct Closing {
    pipe: Mutex<Option<NamedPipeServer>>,
    /// The read that waits, woken when the pipe closes under it.
    reader: Mutex<Option<Waker>>,
}

struct ClosingRead(Arc<Closing>);
struct ClosingWrite(Arc<Closing>);

fn guard<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl AsyncRead for ClosingRead {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut pipe = guard(&self.0.pipe);
        let Some(pipe) = pipe.as_mut() else { return Poll::Ready(Ok(())) };
        let read = Pin::new(pipe).poll_read(cx, buf);
        if read.is_pending() {
            *guard(&self.0.reader) = Some(cx.waker().clone());
        }
        read
    }
}

impl AsyncWrite for ClosingWrite {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match guard(&self.0.pipe).as_mut() {
            Some(pipe) => Pin::new(pipe).poll_write(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match guard(&self.0.pipe).as_mut() {
            Some(pipe) => Pin::new(pipe).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pipe = guard(&self.0.pipe);
        if let Some(open) = pipe.as_mut() {
            // The last bytes go out first.
            std::task::ready!(Pin::new(open).poll_flush(cx))?;
        }
        // A close, not a disconnect, which would drop what the client has
        // not read yet.
        drop(pipe.take());
        if let Some(reader) = guard(&self.0.reader).take() {
            reader.wake();
        }
        Poll::Ready(Ok(()))
    }
}

/// The process at the other end of an AF_UNIX socket.
fn peer_pid(socket: ws::SOCKET) -> io::Result<u32> {
    let mut pid: u32 = 0;
    let mut returned: u32 = 0;
    // SAFETY: the out buffer is a u32 of 4 bytes; no overlapped I/O.
    let rc = unsafe {
        ws::WSAIoctl(
            socket,
            SIO_AF_UNIX_GETPEERPID,
            std::ptr::null(),
            0,
            (&mut pid as *mut u32).cast::<c_void>(),
            4,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        return Err(wsa_error());
    }
    Ok(pid)
}

/// The process at the other end of a named pipe.
fn pipe_pid(server: &NamedPipeServer) -> io::Result<u32> {
    let mut pid: u32 = 0;
    // SAFETY: the handle is the server's, open while it is borrowed.
    if unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// Whether process `pid` runs as the user of `ours`.
fn same_user(ours: &[u64], pid: u32) -> io::Result<bool> {
    // SAFETY: the handle is checked, and closed once.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let theirs = token_user(process);
    // SAFETY: opened above.
    unsafe { CloseHandle(process) };
    let theirs = theirs?;
    // SAFETY: each buffer holds a TOKEN_USER that GetTokenInformation wrote,
    // aligned as u64; its SID points inside the same buffer.
    let equal = unsafe {
        let a = &*(ours.as_ptr() as *const TOKEN_USER);
        let b = &*(theirs.as_ptr() as *const TOKEN_USER);
        EqualSid(a.User.Sid, b.User.Sid)
    };
    Ok(equal != 0)
}

/// The `TOKEN_USER` of a process, in words.
fn token_user(process: HANDLE) -> io::Result<Vec<u64>> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` receives a handle, closed below.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut len: u32 = 0;
    // SAFETY: a call with no buffer asks for the length.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    let size = (buf.len() * 8) as u32;
    // SAFETY: `buf` holds `size` bytes.
    let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), size, &mut len) };
    let e = io::Error::last_os_error();
    // SAFETY: opened above.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(e);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_runs_as_its_own_user() {
        // SAFETY: the pseudo-handle of this process.
        let ours = token_user(unsafe { GetCurrentProcess() }).unwrap();
        assert!(same_user(&ours, std::process::id()).unwrap());
    }
}
