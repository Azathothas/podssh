//! Multipath TCP on the direct road (T-172), on request. A connection with
//! no proxy asks Linux for a socket of `IPPROTO_MPTCP`: where the server
//! speaks MPTCP too, the connection can go on over another network of this
//! host when one goes. Linux makes one from 5.6, when the switch of
//! [`ENABLED_FILE`] is 1, and a server that does not speak it gets plain TCP
//! from the same socket, as the kernel falls back by itself.
//!
//! The probe is the switch, then the socket call. Where either says no, the
//! connection is plain TCP: the same stream, so the fallback changes nothing
//! but the paths. The caller learns which it got, and why, for `-v`.

use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpSocket, TcpStream};

/// Linux's switch of Multipath TCP, for each network namespace.
pub const ENABLED_FILE: &str = "/proc/sys/net/mptcp/enabled";

/// How a connection that asked for Multipath TCP was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Multipath {
    /// A socket of MPTCP. `server`: whether the server took MPTCP, where the
    /// kernel says (Linux 5.16 and later); `None` where it does not.
    Mptcp { server: Option<bool> },
    /// Plain TCP, and why.
    Plain(String),
}

impl std::fmt::Display for Multipath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Multipath::Mptcp { server: Some(true) } => write!(f, "Multipath TCP, which the server took"),
            Multipath::Mptcp { server: Some(false) } => {
                write!(f, "Multipath TCP asked for; the server answered with plain TCP")
            }
            Multipath::Mptcp { server: None } => {
                write!(f, "Multipath TCP asked for; this kernel does not say whether the server took it")
            }
            Multipath::Plain(why) => write!(f, "plain TCP: {why}"),
        }
    }
}

/// Whether this host offers Multipath TCP: Linux, with its switch at 1.
/// The reason, when it does not.
pub fn probe() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("Multipath TCP is made on Linux only".into());
    }
    enabled(std::fs::read_to_string(ENABLED_FILE).as_deref().map_err(|e| e.to_string()))
}

/// The answer of the switch, from its text, or from why it was not read.
pub fn enabled(read: Result<&str, String>) -> Result<(), String> {
    match read {
        Ok(text) if text.trim() == "1" => Ok(()),
        Ok(text) => Err(format!("{ENABLED_FILE} is {}, so this kernel offers no Multipath TCP", text.trim())),
        // A kernel before 5.6, or one built without MPTCP, has no file.
        Err(why) => Err(format!("{ENABLED_FILE}: {why}; this kernel offers no Multipath TCP")),
    }
}

/// Connect to `addr`: over a socket of MPTCP when `offer`, the answer of
/// [`probe`], allows it and the kernel gives one, else over plain TCP.
pub async fn connect(addr: SocketAddr, offer: Result<(), String>) -> io::Result<(TcpStream, Multipath)> {
    connect_with(addr, offer, socket).await
}

/// [`connect`], with the socket call given: a test plants the kernel's
/// refusal there.
pub async fn connect_with(
    addr: SocketAddr,
    offer: Result<(), String>,
    open: fn(&SocketAddr) -> io::Result<TcpSocket>,
) -> io::Result<(TcpStream, Multipath)> {
    if let Err(why) = offer {
        return Ok((TcpStream::connect(addr).await?, Multipath::Plain(why)));
    }
    match open(&addr) {
        Ok(socket) => {
            let stream = socket.connect(addr).await?;
            let server = server_took(&stream);
            Ok((stream, Multipath::Mptcp { server }))
        }
        // EPROTONOSUPPORT, ENOPROTOOPT, EINVAL or EPERM: a kernel, or a
        // sandbox's seccomp, that refuses the protocol. Any other error of
        // the call goes the same way: a plain socket gives it again when its
        // cause is not MPTCP (no descriptor left, say).
        Err(e) => {
            let stream = TcpStream::connect(addr).await?;
            Ok((stream, Multipath::Plain(format!("the kernel refused a socket of Multipath TCP: {e}"))))
        }
    }
}

/// A socket of Multipath TCP for the family of `addr`, as Linux makes one:
/// non-blocking, as tokio needs, and closed at an exec.
#[cfg(target_os = "linux")]
pub fn socket(addr: &SocketAddr) -> io::Result<TcpSocket> {
    use std::os::fd::FromRawFd;
    let family = if addr.is_ipv6() { libc::AF_INET6 } else { libc::AF_INET };
    let kind = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    // SAFETY: a plain socket call; its descriptor is owned below, or none
    // was made.
    let fd = unsafe { libc::socket(family, kind, libc::IPPROTO_MPTCP) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor of a stream socket, owned once from here.
    Ok(unsafe { TcpSocket::from_raw_fd(fd) })
}

/// Only Linux makes a socket of Multipath TCP.
#[cfg(not(target_os = "linux"))]
pub fn socket(_addr: &SocketAddr) -> io::Result<TcpSocket> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "Multipath TCP is made on Linux only"))
}

/// Whether the server took MPTCP: `TCP_IS_MPTCP` is 1 on a connection that
/// speaks it and 0 on one that fell back to plain TCP, as the subflow then
/// answers. A kernel before 5.16 does not know the option, and says nothing.
#[cfg(target_os = "linux")]
fn server_took(stream: &TcpStream) -> Option<bool> {
    use std::os::fd::AsRawFd;
    // From linux/tcp.h: the libc crate does not name it.
    const TCP_IS_MPTCP: libc::c_int = 43;
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `value`, which this
    // function owns, for a descriptor that the stream holds open.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_IS_MPTCP,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(value != 0)
}

#[cfg(not(target_os = "linux"))]
fn server_took(_stream: &TcpStream) -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_offers_mptcp_at_1_only_and_says_why_not() {
        assert_eq!(enabled(Ok("1\n")), Ok(()));
        let off = enabled(Ok("0\n")).unwrap_err();
        assert!(off.contains("is 0"), "{off}");
        let missing = enabled(Err("No such file or directory (os error 2)".into())).unwrap_err();
        assert!(missing.contains(ENABLED_FILE) && missing.contains("No such file"), "{missing}");
    }

    #[test]
    fn each_way_is_named_for_the_log() {
        assert_eq!(Multipath::Mptcp { server: Some(true) }.to_string(), "Multipath TCP, which the server took");
        assert!(Multipath::Mptcp { server: Some(false) }.to_string().contains("plain TCP"));
        assert!(Multipath::Mptcp { server: None }.to_string().contains("does not say"));
        assert_eq!(Multipath::Plain("why".into()).to_string(), "plain TCP: why");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn only_linux_makes_a_socket_of_mptcp() {
        assert!(probe().unwrap_err().contains("Linux only"));
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert_eq!(socket(&addr).err().map(|e| e.kind()), Some(io::ErrorKind::Unsupported));
    }
}
