//! `TCP_NOTSENT_LOWAT` on podssh's own TCP sockets (T-661): the kernel then
//! keeps at most [`LOWAT`] bytes that it has not sent, so a key written
//! after a bulk write waits behind those, not behind the whole send buffer
//! (megabytes, as the kernel tunes it). A probe and not an assumption: the
//! call is tried, and a system that has no such option, or refuses it,
//! keeps its buffer as it was.

/// The bytes that the kernel may hold unsent: osewa's, a few packets.
pub const LOWAT: u32 = 16 * 1024;

#[cfg(target_os = "linux")]
const TCP_NOTSENT_LOWAT: libc::c_int = 25;
#[cfg(target_os = "macos")]
const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;

/// Set [`LOWAT`] on `tcp`; the system's words when it did not take it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn set(tcp: &tokio::net::TcpStream) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    set_on(tcp.as_raw_fd())
}

/// Elsewhere nothing is set: Windows has no such option, and the crate reads
/// no other system's number for it.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn set(_tcp: &tokio::net::TcpStream) -> Result<(), String> {
    Err("this system has no such option".into())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_on(fd: std::os::fd::RawFd) -> Result<(), String> {
    let value = LOWAT as libc::c_int;
    let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the descriptor of a socket that the caller holds open, and a
    // value of the length given, which setsockopt only reads.
    let set = unsafe {
        libc::setsockopt(fd, libc::IPPROTO_TCP, TCP_NOTSENT_LOWAT, (&value as *const libc::c_int).cast(), len)
    };
    if set == 0 {
        Ok(())
    } else {
        Err(format!("the system refused it: {}", std::io::Error::last_os_error()))
    }
}

/// What the socket holds now, where the system tells it: for the tests.
#[cfg(all(test, target_os = "linux"))]
fn get_on(fd: std::os::fd::RawFd) -> Option<u32> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: as in `set_on`; getsockopt writes at most `len` bytes into
    // `value`, and the length back into `len`.
    let got = unsafe {
        libc::getsockopt(fd, libc::IPPROTO_TCP, TCP_NOTSENT_LOWAT, (&mut value as *mut libc::c_int).cast(), &mut len)
    };
    (got == 0).then(|| u32::try_from(value).ok()).flatten()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    /// A TCP socket of Linux takes the option before it connects, and reads
    /// it back as set: no bind, no listen, nothing connects.
    #[tokio::test]
    async fn a_linux_tcp_socket_takes_16_kib_unsent() {
        let socket = tokio::net::TcpSocket::new_v4().expect("a TCP socket");
        assert_ne!(get_on(socket.as_raw_fd()), Some(LOWAT), "not the kernel's default");
        assert_eq!(set_on(socket.as_raw_fd()), Ok(()));
        assert_eq!(get_on(socket.as_raw_fd()), Some(LOWAT));
    }

    /// A descriptor that is no socket: the system's refusal, in words.
    #[test]
    fn a_refusal_is_said() {
        let refused = set_on(-1).expect_err("no socket");
        assert!(refused.starts_with("the system refused it: "), "{refused}");
    }
}
