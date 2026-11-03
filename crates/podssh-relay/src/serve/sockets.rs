//! The kernel's part of a slow reader's queue, bounded (T-336). Each write
//! of the role waits for its reader, so the role itself holds one read of
//! the other side at most; but the kernel grows a socket's send buffer to
//! some MiB, and a client that reads slowly then ties that much of the
//! host's memory to its session. `TCP_NOTSENT_LOWAT` keeps a socket's bytes
//! not yet sent under [`UNSENT`] and leaves those in flight to TCP, so a
//! fast reader's rate is not capped as a smaller send buffer would cap it.

use tokio::net::TcpStream;

/// The bytes that a socket of the role may hold not yet sent.
pub const UNSENT: u32 = 128 * 1024;

/// Bound what `tcp` holds unsent; where the system has no such option, or
/// refuses it, its own buffers are the bound.
pub fn bound_unsent(tcp: &TcpStream) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let value: libc::c_int = UNSENT as libc::c_int;
        // SAFETY: the descriptor is the stream's own, open while it is
        // borrowed, and the option's value is a c_int of the size given.
        unsafe {
            libc::setsockopt(
                tcp.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_NOTSENT_LOWAT,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = tcp;
}

/// What `tcp` holds unsent at most, as the kernel reads it back; `None`
/// where the system has no such option (for the tests).
pub fn unsent_bound(tcp: &TcpStream) -> Option<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: as in `bound_unsent`, with a value and a length of ours.
        let rc = unsafe {
            libc::getsockopt(
                tcp.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_NOTSENT_LOWAT,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        (rc == 0).then_some(value as u32)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = tcp;
        None
    }
}
