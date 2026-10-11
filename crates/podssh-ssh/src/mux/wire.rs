//! Packets and descriptors on a control socket. A packet is read exactly,
//! its length then its body, so that the byte that carries a descriptor
//! after it is never read as data: a plain read of that byte drops the
//! descriptor. Each descriptor goes alone, with one byte, as OpenSSH's
//! `mm_send_fd` sends it.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::UnixStream;

use super::proto::{Message, MAX_PACKET};

/// The next message, or `None` when the peer closed between messages.
pub async fn read(stream: &mut UnixStream) -> io::Result<Option<Message>> {
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < head.len() {
        match stream.read(&mut head[got..]).await? {
            0 if got == 0 => return Ok(None),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => got += n,
        }
    }
    let len = u32::from_be_bytes(head) as usize;
    if len == 0 || len > MAX_PACKET {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("a control message of {len} bytes")));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Message::parse(&body).map(Some).map_err(|why| io::Error::new(io::ErrorKind::InvalidData, why))
}

pub async fn write(stream: &mut UnixStream, message: &Message) -> io::Result<()> {
    stream.write_all(&message.packet()).await?;
    stream.flush().await
}

/// Send `fd`, with one byte.
pub async fn send_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
    loop {
        stream.writable().await?;
        match stream.try_io(Interest::WRITABLE, || send_now(stream.as_raw_fd(), fd)) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            done => return done,
        }
    }
}

/// The descriptor that comes with the next byte.
pub async fn recv_fd(stream: &UnixStream) -> io::Result<OwnedFd> {
    loop {
        stream.readable().await?;
        match stream.try_io(Interest::READABLE, || recv_now(stream.as_raw_fd())) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            done => return done,
        }
    }
}

/// Room for the control message of one descriptor, aligned for its header.
#[repr(C)]
struct Control([u64; 4]);

fn send_now(socket: RawFd, fd: RawFd) -> io::Result<()> {
    let byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut control = Control([0; 4]);
    // SAFETY: the header and the buffers live through the call, the control
    // buffer is large enough and aligned for one descriptor, and CMSG_*
    // only compute within it.
    unsafe {
        let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        match libc::sendmsg(socket, &msg, NO_SIGNAL) {
            1 => Ok(()),
            -1 => Err(io::Error::last_os_error()),
            _ => Err(io::Error::new(io::ErrorKind::WriteZero, "the byte of a descriptor was not sent")),
        }
    }
}

fn recv_now(socket: RawFd) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let mut control = Control([0; 4]);
    // SAFETY: as in `send_now`; a descriptor read from the control message
    // is the kernel's new one, owned here alone.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of::<Control>() as _;
        let n = libc::recvmsg(socket, &mut msg, CLOSE_ON_EXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the client left before its descriptors"));
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a byte came with no descriptor"));
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>());
        let owned = OwnedFd::from_raw_fd(fd);
        if CLOSE_ON_EXEC == 0 {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        Ok(owned)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const NO_SIGNAL: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const NO_SIGNAL: libc::c_int = 0;
#[cfg(any(target_os = "linux", target_os = "android"))]
const CLOSE_ON_EXEC: libc::c_int = libc::MSG_CMSG_CLOEXEC;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const CLOSE_ON_EXEC: libc::c_int = 0;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[tokio::test]
    async fn mux_protocol_a_descriptor_crosses_after_a_message() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let (mut pipe_read, pipe_write) = std::io::pipe().unwrap();
        write(&mut a, &Message::AliveCheck { rid: 5 }).await.unwrap();
        send_fd(&a, pipe_write.as_raw_fd()).await.unwrap();
        drop(pipe_write);
        assert_eq!(read(&mut b).await.unwrap(), Some(Message::AliveCheck { rid: 5 }));
        let fd = recv_fd(&b).await.unwrap();
        let mut writer = std::fs::File::from(fd);
        writer.write_all(b"through the descriptor").unwrap();
        drop(writer);
        let mut got = String::new();
        pipe_read.read_to_string(&mut got).unwrap();
        assert_eq!(got, "through the descriptor");
        drop(a);
        assert_eq!(read(&mut b).await.unwrap(), None, "a close between messages");
    }

    #[tokio::test]
    async fn mux_protocol_refuses_a_byte_with_no_descriptor_and_a_huge_packet() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&[0]).await.unwrap();
        assert!(recv_fd(&b).await.is_err());
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(read(&mut b).await.is_err());
    }
}
