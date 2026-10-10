//! The `-W` byte pipe: stdin↔stream, bytes only on stdout.
//!
//! Diagnostics never touch stdout — the caller owns the streams, and this
//! function only returns counts. A framing byte on stdout would corrupt the
//! stream for anything downstream (`ssh -o ProxyCommand`), so the byte
//! equality is pinned in `tests/pipe.rs`, not trusted to review.

use std::cell::Cell;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How long the pipe reads on after the end of stdin while the stream sends
/// nothing: the relay's own rule for a half-closed forward session, which it
/// closes after 15 s with no byte from the target. A request on stdin gets its
/// reply, and a peer that never closes does not hold the pipe.
pub const IDLE_AFTER_EOF: Duration = Duration::from_secs(15);

/// One read of either leg.
const CHUNK: usize = 16 * 1024;

/// Copy both directions until EOF on either side. Returns `(to_remote,
/// from_remote)` byte counts. Any I/O error aborts with the error — a
/// half-open pipe is a failure, not a partial success.
///
/// A leg here must be both readable AND writable, which stdin is not —
/// so `-W` does not use this function. It uses [`pipe_streams`] below, and
/// this one stays for duplex-shaped ends (its tests pin the byte equality).
pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(a, b).await
}

/// Why a `-W` pipe ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The stream ended.
    RemoteEof,
    /// stdout's reader left: a clean end, as for `podssh proxy`.
    StdoutClosed,
    /// After the end of stdin, the stream sent nothing for
    /// [`IDLE_AFTER_EOF`].
    Idle,
}

/// How a `-W` pipe ended: the bytes of each direction, exact, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipeEnds {
    /// Bytes stdin→stream.
    pub up: u64,
    /// Bytes stream→stdout.
    pub down: u64,
    /// stdin ended, and the stream's write half was shut down.
    pub local_eof: bool,
    /// Why the pipe ended.
    pub end: End,
}

/// Shuttle `local_r → stream → local_w`.
///
/// The local side stays split (read + write halves) because stdin is not
/// writable and stdout is not readable. At the end of stdin the stream's
/// write half is shut down (a clean FIN to the remote), and the pipe reads
/// on, so a reply that comes after the request is delivered, as `podssh
/// proxy` and the relay's forward road deliver it. The pipe ends when the
/// stream ends, when stdout closes, or, once stdin has ended, when the
/// stream sends nothing for [`IDLE_AFTER_EOF`]: an earlier revision waited
/// with no limit and hung whenever the remote never closed — measured, 30 s
/// timeout, exit 124.
pub async fn pipe_streams<LR, LW, S>(local_r: &mut LR, local_w: &mut LW, stream: S) -> io::Result<PipeEnds>
where
    LR: AsyncRead + Unpin,
    LW: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    // Counted as the bytes go, so a leg that the end drops mid-copy still
    // reports what it moved.
    let up = Cell::new(0u64);
    let up_leg = async {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = local_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            wr.write_all(&buf[..n]).await?;
            up.set(up.get() + n as u64);
        }
        wr.shutdown().await
    };
    tokio::pin!(up_leg);
    let mut local_eof = false;
    let mut down = 0u64;
    let mut buf = vec![0u8; CHUNK];
    let end = loop {
        // A new limit for each wait: each byte from the stream restarts it.
        let eof = local_eof;
        let idle = async move {
            if eof {
                tokio::time::sleep(IDLE_AFTER_EOF).await
            } else {
                std::future::pending::<()>().await
            }
        };
        tokio::select! {
            r = &mut up_leg, if !local_eof => {
                r?;
                local_eof = true;
            }
            r = rd.read(&mut buf) => {
                let n = r?;
                if n == 0 {
                    break End::RemoteEof;
                }
                match write_out(local_w, &buf[..n]).await {
                    Ok(()) => down += n as u64,
                    Err(e) if closed(&e) => break End::StdoutClosed,
                    Err(e) => return Err(e),
                }
            }
            () = idle => break End::Idle,
        }
    };
    Ok(PipeEnds { up: up.get(), down, local_eof, end })
}

/// Write and flush: a byte that waits in a buffer has not been delivered.
async fn write_out<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    w.write_all(bytes).await?;
    w.flush().await
}

/// A write error that means stdout's reader left — EPIPE on Unix, and on
/// Windows a pipe being closed, which Rust names `BrokenPipe` too: the end
/// of the pipe, not a failure.
fn closed(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
}
