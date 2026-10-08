//! The `-W` byte pipe: stdin↔stream until EOF, bytes only on stdout.
//!
//! ⛔ Diagnostics never touch stdout — the caller owns the streams, and this
//! function only returns counts. A framing byte on stdout would corrupt the
//! stream for anything downstream (`ssh -o ProxyCommand`), so the byte
//! equality is pinned in `tests/pipe.rs`, not trusted to review.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Copy both directions until EOF on either side. Returns `(to_remote,
/// from_remote)` byte counts. Any I/O error aborts with the error — a
/// half-open pipe is a failure, not a partial success.
///
/// ⛔ A leg here must be both readable AND writable, which stdin is not —
/// so `-W` does not use this function. It uses [`pipe_streams`] below, and
/// this one stays for duplex-shaped ends (its tests pin the byte equality).
pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(a, b).await
}

/// Which direction ended the pipe first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstEnd {
    /// Local stdin hit EOF first (the normal `-W` ending).
    LocalEof,
    /// The remote stream hit EOF first.
    RemoteEof,
}

/// How a `-W` pipe ended: per-direction byte counts (`None` when that
/// direction did not run to EOF) and which end finished first.
///
/// ⛔ `down: None` does NOT mean zero bytes arrived: when local EOF wins,
/// the down leg is cancelled mid-drain, and bytes it already delivered to
/// local stdout are real but uncounted. `None` means "incomplete", and the
/// count beside it is the only number reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipeEnds {
    /// Bytes local→remote, or `None` when the remote ended first.
    pub up: Option<u64>,
    /// Bytes remote→local, or `None` when the local side ended first.
    pub down: Option<u64>,
    /// Which end finished first.
    pub first: FirstEnd,
}

/// Shuttle `local_r → stream → local_w` until either direction ends.
///
/// The local side stays split (read + write halves) because stdin is not
/// writable and stdout is not readable. First completion wins, faithful to
/// `ssh` ProxyCommand semantics: on local EOF the stream's write half is
/// shut down (clean FIN to the remote) and the pipe returns at once — the
/// down leg is cancelled mid-drain and reported `down: None`. On remote EOF
/// first the pipe returns with `up: None`. A peer that never closes holds
/// the pipe — `ssh` kills its ProxyCommand on session end, so the
/// supervisor bounds it, and that bound is named here rather than hidden
/// behind a grace constant nobody measured.
pub async fn pipe_streams<LR, LW, S>(
    local_r: &mut LR,
    local_w: &mut LW,
    stream: S,
) -> std::io::Result<PipeEnds>
where
    LR: AsyncRead + Unpin,
    LW: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let up_fut = async {
        let n = tokio::io::copy(local_r, &mut wr).await?;
        wr.shutdown().await?;
        Ok::<u64, std::io::Error>(n)
    };
    let down_fut = async { tokio::io::copy(&mut rd, local_w).await };
    tokio::pin!(up_fut);
    tokio::pin!(down_fut);
    // ⛔ No `down_fut.await` on the up-win arm: the down leg can only finish
    // on stream EOF, and awaiting it here reintroduces the exact hang this
    // function exists to avoid (the losing future is cancelled by the
    // select). An earlier revision awaited it and hung forever whenever the
    // remote never closed — measured, 30 s timeout, exit 124.
    let ends = tokio::select! {
        r = &mut up_fut => {
            let up = r?;
            PipeEnds { up: Some(up), down: None, first: FirstEnd::LocalEof }
        }
        r = &mut down_fut => {
            let down = r?;
            PipeEnds { up: None, down: Some(down), first: FirstEnd::RemoteEof }
        }
    };
    Ok(ends)
}
