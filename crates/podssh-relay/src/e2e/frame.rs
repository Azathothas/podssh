//! The frames of the channel: the magic that each end sends first; then a
//! 2-byte length (big-endian) and one Noise message; and the type that leads
//! each message after the handshake.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Error, Refusal, MAGIC, MAX_MESSAGE};

/// The node's verdict on a session.
pub const VERDICT: u8 = 1;
/// Bytes of the session.
pub const DATA: u8 = 2;
/// The clean end of one direction.
pub const END: u8 = 3;

/// The verdicts: let in, or why not.
const LET_IN: u8 = 0;
const NOT_ALLOWED: u8 = 1;
const NO_TARGET: u8 = 2;
const OTHER: u8 = 3;

/// The most bytes of a refusal's reason that travel.
const MAX_REASON: usize = 1024;

/// Read the peer's magic. A peer that sends something else does not speak
/// the channel: no more is read than the magic's length, and what came is
/// named, made safe for a terminal.
pub async fn read_magic<R: AsyncRead + Unpin>(r: &mut R) -> Result<(), Error> {
    let mut got = [0u8; MAGIC.len()];
    let mut n = 0;
    while n < got.len() {
        let k = r.read(&mut got[n..]).await.map_err(Error::Io)?;
        if k == 0 {
            return Err(Error::NotChannel(if n == 0 { "nothing".into() } else { shown(&got[..n]) }));
        }
        n += k;
        if got[..n] != MAGIC[..n] {
            return Err(Error::NotChannel(shown(&got[..n])));
        }
    }
    Ok(())
}

fn shown(bytes: &[u8]) -> String {
    format!("{:?}", podssh_ws::text::one_line(&String::from_utf8_lossy(bytes)))
}

/// Read one frame into `buf`: `Ok(false)` when the stream ended where a
/// frame would start, which the caller judges; an end inside a frame is a
/// cut.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> Result<bool, Error> {
    let mut len = [0u8; 2];
    if r.read(&mut len[..1]).await.map_err(Error::Io)? == 0 {
        return Ok(false);
    }
    r.read_exact(&mut len[1..]).await?;
    let n = usize::from(u16::from_be_bytes(len));
    if n == 0 {
        return Err(Error::Malformed("an empty frame".into()));
    }
    buf.resize(n, 0);
    r.read_exact(buf).await?;
    Ok(true)
}

/// Write one frame: the message's length, then the message.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, message: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(message.len())
        .ok()
        .filter(|n| usize::from(*n) <= MAX_MESSAGE && *n > 0)
        .ok_or_else(|| Error::Malformed(format!("a message of {} bytes", message.len())))?;
    let mut out = Vec::with_capacity(2 + message.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(message);
    w.write_all(&out).await.map_err(Error::Io)?;
    w.flush().await.map_err(Error::Io)
}

/// The body of a verdict.
pub fn verdict(answer: &Result<(), Refusal>) -> Vec<u8> {
    let (code, reason) = match answer {
        Ok(()) => (LET_IN, ""),
        Err(Refusal::NotAllowed) => (NOT_ALLOWED, ""),
        Err(Refusal::NoTarget(why)) => (NO_TARGET, why.as_str()),
        Err(Refusal::Other(why)) => (OTHER, why.as_str()),
    };
    let mut cut = reason.len().min(MAX_REASON);
    while !reason.is_char_boundary(cut) {
        cut -= 1;
    }
    [&[code][..], &reason.as_bytes()[..cut]].concat()
}

/// The answer of a verdict's body; a reason is made safe for a terminal.
pub fn answer(body: &[u8]) -> Result<Result<(), Refusal>, Error> {
    let (&code, reason) = body.split_first().ok_or_else(|| Error::Malformed("an empty verdict".into()))?;
    let reason = || podssh_ws::text::one_line(&String::from_utf8_lossy(reason));
    match code {
        LET_IN => Ok(Ok(())),
        NOT_ALLOWED => Ok(Err(Refusal::NotAllowed)),
        NO_TARGET => Ok(Err(Refusal::NoTarget(reason()))),
        OTHER => Ok(Err(Refusal::Other(reason()))),
        other => Err(Error::Malformed(format!("a verdict of code {other}"))),
    }
}
