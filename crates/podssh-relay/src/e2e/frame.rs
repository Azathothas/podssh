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
/// The net's document (T-429), between two ends that said they read it.
pub const NET: u8 = 4;

/// The verdicts: let in, or why not.
const LET_IN: u8 = 0;
const NOT_ALLOWED: u8 = 1;
const NO_TARGET: u8 = 2;
const OTHER: u8 = 3;

/// The most bytes of a refusal's reason that travel.
const MAX_REASON: usize = 1024;

/// An item after the code of a verdict that lets in, its kind and its length
/// in a byte each, then its bytes: the seed of the session's tokens of one
/// leg (T-615). A podssh of before reads nothing past the code.
const SEED: u8 = 1;

/// Read the peer's magic. A peer that sends something else does not speak
/// the channel: no more is read than the magic's length, and what came is
/// named, made safe for a terminal.
pub async fn read_magic<R: AsyncRead + Unpin>(r: &mut R) -> Result<(), Error> {
    let mut got = [0u8; MAGIC.len()];
    let mut n = 0;
    while n < got.len() {
        let k = r.read(&mut got[n..]).await.map_err(Error::Io)?;
        if k == 0 {
            // An end with nothing but the magic's start is a cut, whose reason
            // is the road's (a refused key, a lost link): this peer said
            // nothing that is not the channel's.
            return Err(Error::Cut);
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
    verdict_with(answer, None)
}

/// [`verdict`], with `seed` after the code of one that lets in: the seed of
/// the session's tokens of one leg (T-615). A refusal carries none.
pub fn verdict_with(answer: &Result<(), Refusal>, seed: Option<&[u8; 32]>) -> Vec<u8> {
    if let (Ok(()), Some(seed)) = (answer, seed) {
        return [&[LET_IN, SEED, 32][..], &seed[..]].concat();
    }
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

/// The seed that a verdict which lets in carries among its items (T-615); an
/// item of another kind is set aside, as a later podssh may add one.
pub fn seed_of(body: &[u8]) -> Option<[u8; 32]> {
    let (&code, mut rest) = body.split_first()?;
    if code != LET_IN {
        return None;
    }
    while let [kind, len, tail @ ..] = rest {
        let (value, after) = tail.split_at_checked(usize::from(*len))?;
        if *kind == SEED {
            return value.try_into().ok();
        }
        rest = after;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-615: a verdict that lets in with a seed reads as one that lets in to
    /// a podssh of before, which reads the code alone, and gives its seed to
    /// one that reads it; a refusal carries none.
    #[test]
    fn a_seed_rides_after_the_code_of_a_verdict_that_lets_in() {
        let seed = [9u8; 32];
        let body = verdict_with(&Ok(()), Some(&seed));
        assert_eq!(answer(&body).unwrap(), Ok(()), "a podssh of before lets the session in");
        assert_eq!(seed_of(&body), Some(seed));
        assert_eq!(seed_of(&verdict(&Ok(()))), None, "a verdict of before");
        let refused = verdict_with(&Err(Refusal::NotAllowed), Some(&seed));
        assert_eq!((answer(&refused).unwrap(), seed_of(&refused)), (Err(Refusal::NotAllowed), None));
        // An item of a later kind first, then the seed.
        let later = [&[LET_IN, 7, 2, 0, 0, SEED, 32][..], &seed[..]].concat();
        assert_eq!(seed_of(&later), Some(seed));
        assert_eq!(seed_of(&[LET_IN, SEED, 32, 1, 2]), None, "a seed cut short");
    }
}
