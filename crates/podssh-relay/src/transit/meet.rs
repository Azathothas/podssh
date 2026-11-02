//! A meeting at the transit relay (T-436): this end's line, the relay's
//! answer, then podssh's own words each way through the relay's copy: a
//! hello with this end's part and a nonce, then a proof of the pair's
//! secret over both nonces. The relay pairs any two sides of one token, so
//! two clients of one pair can meet each other: their parts tell them
//! apart. The relay sees the token; a side that knows it alone, as the
//! relay does, proves nothing, so the node's door stays the pair's.
//!
//! The relay's words (magic-wormhole/magic-wormhole-transit-relay:
//! src/wormhole_transit_relay/transit_server.py and server_state.py): the
//! first message is the line alone; `ok\n` once a second side of the token
//! came; `bad handshake\n` for a line that it does not read; `impatient\n`
//! for bytes sent before `ok`. Over a WebSocket each message is binary, and
//! where one ends means nothing, so the answers are read as bytes.

use std::fmt;
use std::time::Duration;

use podssh_ws::session::close_code_and_reason;
use podssh_ws::{frame, RelaySession, SessionError};
use tokio::io::{AsyncRead, AsyncWrite};

use super::token::{line, Keys, Side, PROOF_BYTES};
use crate::session::secret::Entropy;

/// The version of podssh's words after `ok`.
pub const VERSION: u8 = 1;
/// The bytes of a nonce.
pub const NONCE: usize = 32;
/// A hello: the version, the part, the nonce.
pub const HELLO: usize = 2 + NONCE;
/// The longest answer of the relay that is read for its newline.
const ANSWER_MOST: usize = 256;
/// How long the hello and the proof of a peer that met this end may take.
pub const PROOF_LIMIT: Duration = Duration::from_secs(10);

/// Which end of a pair's road this one is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Node,
    Client,
}

impl Part {
    /// The byte of the part in a hello and a proof.
    pub fn byte(self) -> u8 {
        match self {
            Part::Node => b'N',
            Part::Client => b'C',
        }
    }

    pub fn other(self) -> Part {
        match self {
            Part::Node => Part::Client,
            Part::Client => Part::Node,
        }
    }
}

/// Why a meeting gave no link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missed {
    /// No other side of the token came within the wait.
    Alone(Duration),
    /// The relay ended the connection before `ok`: a spare side of the
    /// token, which it drops once another one met, or a limit of its own.
    Dropped(String),
    /// The relay refused the line, or answered words that are not its.
    Refused(String),
    /// A peer of this end's own part met it: two clients of one pair.
    SamePart,
    /// The peer did not prove the pair: a side that knows the token alone,
    /// or the end of another pair whose token is the same.
    NotProven(String),
    /// The connection failed, or the peer said nothing in time.
    Broken(String),
}

impl fmt::Display for Missed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Missed::Alone(wait) => write!(f, "no other side came within {} s", wait.as_secs()),
            Missed::Dropped(why) => write!(f, "the relay ended the connection before the meeting: {why}"),
            Missed::Refused(why) | Missed::Broken(why) => f.write_str(why),
            Missed::SamePart => f.write_str("another client of the pair met this one"),
            Missed::NotProven(why) => write!(f, "the peer did not prove the pair: {why}"),
        }
    }
}

/// Meet the other end at the relay over `session`, as `part`, waiting at
/// most `wait` for it (`None`: as long as the connection lives): the bytes
/// that came after the peer's proof, which are the first of the link.
pub async fn meet<S>(
    session: &RelaySession<S>,
    keys: &Keys,
    side: &Side,
    part: Part,
    wait: Option<Duration>,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Vec<u8>, Missed>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let mut nonce = [0u8; NONCE];
    entropy.fill(&mut nonce).map_err(|e| Missed::Broken(e.to_string()))?;
    // The line alone in its message: the relay reads the first message as
    // the line, and refuses one with more.
    session.send_binary(line(keys, side).as_bytes()).await.map_err(broken)?;
    let mut got = Got { bytes: Vec::new() };
    let answer = match wait {
        Some(wait) => tokio::time::timeout(wait, got.line(session)).await.map_err(|_| Missed::Alone(wait))??,
        None => got.line(session).await?,
    };
    match answer.as_str() {
        "ok" => {}
        "bad handshake" => return Err(Missed::Refused("the relay did not take the line (bad handshake)".into())),
        "impatient" => {
            return Err(Missed::Refused("the relay took bytes before its ok for a fault (impatient)".into()))
        }
        other => {
            let shown: String = podssh_ws::text::one_line(other).chars().take(60).collect();
            return Err(Missed::Refused(format!("the relay answered {shown:?}, not ok")));
        }
    }
    let mut hello = Vec::with_capacity(HELLO);
    hello.extend_from_slice(&[VERSION, part.byte()]);
    hello.extend_from_slice(&nonce);
    session.send_binary(&hello).await.map_err(broken)?;
    let theirs = got.within(session, HELLO).await?;
    if theirs[0] != VERSION {
        let why = format!("its words are of version {}, and this podssh's of {VERSION}", theirs[0]);
        return Err(Missed::NotProven(why));
    }
    if theirs[1] == part.byte() {
        return Err(Missed::SamePart);
    }
    if theirs[1] != part.other().byte() {
        return Err(Missed::NotProven("its hello is not podssh's".into()));
    }
    let peer = &theirs[2..];
    session.send_binary(&keys.prove(part.byte(), &nonce, peer)).await.map_err(broken)?;
    let proof = got.within(session, PROOF_BYTES).await?;
    if !keys.verify(part.other().byte(), peer, &nonce, &proof) {
        return Err(Missed::NotProven("its proof is not of this pair's secret".into()));
    }
    Ok(got.bytes)
}

fn broken(e: SessionError) -> Missed {
    Missed::Broken(e.to_string())
}

/// The bytes that came, and are not read yet.
struct Got {
    bytes: Vec<u8>,
}

impl Got {
    /// The relay's answer: a line, without its newline.
    async fn line<S>(&mut self, session: &RelaySession<S>) -> Result<String, Missed>
    where
        S: AsyncRead + AsyncWrite + Send,
    {
        loop {
            if let Some(at) = self.bytes.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.bytes.drain(..=at).collect();
                return Ok(String::from_utf8_lossy(&line[..at]).trim_end_matches('\r').to_string());
            }
            if self.bytes.len() > ANSWER_MOST {
                return Err(Missed::Refused(format!("the relay answered {} bytes with no newline", self.bytes.len())));
            }
            self.more(session).await?;
        }
    }

    /// `n` bytes of the peer, within [`PROOF_LIMIT`].
    async fn within<S>(&mut self, session: &RelaySession<S>, n: usize) -> Result<Vec<u8>, Missed>
    where
        S: AsyncRead + AsyncWrite + Send,
    {
        let read = async {
            while self.bytes.len() < n {
                self.more(session).await?;
            }
            Ok::<Vec<u8>, Missed>(self.bytes.drain(..n).collect())
        };
        let late = || Missed::Broken(format!("the peer said too little within {} s", PROOF_LIMIT.as_secs()));
        tokio::time::timeout(PROOF_LIMIT, read).await.map_err(|_| late())?
    }

    /// The next message's bytes; the connection pinged meanwhile, so that a
    /// dead one is found while this end waits.
    async fn more<S>(&mut self, session: &RelaySession<S>) -> Result<(), Missed>
    where
        S: AsyncRead + AsyncWrite + Send,
    {
        let liveness = session.watch_liveness(podssh_ws::LIVENESS_EVERY, podssh_ws::LIVENESS_ALLOWED);
        let read = tokio::select! {
            read = session.read_frame() => read,
            dead = liveness => return Err(Missed::Broken(dead.to_string())),
        };
        let f = match read {
            Ok(f) => f,
            Err(SessionError::ClosedWithoutClose(why)) => return Err(Missed::Dropped(why)),
            Err(e) => return Err(broken(e)),
        };
        match f.opcode {
            frame::OPCODE_BINARY | frame::OPCODE_TEXT => {
                self.bytes.extend_from_slice(&f.payload);
                Ok(())
            }
            frame::OPCODE_CLOSE => {
                let (code, reason) = close_code_and_reason(&f.payload);
                let code = code.map_or_else(|| "no code".to_string(), |c| c.to_string());
                let reason = match reason.is_empty() {
                    true => String::new(),
                    false => format!(" {}", podssh_ws::text::one_line(&reason)),
                };
                Err(Missed::Dropped(format!("a Close ({code}{reason})")))
            }
            other => Err(Missed::Broken(format!("an unexpected frame (opcode {other:#x})"))),
        }
    }
}
