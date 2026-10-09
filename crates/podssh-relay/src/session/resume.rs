//! The client's session across links (T-153). When a link is lost, the
//! caller gives a new one (a new relay connection, through any relay host or
//! road), the handshake proves the session's secret, and each side sends
//! again from the other's received offset. SSH above sees no gap.
//!
//! A `CLOSE` or a `REFUSE` ends the session; each other loss is resumed,
//! with a backoff between attempts, until the deadline. The caller decides,
//! from what the transport said (a relay's close code), whether a loss may
//! be resumed at all.

use std::future::Future;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use super::client::{self, Client, ClientError, Outcome};
use super::decode::Decoder;
use super::handshake::{Ask, ClientHandshake, Established, HandshakeError};
use super::pump::{self, Carry, End, Ended};
use super::record::kind;
use super::replay::NotKept;
use super::secret::{Entropy, Secret};
use super::Settings;

/// How long after a loss the session waits for a new link, at both ends:
/// the exit of M6 asks for a stall of 3 minutes to pass, and the backoff
/// adds up to 45 s (the decision of T-153).
pub const RESUME_DEADLINE: Duration = Duration::from_secs(600);

/// What the caller gives in place of a lost link.
pub enum Next<L> {
    /// A new link to the far end, nothing read from it yet.
    Link(L),
    /// No link this time; the driver waits its backoff and asks again.
    Retry(String),
    /// The session must not resume, for this reason (a close that says so).
    Stop(String),
}

/// A step of the session across links, each worth one line to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// The link was lost; the session waits for a new one.
    Lost { why: String },
    /// An attempt failed; the next comes after `wait`.
    Retry { why: String, wait: Duration },
    /// A new link carries the session, `resent` bytes sent again.
    Resumed { resent: u64, after: Duration },
}

/// Why a resume on a new link failed.
#[derive(Debug)]
enum Failed {
    /// Worth another attempt: the link failed, or took too long.
    Again(String),
    /// The far end cannot resume the session.
    Final(String),
}

/// Carry the session of `client` between `app` and its links until it ends.
/// `connect` is asked for a new link after each loss, with the end of the
/// lost one; `note` hears of each loss, attempt and resume. With no layer at
/// the far end, the bytes pass as they are, on the first link only.
pub async fn run<L, A, C, F, N>(
    client: Client<L>,
    mut app: A,
    mut connect: C,
    mut note: N,
    entropy: &mut (dyn Entropy + Send),
) -> Outcome
where
    L: AsyncRead + AsyncWrite + Unpin + Send,
    A: AsyncRead + AsyncWrite + Unpin + Send,
    C: FnMut(&Ended) -> F,
    F: Future<Output = Next<L>>,
    N: FnMut(Note),
{
    let parts = client.into_parts();
    let Some((mut decoder, established)) = parts.layer else {
        return Client::from_parts(parts).run(app).await;
    };
    let settings = parts.settings;
    let mut link = parts.link;
    let mut carry = Carry::new(settings.link(&established));
    loop {
        let ended = pump::run(&mut app, link, decoder, &mut carry, None).await;
        if !ended.end.resumable() {
            let _ = app.shutdown().await;
            return Outcome::Layer(ended);
        }
        note(Note::Lost { why: describe(&ended.end) });
        let lost = Instant::now();
        let deadline = lost + settings.resume_deadline;
        let mut attempt = 0u32;
        let next = loop {
            attempt += 1;
            let why = match tokio::time::timeout_at(deadline, connect(&ended)).await {
                Err(_) => break Err(format!("no new link within {} s", settings.resume_deadline.as_secs())),
                Ok(Next::Stop(reason)) => break Err(reason),
                Ok(Next::Retry(why)) => why,
                Ok(Next::Link(new)) => {
                    let limit = client::HANDSHAKE_LIMIT.min(deadline.saturating_duration_since(Instant::now()));
                    match tokio::time::timeout(limit, resume_on(new, &established, &carry, settings, entropy)).await {
                        Ok(Ok(resumed)) => break Ok(resumed),
                        Ok(Err(Failed::Final(reason))) => break Err(reason),
                        Ok(Err(Failed::Again(why))) => why,
                        Err(_) => format!("the handshake took more than {} s", limit.as_secs()),
                    }
                }
            };
            let wait = crate::open::backoff(attempt);
            if Instant::now() + wait >= deadline {
                break Err(format!("no new link within {} s: {why}", settings.resume_deadline.as_secs()));
            }
            note(Note::Retry { why, wait });
            tokio::time::sleep(wait).await;
        };
        match next {
            Ok((new, new_decoder, resent)) => {
                note(Note::Resumed { resent, after: lost.elapsed() });
                link = new;
                decoder = new_decoder;
            }
            Err(reason) => {
                let _ = app.shutdown().await;
                return Outcome::Layer(Ended { end: End::GaveUp(reason), received: ended.received, sent: ended.sent });
            }
        }
    }
}

/// A loss, in words.
fn describe(end: &End) -> String {
    match end {
        End::Lost(Some(e)) => format!("the link failed: {e}"),
        End::Lost(None) => "the link ended with no word from the far end".to_string(),
        End::Broken(e) => format!("the link broke: {e}"),
        End::Stopped => "the link was replaced".to_string(),
        End::LocalEnd | End::Closed(_) | End::GaveUp(_) => "the session ended".to_string(),
    }
}

/// The handshake of a resume on `link`, and the bytes to send again: the
/// new link and its decoder, and the count sent again.
async fn resume_on<L>(
    mut link: L,
    established: &Established,
    carry: &Carry,
    settings: Settings,
    entropy: &mut (dyn Entropy + Send),
) -> Result<(L, Decoder, u64), Failed>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let received = carry.state.lock().unwrap_or_else(|e| e.into_inner()).received();
    let ask = Ask::Resume { id: established.id, secret: Secret::from_bytes(*established.secret.bytes()), received };
    let (handshake, open) = ClientHandshake::start(ask, settings.features, entropy)
        .map_err(|e| Failed::Final(format!("the resume could not start: {e}")))?;
    // The far end greets first, as on the first link.
    let mut buf = vec![0u8; 64 * 1024];
    let n = link.read(&mut buf).await.map_err(|e| Failed::Again(format!("the new link failed: {e}")))?;
    if n == 0 {
        return Err(Failed::Again("the new link ended before the far end greeted".into()));
    }
    if buf[0] != kind::GREETING {
        return Err(Failed::Final("the far end no longer offers the resumable layer".into()));
    }
    let mut decoder = Decoder::new();
    decoder.push(&buf[..n]);
    let resumed = match client::shake(&mut link, &mut decoder, handshake, open, &mut buf).await {
        Ok(resumed) => resumed,
        Err(ClientError::Handshake(e @ (HandshakeError::Refused { .. } | HandshakeError::BadProof))) => {
            return Err(Failed::Final(format!("the far end did not resume the session: {e}")))
        }
        Err(e) => return Err(Failed::Again(e.to_string())),
    };
    let mut again = Vec::new();
    let resent = carry.state.lock().unwrap_or_else(|e| e.into_inner()).resume(resumed.peer_received, &mut again);
    let resent = match resent {
        Ok(resent) => resent,
        Err(not_kept) => return Err(not_kept_end(&mut link, not_kept).await),
    };
    link.write_all(&again).await.map_err(|e| Failed::Again(format!("the new link failed: {e}")))?;
    Ok((link, decoder, resent))
}

/// The far end asks for bytes that this side no longer keeps: the session
/// cannot go on, and the far end hears why.
async fn not_kept_end<L: AsyncWrite + Unpin>(link: &mut L, not_kept: NotKept) -> Failed {
    let _ = client::send(link, &not_kept.refusal()).await;
    Failed::Final(not_kept.to_string())
}
