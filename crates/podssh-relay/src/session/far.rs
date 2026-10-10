//! The far end of the layer over tokio streams: a node or `podssh serve`,
//! between a link from the relay and the target of the session.
//!
//! [`accept`] greets the client and runs the handshake, and only then does
//! the caller connect to the target, so that a link that never completes its
//! handshake costs no connection to sshd (T-164). [`serve`] is the whole of
//! one link of a far end that keeps its sessions: each road's far end (the
//! node of the reverse road, the iroh road) runs it.

use std::fmt;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::decode::{DecodeError, Decoder};
use super::handshake::{Established, FarHandshake, HandshakeError, Step};
use super::keep::Keeper;
use super::pump::{self, Carry, Ended};
use super::record::{Record, Role};
use super::secret::{Entropy, OsEntropy};
use super::sessions::Sessions;
use super::Settings;

/// How long the client may take to open or resume a session.
pub const HANDSHAKE_LIMIT: Duration = Duration::from_secs(30);
/// How long a new session's target may take to answer.
pub const TARGET_LIMIT: Duration = Duration::from_secs(10);

/// Why the far end could not accept the link.
#[derive(Debug)]
pub enum FarError {
    /// The link failed or ended in the handshake.
    Io(std::io::Error),
    /// The client sent bytes that are not records of the layer.
    Decode(DecodeError),
    /// The handshake failed; a `REFUSE` went out when it could.
    Handshake(HandshakeError),
    /// The handshake took longer than [`HANDSHAKE_LIMIT`].
    Timeout,
}

impl fmt::Display for FarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FarError::Io(e) => write!(f, "the link failed in the layer's handshake: {e}"),
            FarError::Decode(e) => write!(f, "the client sent {e} in the layer's handshake"),
            FarError::Handshake(e) => write!(f, "the layer's handshake failed: {e}"),
            FarError::Timeout => write!(f, "the layer's handshake took more than {} s", HANDSHAKE_LIMIT.as_secs()),
        }
    }
}

impl std::error::Error for FarError {}

/// A link whose client opened or resumed a session.
pub struct Accepted<L> {
    link: L,
    decoder: Decoder,
    established: Box<Established>,
    settings: Settings,
    /// A resume's number, in the order of the handshakes; 0 for a new
    /// session.
    resume: u64,
}

/// Greet the client on `link`, and accept the session that it opens or
/// resumes, by the sessions that this far end keeps.
pub async fn accept<L>(
    mut link: L,
    role: Role,
    settings: Settings,
    sessions: &Mutex<Sessions>,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Accepted<L>, FarError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let (handshake, greeting) = FarHandshake::start(role, settings.features, entropy).map_err(FarError::Handshake)?;
    send(&mut link, &greeting).await?;
    let mut decoder = Decoder::new();
    let shaken = tokio::time::timeout(HANDSHAKE_LIMIT, shake(&mut link, &mut decoder, handshake, sessions, entropy));
    let (established, resume) = match shaken.await {
        Ok(result) => result?,
        Err(_) => return Err(FarError::Timeout),
    };
    Ok(Accepted { link, decoder, established, settings, resume })
}

async fn shake<L>(
    link: &mut L,
    decoder: &mut Decoder,
    mut handshake: FarHandshake,
    sessions: &Mutex<Sessions>,
    entropy: &mut (dyn Entropy + Send),
) -> Result<(Box<Established>, u64), FarError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        while let Some(record) = decoder.next().map_err(FarError::Decode)? {
            let step = {
                let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
                handshake.handle(record, &mut sessions, entropy).map_err(FarError::Handshake)?
            };
            match step {
                Step::Send(record) => send(link, &record).await?,
                Step::Wait => {}
                Step::Established(accept, established) => {
                    // A resume's place is set before its answer goes out:
                    // the task that runs it may start late, after a newer
                    // resume of the same client.
                    let resume = if established.resumed {
                        sessions.lock().unwrap_or_else(|e| e.into_inner()).next_resume()
                    } else {
                        0
                    };
                    if let Some(accept) = accept {
                        send(link, &accept).await?;
                    }
                    return Ok((established, resume));
                }
                Step::Refuse(refusal, error) => {
                    // The client reads why before the link ends.
                    let _ = send(link, &refusal).await;
                    let _ = link.shutdown().await;
                    return Err(FarError::Handshake(error));
                }
            }
        }
        match link.read(&mut buf).await {
            Ok(0) => return Err(FarError::Io(std::io::ErrorKind::UnexpectedEof.into())),
            Ok(n) => decoder.push(&buf[..n]),
            Err(e) => return Err(FarError::Io(e)),
        }
    }
}

async fn send<L: AsyncWrite + Unpin>(link: &mut L, record: &Record) -> Result<(), FarError> {
    let bytes = record.to_bytes().map_err(|e| FarError::Io(std::io::Error::other(e)))?;
    link.write_all(&bytes).await.map_err(FarError::Io)?;
    link.flush().await.map_err(FarError::Io)
}

/// One link of a far end that keeps its sessions in `keeper`: the layer's
/// handshake, then a resume goes on with the target that its session kept,
/// and a new session reaches its target with `open`. A new session that
/// would pass `budget` bytes of replay buffers, or whose target cannot be
/// reached, ends at once with the reason (T-153).
pub async fn serve<L, A, O, F>(link: L, role: Role, settings: Settings, keeper: &Keeper<A>, budget: usize, open: O)
where
    L: AsyncRead + AsyncWrite + Unpin + Send,
    A: AsyncRead + AsyncWrite + Unpin + Send,
    O: FnOnce() -> F,
    F: Future<Output = Result<A, String>>,
{
    let accepted = match accept(link, role, settings, &keeper.sessions, &mut OsEntropy).await {
        Ok(accepted) => accepted,
        // A link that never completed its handshake: nothing to keep.
        Err(_) => return,
    };
    if accepted.established().resumed {
        let _ = keeper.run_resumed(accepted).await;
        return;
    }
    // A new session holds a whole buffer's worth of the budget while it is
    // kept, so the budget is a bound, not a hope.
    let held = keeper.kept().saturating_mul(settings.replay_capacity);
    if held.saturating_add(settings.replay_capacity) > budget {
        let reason = format!(
            "this node keeps as many resumable sessions as its budget allows ({} MiB of replay buffers)",
            budget >> 20
        );
        accepted.close(&reason, &keeper.sessions).await;
        return;
    }
    match tokio::time::timeout(TARGET_LIMIT, open()).await {
        Ok(Ok(target)) => {
            keeper.run_new(accepted, target).await;
        }
        Ok(Err(why)) => {
            let reason = format!("the node could not reach its target: {why}");
            accepted.close(&reason, &keeper.sessions).await;
        }
        Err(_) => {
            let reason = format!("the node's target did not answer within {} s", TARGET_LIMIT.as_secs());
            accepted.close(&reason, &keeper.sessions).await;
        }
    }
}

impl<L> Accepted<L>
where
    L: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// The session that the link carries. Its secret is never for a message.
    pub fn established(&self) -> &Established {
        &self.established
    }

    pub(crate) fn into_parts(self) -> (L, Decoder, Box<Established>, Settings) {
        (self.link, self.decoder, self.established, self.settings)
    }

    /// The resume's number, in the order of the handshakes; 0 for a new
    /// session.
    pub(crate) fn resume(&self) -> u64 {
        self.resume
    }

    /// End the session at once, with `reason` in a `CLOSE` (its target could
    /// not be reached, or the far end keeps as many sessions as it can): the
    /// session is forgotten, and the client ends with the reason.
    pub async fn close(self, reason: &str, sessions: &Mutex<Sessions>) {
        let Accepted { mut link, established, .. } = self;
        sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&established.id);
        let close = Record::Close { reason: super::record::cut_reason(reason) };
        if let Ok(bytes) = close.to_bytes() {
            let _ = link.write_all(&bytes).await;
        }
        let _ = link.shutdown().await;
    }

    /// Carry the session between the target `app` and the link until either
    /// ends. The far end's received offset goes back to `sessions`, for a
    /// resume.
    pub async fn run<A>(self, app: A, sessions: &Mutex<Sessions>) -> Ended
    where
        A: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let Accepted { link, decoder, established, settings, .. } = self;
        let mut carry = Carry::new(settings.link(&established));
        let mut app = app;
        let ended = pump::run(&mut app, link, decoder, &mut carry, &pump::Watch::default()).await;
        // The target learns that no more bytes come.
        let _ = app.shutdown().await;
        let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.set_received(&established.id, ended.received);
        ended
    }
}
