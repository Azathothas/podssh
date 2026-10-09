//! The far end of the layer over tokio streams: a node or `podssh serve`,
//! between a link from the relay and the target of the session.
//!
//! [`accept`] greets the client and runs the handshake, and only then does
//! the caller connect to the target, so that a link that never completes its
//! handshake costs no connection to sshd (T-164).

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::decode::{DecodeError, Decoder};
use super::handshake::{Established, FarHandshake, HandshakeError, Sessions, Step};
use super::link::Link;
use super::pump::{self, Ended};
use super::record::{Record, Role};
use super::secret::Entropy;
use super::Settings;

/// How long the client may take to open or resume a session.
pub const HANDSHAKE_LIMIT: Duration = Duration::from_secs(30);

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
    let established = match shaken.await {
        Ok(result) => result?,
        Err(_) => return Err(FarError::Timeout),
    };
    Ok(Accepted { link, decoder, established, settings })
}

async fn shake<L>(
    link: &mut L,
    decoder: &mut Decoder,
    mut handshake: FarHandshake,
    sessions: &Mutex<Sessions>,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Box<Established>, FarError>
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
                    if let Some(accept) = accept {
                        send(link, &accept).await?;
                    }
                    return Ok(established);
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

impl<L> Accepted<L>
where
    L: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// The session that the link carries. Its secret is never for a message.
    pub fn established(&self) -> &Established {
        &self.established
    }

    /// Carry the session between the target `app` and the link until either
    /// ends. The far end's received offset goes back to `sessions`, for a
    /// resume.
    pub async fn run<A>(self, app: A, sessions: &Mutex<Sessions>) -> Ended
    where
        A: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let Accepted { link, decoder, established, settings } = self;
        let state: Arc<Mutex<Link>> = Arc::new(Mutex::new(settings.link(&established)));
        let ended = pump::run(app, link, decoder, state).await;
        let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.set_received(&established.id, ended.received);
        ended
    }
}
