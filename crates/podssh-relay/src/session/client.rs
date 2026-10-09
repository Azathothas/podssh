//! The client's end of the layer over tokio streams: between the pipe that
//! SSH reads and writes, and the link to the far end.
//!
//! On the reverse road the client cannot know whether the node speaks the
//! layer, so it sends nothing until the far end's first byte. A `GREETING`
//! starts with a byte that no line of text does; an SSH server sends its
//! version line first (RFC 4253, section 4.2). With no `GREETING`, the bytes
//! pass both ways as they are, as before the layer.

use std::fmt;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::decode::{DecodeError, Decoder};
use super::handshake::{Ask, ClientHandshake, Established, HandshakeError, Step};
use super::link::Link;
use super::pump::{self, Ended};
use super::record::{kind, Record, Role};
use super::secret::{Entropy, SessionId};

/// How long the client waits for the far end's first byte: longer than the
/// operator leg waits for the node's `ready` (20 s), after which the first
/// byte comes. A server behind a protocol multiplexer can wait for the
/// client to speak first; it then gets the client's bytes after this wait,
/// with no layer.
pub const FIRST_BYTE_WAIT: Duration = Duration::from_secs(30);
/// How long the handshake may take once `GREETING` began.
pub const HANDSHAKE_LIMIT: Duration = Duration::from_secs(30);

/// What the client found at the far end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// No layer: the bytes pass as they are. `first` is the far end's first
    /// byte, or `None` when it sent none within the wait.
    Plain { first: Option<u8> },
    /// The layer carries the session.
    Layer { id: SessionId, peer_role: Role, features: Vec<String>, resumed: bool },
}

impl fmt::Display for Found {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Found::Plain { first: Some(_) } => f.write_str("the far end offers no resumable layer"),
            Found::Plain { first: None } => {
                f.write_str("the far end sent nothing first, so the session runs with no resumable layer")
            }
            Found::Layer { id, peer_role, resumed: false, .. } => {
                write!(f, "the far end ({peer_role}) opened resumable session {}", id.short())
            }
            Found::Layer { id, peer_role, resumed: true, .. } => {
                write!(f, "the far end ({peer_role}) resumed session {}", id.short())
            }
        }
    }
}

/// Why the client could not start the session.
#[derive(Debug)]
pub enum ClientError {
    /// The link failed or ended before the layer was established.
    Io(std::io::Error),
    /// The far end's first bytes are neither text nor the layer's records.
    Decode(DecodeError),
    /// The handshake failed.
    Handshake(HandshakeError),
    /// The handshake took longer than [`HANDSHAKE_LIMIT`].
    Timeout,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "the link failed in the layer's handshake: {e}"),
            ClientError::Decode(e) => write!(f, "the far end sent {e} in the layer's handshake"),
            ClientError::Handshake(e) => write!(f, "the layer's handshake failed: {e}"),
            ClientError::Timeout => write!(f, "the layer's handshake took more than {} s", HANDSHAKE_LIMIT.as_secs()),
        }
    }
}

impl std::error::Error for ClientError {}

/// A client that knows what the far end speaks.
pub struct Client<L> {
    link: L,
    found: Found,
    /// The far end's bytes read in the wait for its first byte, for a far
    /// end with no layer.
    early: Vec<u8>,
    /// The layer's state, for a far end with it.
    layer: Option<(Decoder, Box<Established>)>,
}

/// Wait for the far end's first byte. A `GREETING` starts the handshake for
/// `ask`, and `OPEN` goes out after it; anything else means no layer.
pub async fn start<L>(
    mut link: L,
    ask: Ask,
    features: &[&str],
    entropy: &mut (dyn Entropy + Send),
) -> Result<Client<L>, ClientError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    // The `OPEN` is made first, while `entropy` is at hand; it waits for
    // the `GREETING`, and with no layer it is dropped unsent.
    let (handshake, open) = ClientHandshake::start(ask, features, entropy).map_err(ClientError::Handshake)?;
    let mut buf = vec![0u8; 64 * 1024];
    let first = match tokio::time::timeout(FIRST_BYTE_WAIT, link.read(&mut buf)).await {
        Err(_) => 0,
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(ClientError::Io(e)),
    };
    if first == 0 || buf[0] != kind::GREETING {
        let found = Found::Plain { first: buf[..first].first().copied() };
        return Ok(Client { link, found, early: buf[..first].to_vec(), layer: None });
    }
    let mut decoder = Decoder::new();
    decoder.push(&buf[..first]);
    let established =
        match tokio::time::timeout(HANDSHAKE_LIMIT, shake(&mut link, &mut decoder, handshake, open, &mut buf)).await {
            Ok(result) => result?,
            Err(_) => return Err(ClientError::Timeout),
        };
    let found = Found::Layer {
        id: established.id,
        peer_role: established.peer_role,
        features: established.features.clone(),
        resumed: established.resumed,
    };
    Ok(Client { link, found, early: Vec::new(), layer: Some((decoder, established)) })
}

/// The handshake, from the far end's first bytes on.
async fn shake<L>(
    link: &mut L,
    decoder: &mut Decoder,
    mut handshake: ClientHandshake,
    open: Record,
    buf: &mut [u8],
) -> Result<Box<Established>, ClientError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let mut open = Some(open);
    loop {
        while let Some(record) = decoder.next().map_err(ClientError::Decode)? {
            let step = handshake.handle(record).map_err(ClientError::Handshake)?;
            // The `OPEN` follows the `GREETING`, which is the first record.
            if let Some(open) = open.take() {
                send(link, &open).await?;
            }
            match step {
                Step::Send(record) => send(link, &record).await?,
                Step::Wait => {}
                Step::Established(_, established) => return Ok(established),
                // A client never refuses: its errors end the handshake.
                Step::Refuse(_, error) => return Err(ClientError::Handshake(error)),
            }
        }
        match link.read(buf).await {
            Ok(0) => return Err(ClientError::Io(std::io::ErrorKind::UnexpectedEof.into())),
            Ok(n) => decoder.push(&buf[..n]),
            Err(e) => return Err(ClientError::Io(e)),
        }
    }
}

async fn send<L: AsyncWrite + Unpin>(link: &mut L, record: &Record) -> Result<(), ClientError> {
    let bytes = record.to_bytes().map_err(|e| ClientError::Io(std::io::Error::other(e)))?;
    link.write_all(&bytes).await.map_err(ClientError::Io)?;
    link.flush().await.map_err(ClientError::Io)
}

/// How the client's session ended.
#[derive(Debug)]
pub enum Outcome {
    /// With no layer: the copy ended, or failed with this error.
    Plain(Option<std::io::Error>),
    /// With the layer: how its link ended.
    Layer(Ended),
}

impl<L> Client<L>
where
    L: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn found(&self) -> &Found {
        &self.found
    }

    /// The session's id and secret, which a resume needs (T-153). Never for
    /// a message.
    pub fn established(&self) -> Option<&Established> {
        self.layer.as_ref().map(|(_, established)| established.as_ref())
    }

    /// Carry the session between `app` and the link until either ends.
    pub async fn run<A>(self, mut app: A) -> Outcome
    where
        A: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let Client { mut link, early, layer, .. } = self;
        match layer {
            Some((decoder, established)) => {
                let state = Link::new(established.received, established.peer_received);
                Outcome::Layer(pump::run(app, link, decoder, state).await)
            }
            None => {
                if let Err(e) = app.write_all(&early).await {
                    return Outcome::Plain(Some(e));
                }
                match tokio::io::copy_bidirectional(&mut app, &mut link).await {
                    Ok(_) => Outcome::Plain(None),
                    Err(e) => Outcome::Plain(Some(e)),
                }
            }
        }
    }
}
