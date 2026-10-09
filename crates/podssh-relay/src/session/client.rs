//! The client's end of the layer over tokio streams: between the pipe that
//! SSH reads and writes, and the link to the far end.
//!
//! On the reverse road the client cannot know whether the node speaks the
//! layer, so it sends nothing until the far end's first byte. A `GREETING`
//! starts with a byte that no line of text does; an SSH server sends its
//! version line first (RFC 4253, section 4.2). With no `GREETING`, the bytes
//! pass both ways as they are, as before the layer.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::decode::{DecodeError, Decoder};
use super::handshake::{Ask, ClientHandshake, Established, HandshakeError, Step};
use super::pump::{self, Carry, Ended};
use super::record::{kind, Record, Role};
use super::secret::{Entropy, SessionId};
use super::Settings;

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
    settings: Settings,
}

/// A client taken apart, for the session across links.
pub(crate) struct Parts<L> {
    pub(crate) link: L,
    pub(crate) found: Found,
    pub(crate) early: Vec<u8>,
    pub(crate) layer: Option<(Decoder, Box<Established>)>,
    pub(crate) settings: Settings,
}

/// Wait for the far end's first byte. A `GREETING` starts the handshake for
/// `ask`, and `OPEN` goes out after it; anything else means no layer.
pub async fn start<L>(
    link: L,
    ask: Ask,
    settings: Settings,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Client<L>, ClientError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    greeted(link).await?.start(ask, settings, entropy).await
}

/// A link whose far end has spoken first, or kept silent for
/// [`FIRST_BYTE_WAIT`]: what it sent, and nothing of the client yet. The
/// race between roads (T-164) stops here, so a link that loses it never
/// sends `OPEN`, and its far end never dials its target.
pub struct Greeted<L> {
    link: L,
    /// The far end's first bytes; none after a silent wait.
    first: Vec<u8>,
}

impl<L> Greeted<L> {
    /// Whether the far end said anything in the wait.
    pub fn spoke(&self) -> bool {
        !self.first.is_empty()
    }

    /// Whether the far end greets with the resumable layer.
    pub fn layer(&self) -> bool {
        self.first.first() == Some(&kind::GREETING)
    }

    /// The link with the bytes read in the wait given back first, for a
    /// handshake that reads them itself (a resume, T-164).
    pub fn rewound(self) -> Rewound<L> {
        Rewound { first: self.first, at: 0, link: self.link }
    }
}

/// A link whose first bytes were read already: it reads them again first.
pub struct Rewound<L> {
    first: Vec<u8>,
    at: usize,
    link: L,
}

impl<L: AsyncRead + Unpin> AsyncRead for Rewound<L> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.at < self.first.len() {
            let n = (self.first.len() - self.at).min(buf.remaining());
            let at = self.at;
            buf.put_slice(&self.first[at..at + n]);
            self.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.link).poll_read(cx, buf)
    }
}

impl<L: AsyncWrite + Unpin> AsyncWrite for Rewound<L> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.link).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.link).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.link).poll_shutdown(cx)
    }
}

/// Wait for the far end's first bytes, within [`FIRST_BYTE_WAIT`].
pub async fn greeted<L>(mut link: L) -> Result<Greeted<L>, ClientError>
where
    L: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    let first = match tokio::time::timeout(FIRST_BYTE_WAIT, link.read(&mut buf)).await {
        Err(_) => 0,
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(ClientError::Io(e)),
    };
    buf.truncate(first);
    Ok(Greeted { link, first: buf })
}

impl<L> Greeted<L>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    /// The handshake for `ask`, after a `GREETING`; with anything else, no
    /// layer, and the bytes read pass on as they are.
    pub async fn start(
        self,
        ask: Ask,
        settings: Settings,
        entropy: &mut (dyn Entropy + Send),
    ) -> Result<Client<L>, ClientError> {
        let Greeted { mut link, first } = self;
        if !first.first().is_some_and(|b| *b == kind::GREETING) {
            let found = Found::Plain { first: first.first().copied() };
            return Ok(Client { link, found, early: first, layer: None, settings });
        }
        let (handshake, open) =
            ClientHandshake::start(ask, settings.features, entropy).map_err(ClientError::Handshake)?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut decoder = Decoder::new();
        decoder.push(&first);
        let shaking = shake(&mut link, &mut decoder, handshake, open, &mut buf);
        let established = match tokio::time::timeout(HANDSHAKE_LIMIT, shaking).await {
            Ok(result) => result?,
            Err(_) => return Err(ClientError::Timeout),
        };
        let found = Found::Layer {
            id: established.id,
            peer_role: established.peer_role,
            features: established.features.clone(),
            resumed: established.resumed,
        };
        Ok(Client { link, found, early: Vec::new(), layer: Some((decoder, established)), settings })
    }
}

/// The handshake, from the far end's first bytes on: `open` goes out after
/// the far end's first record, its `GREETING`.
pub(crate) async fn shake<L>(
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

pub(crate) async fn send<L: AsyncWrite + Unpin>(link: &mut L, record: &Record) -> Result<(), ClientError> {
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

    pub(crate) fn into_parts(self) -> Parts<L> {
        Parts { link: self.link, found: self.found, early: self.early, layer: self.layer, settings: self.settings }
    }

    pub(crate) fn from_parts(parts: Parts<L>) -> Client<L> {
        let Parts { link, found, early, layer, settings } = parts;
        Client { link, found, early, layer, settings }
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
        let Client { mut link, early, layer, settings, .. } = self;
        match layer {
            Some((decoder, established)) => {
                let mut carry = Carry::new(settings.link(&established));
                let ended = pump::run(&mut app, link, decoder, &mut carry, &pump::Watch::default()).await;
                // The application learns that no more bytes come.
                let _ = app.shutdown().await;
                Outcome::Layer(ended)
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
