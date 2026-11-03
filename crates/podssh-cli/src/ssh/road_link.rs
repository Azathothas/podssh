//! A link of `podssh ssh node://NAME` on any of its roads (`super::roads`):
//! one type for the race and the resumable layer above it, whichever road
//! won. Apart from `roads.rs`, for the length of that file.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// A link on any road.
pub enum Road {
    #[cfg(feature = "iroh")]
    Iroh(podssh_iroh::Stream),
    Pair(DuplexStream),
    Derp(podssh_relay::derp::Link),
    Transit(podssh_relay::transit::Link),
    Piping(podssh_relay::piping::Link),
    /// A WebSocket to a node's quick tunnel, of its record (T-445), which a
    /// build with the iroh road reads.
    #[cfg(feature = "iroh")]
    Tunnel(DuplexStream),
}

impl AsyncRead for Road {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_read(cx, buf),
            Road::Pair(link) => Pin::new(link).poll_read(cx, buf),
            Road::Derp(link) => Pin::new(link).poll_read(cx, buf),
            Road::Transit(link) => Pin::new(link).poll_read(cx, buf),
            Road::Piping(link) => Pin::new(link).poll_read(cx, buf),
            #[cfg(feature = "iroh")]
            Road::Tunnel(link) => Pin::new(link).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Road {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_write(cx, buf),
            Road::Pair(link) => Pin::new(link).poll_write(cx, buf),
            Road::Derp(link) => Pin::new(link).poll_write(cx, buf),
            Road::Transit(link) => Pin::new(link).poll_write(cx, buf),
            Road::Piping(link) => Pin::new(link).poll_write(cx, buf),
            #[cfg(feature = "iroh")]
            Road::Tunnel(link) => Pin::new(link).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_flush(cx),
            Road::Pair(link) => Pin::new(link).poll_flush(cx),
            Road::Derp(link) => Pin::new(link).poll_flush(cx),
            Road::Transit(link) => Pin::new(link).poll_flush(cx),
            Road::Piping(link) => Pin::new(link).poll_flush(cx),
            #[cfg(feature = "iroh")]
            Road::Tunnel(link) => Pin::new(link).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_shutdown(cx),
            Road::Pair(link) => Pin::new(link).poll_shutdown(cx),
            Road::Derp(link) => Pin::new(link).poll_shutdown(cx),
            Road::Transit(link) => Pin::new(link).poll_shutdown(cx),
            Road::Piping(link) => Pin::new(link).poll_shutdown(cx),
            #[cfg(feature = "iroh")]
            Road::Tunnel(link) => Pin::new(link).poll_shutdown(cx),
        }
    }
}

/// Which road a place of the race is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Iroh,
    Pair,
    Derp,
    Transit,
    Piping,
    /// A road of the node's record, by its name.
    Record(&'static str),
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Kind::Record(name) => name,
            Kind::Iroh => "the iroh road",
            Kind::Pair => "the pair's road",
            Kind::Derp => "the DERP road",
            Kind::Transit => "the transit road",
            Kind::Piping => "the Piping Server road",
        }
    }
}
