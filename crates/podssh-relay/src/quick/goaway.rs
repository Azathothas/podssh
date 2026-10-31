//! The edge's GOAWAY, seen as it passes (T-300). After a GOAWAY, h2 keeps
//! the connection until its last stream ends and tells no one, and the edge
//! opens no stream on it; a node with one connection would serve no new
//! visitor meanwhile. This reads the headers of the frames that come from
//! the edge (RFC 9113, section 4.1), skips their payloads, and says when
//! one is a GOAWAY, so that the node connects again at once.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

/// The client's preface, which comes before its first frame.
const PREFACE: usize = 24;
/// A frame's header: its length, type, flags and stream.
const HEADER: usize = 9;
/// The type of a GOAWAY.
const GOAWAY: u8 = 0x7;

/// Where the reading of the edge's bytes stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum At {
    /// In the preface: the bytes of it still to come.
    Preface(usize),
    /// In a frame's header: the bytes of it read so far.
    Header([u8; HEADER], usize),
    /// In a frame's payload: the bytes of it still to come.
    Payload(usize),
}

/// The reading of the frames' headers.
#[derive(Debug)]
struct Scan(At);

impl Scan {
    fn new() -> Scan {
        Scan(At::Preface(PREFACE))
    }

    /// Read `bytes`: whether a GOAWAY's header was among them.
    fn feed(&mut self, mut bytes: &[u8]) -> bool {
        let mut seen = false;
        while !bytes.is_empty() {
            self.0 = match self.0 {
                At::Preface(left) | At::Payload(left) => {
                    let take = left.min(bytes.len());
                    bytes = &bytes[take..];
                    match left - take {
                        0 => At::Header([0; HEADER], 0),
                        more if matches!(self.0, At::Preface(_)) => At::Preface(more),
                        more => At::Payload(more),
                    }
                }
                At::Header(mut header, have) => {
                    let take = (HEADER - have).min(bytes.len());
                    header[have..have + take].copy_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if have + take < HEADER {
                        At::Header(header, have + take)
                    } else {
                        seen |= header[3] == GOAWAY;
                        let length =
                            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
                        if length == 0 {
                            At::Header([0; HEADER], 0)
                        } else {
                            At::Payload(length)
                        }
                    }
                }
            };
        }
        seen
    }
}

/// The connection to the edge, whose reads are watched for a GOAWAY.
pub struct Watched<IO> {
    io: IO,
    scan: Scan,
    said: watch::Sender<bool>,
}

/// `io` watched, and the word that turns `true` at the edge's GOAWAY.
pub fn watched<IO>(io: IO) -> (Watched<IO>, watch::Receiver<bool>) {
    let (said, heard) = watch::channel(false);
    (Watched { io, scan: Scan::new(), said }, heard)
}

impl<IO: AsyncRead + Unpin> AsyncRead for Watched<IO> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.io).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            let this = &mut *self;
            if this.scan.feed(&buf.filled()[before..]) {
                this.said.send_replace(true);
            }
        }
        polled
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Watched<IO> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let n = payload.len();
        let mut out = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, 0, 0, 0, 0, 0];
        out.extend_from_slice(payload);
        out
    }

    /// The preface, SETTINGS, a DATA frame whose payload holds a GOAWAY's
    /// bytes, then a PING.
    fn stream() -> Vec<u8> {
        let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        bytes.extend(frame(0x4, &[0, 3, 0, 0, 0, 100]));
        bytes.extend(frame(0x0, &frame(GOAWAY, &[0; 8])));
        bytes.extend(frame(0x6, &[0; 8]));
        bytes
    }

    #[test]
    fn a_goaway_is_seen_in_any_cut_of_the_stream_and_its_look_alike_in_a_payload_is_not() {
        let bytes = stream();
        for cut in [1, 2, 7, 9, 24, 1000] {
            let mut scan = Scan::new();
            assert!(!bytes.chunks(cut).any(|chunk| scan.feed(chunk)), "no GOAWAY yet, in pieces of {cut}");
            let goaway = frame(GOAWAY, &[0, 0, 0, 1, 0, 0, 0, 0]);
            assert!(goaway.chunks(cut).any(|chunk| scan.feed(chunk)), "the GOAWAY, in pieces of {cut}");
        }
    }

    #[tokio::test]
    async fn the_reads_of_a_watched_stream_say_the_goaway() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut edge, node) = tokio::io::duplex(1024);
        let (mut node, mut said) = watched(node);
        edge.write_all(&stream()).await.unwrap();
        let mut buf = vec![0u8; stream().len()];
        node.read_exact(&mut buf).await.unwrap();
        assert!(!*said.borrow(), "nothing said yet");
        edge.write_all(&frame(GOAWAY, &[0; 8])).await.unwrap();
        let mut buf = [0u8; 17];
        node.read_exact(&mut buf).await.unwrap();
        assert!(said.has_changed().unwrap() && *said.borrow_and_update());
    }
}
