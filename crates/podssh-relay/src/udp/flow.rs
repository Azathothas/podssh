//! One flow of UDP at the far end (T-168): a UDP socket connected to the
//! target, and the stream that carries the flow's datagrams in the framing
//! of [`super::codec`]. Each datagram of the stream goes out as one UDP
//! datagram, and each that comes back goes into the stream. UDP has no end
//! of its own, so the flow ends when its stream ends, or after its idle
//! limit with no datagram either way.
//!
//! The socket takes an address of port 0, as any client's socket does, and
//! is connected: it takes datagrams from the target alone. Its maker probes
//! first that this host allows UDP at all (a sandbox gives EPERM).

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::codec::{framed, Frames, MAX_DATAGRAM};

/// A flow with no datagram either way for this long ends.
pub const IDLE: Duration = Duration::from_secs(60);
/// Each receive: room for the longest datagram of IPv6, so that one over
/// the limit shows as longer, and is dropped, rather than failing.
const RECEIVE: usize = 64 * 1024;

/// Why no flow could be opened to a target.
#[derive(Debug)]
pub enum NoFlow {
    /// The target's name has no address.
    Resolve(String),
    /// This host refuses UDP (EPERM or EACCES), as a sandbox does.
    Refused(io::Error),
    /// Another failure of the socket.
    Socket(io::Error),
}

impl NoFlow {
    /// Whether this host refuses UDP, whatever the target.
    pub fn host_refuses(&self) -> bool {
        matches!(self, NoFlow::Refused(_))
    }
}

impl fmt::Display for NoFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoFlow::Resolve(why) => write!(f, "could not resolve the name: {why}"),
            NoFlow::Refused(e) => write!(f, "this host refuses UDP: {e}"),
            NoFlow::Socket(e) => write!(f, "no UDP socket to it: {e}"),
        }
    }
}

impl std::error::Error for NoFlow {}

/// A UDP socket connected to `host:port`: the first address of the name
/// that takes one. The name resolves as each of podssh's dials resolves
/// one, within `timeout`.
pub async fn connect(host: &str, port: u16, timeout: Duration) -> Result<UdpSocket, NoFlow> {
    let deadline = Instant::now() + timeout;
    let addrs = podssh_ws::resolve::resolve(host, port, deadline).await.map_err(NoFlow::Resolve)?;
    let mut last = None;
    for addr in addrs {
        match socket_to(addr).await {
            Ok(socket) => return Ok(socket),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(NoFlow::Refused(e)),
            Err(e) => last = Some(e),
        }
    }
    Err(NoFlow::Socket(last.unwrap_or_else(|| io::Error::other("the name has no address"))))
}

/// Whether this host sends UDP to `host:port`: a socket, connected, then
/// closed. No datagram goes out, so the target sees nothing. The address
/// that it would reach.
pub async fn probe(host: &str, port: u16, timeout: Duration) -> Result<SocketAddr, NoFlow> {
    let socket = connect(host, port, timeout).await?;
    socket.peer_addr().map_err(NoFlow::Socket)
}

/// A socket on port 0 of the target's family, connected to it: on the
/// loopback for a target there, which no other host can reach.
async fn socket_to(addr: SocketAddr) -> io::Result<UdpSocket> {
    let local: IpAddr = match addr {
        SocketAddr::V4(v4) if v4.ip().is_loopback() => Ipv4Addr::LOCALHOST.into(),
        SocketAddr::V6(v6) if v6.ip().is_loopback() => Ipv6Addr::LOCALHOST.into(),
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
    socket.connect(addr).await?;
    Ok(socket)
}

/// How a flow ended.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum FlowEnd {
    /// The stream ended, or its reader is gone.
    #[default]
    Closed,
    /// No datagram either way for the idle limit.
    Idle,
    /// The stream is not the framing, or it ended inside a datagram.
    Framing(String),
    /// The socket failed.
    Socket(String),
}

/// What a flow carried, and how it ended.
#[derive(Debug, Default)]
pub struct Carried {
    /// Datagrams sent to the target.
    pub sent: u64,
    /// Datagrams from the target, into the stream.
    pub received: u64,
    /// Datagrams from the target over [`MAX_DATAGRAM`] bytes, dropped.
    pub dropped: u64,
    /// The datagrams that the target's host refused (ICMP port
    /// unreachable): UDP goes on after one, as the next may be taken.
    pub refused: u64,
    pub end: FlowEnd,
}

impl Carried {
    /// A line for the log of a flow that did not end plainly, or `None`.
    pub fn note(&self) -> Option<String> {
        let mut parts = Vec::new();
        match &self.end {
            FlowEnd::Framing(why) => parts.push(format!("its stream is not the framing: {why}")),
            FlowEnd::Socket(why) => parts.push(format!("its socket failed: {why}")),
            FlowEnd::Closed | FlowEnd::Idle => {}
        }
        if self.dropped > 0 {
            parts.push(format!("{} datagrams over {MAX_DATAGRAM} bytes were dropped", self.dropped));
        }
        if self.refused > 0 {
            parts.push(format!("the target's host refused {} datagrams (port unreachable)", self.refused));
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// A send or a receive that a target's ICMP error failed: the flow goes on.
fn refused(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset)
}

/// Carry one flow between `stream` and `socket` until the stream ends, its
/// reader is gone, or `idle` passes with no datagram either way; then the
/// stream's write side is shut down, and the socket closes.
pub async fn carry<S>(stream: S, socket: UdpSocket, idle: Duration) -> Carried
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut frames = Frames::new(read);
    let mut buf = vec![0u8; RECEIVE];
    let mut carried = Carried::default();
    let quiet = tokio::time::sleep(idle);
    tokio::pin!(quiet);
    carried.end = loop {
        tokio::select! {
            next = frames.recv() => match next {
                Ok(Some(datagram)) => {
                    quiet.as_mut().reset(Instant::now() + idle);
                    match socket.send(&datagram).await {
                        Ok(_) => carried.sent += 1,
                        Err(e) if refused(&e) => carried.refused += 1,
                        Err(e) => break FlowEnd::Socket(e.to_string()),
                    }
                }
                Ok(None) => break FlowEnd::Closed,
                Err(e) if matches!(e.kind(), io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof) => {
                    break FlowEnd::Framing(e.to_string())
                }
                Err(_) => break FlowEnd::Closed,
            },
            got = socket.recv(&mut buf) => match got {
                Ok(n) => match framed(&buf[..n]) {
                    Some(bytes) => {
                        quiet.as_mut().reset(Instant::now() + idle);
                        if write.write_all(&bytes).await.is_err() || write.flush().await.is_err() {
                            break FlowEnd::Closed;
                        }
                        carried.received += 1;
                    }
                    None => carried.dropped += 1,
                },
                Err(e) if refused(&e) => carried.refused += 1,
                Err(e) => break FlowEnd::Socket(e.to_string()),
            },
            () = &mut quiet => break FlowEnd::Idle,
        }
    };
    let _ = write.shutdown().await;
    carried
}
