//! `-X` and `-Y` (T-037): X11 forwarding to the display that `DISPLAY`
//! names. The server listens; for each `x11` channel that it opens, podssh
//! connects to the local X server, puts the real cookie in place of the
//! spoofed one that the server was given, and copies the bytes both ways, as
//! OpenSSH does. The real cookie never leaves this host. Asked for the
//! destination alone: every other connection refuses such a channel.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::{ChannelOpenHandle, Msg};
use russh::{Channel, ChannelMsg, ChannelOpenFailure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::log::Log;

/// The authorization of an X connection that podssh knows.
pub const PROTOCOL: &str = "MIT-MAGIC-COOKIE-1";

/// How long the local X server, and an X client's first packet, may take.
const LIMIT: Duration = Duration::from_secs(10);

/// Where an X server listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum At {
    /// A Unix socket: `/tmp/.X11-unix/XN` for `:N`, or the path of a
    /// `DISPLAY` that starts with `/` (XQuartz).
    Socket(PathBuf),
    /// TCP port 6000+N of a host: `HOST:N`, and `:N` on Windows.
    Tcp(String),
}

/// A display of `DISPLAY`: `[HOST]:NUMBER[.SCREEN]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Display {
    pub at: At,
    pub number: u16,
    pub screen: u32,
}

impl Display {
    pub fn parse(text: &str) -> Result<Display, String> {
        let bad = || format!("DISPLAY={text} is not [HOST]:NUMBER[.SCREEN]");
        let (host, rest) = text.rsplit_once(':').ok_or_else(bad)?;
        let (number, screen) = rest.split_once('.').unwrap_or((rest, "0"));
        let number: u16 = number.parse().ok().filter(|n| *n < 59536).ok_or_else(bad)?;
        let screen: u32 = screen.parse().map_err(|_| bad())?;
        let at = if host.starts_with('/') {
            At::Socket(PathBuf::from(text))
        } else if host.is_empty() || host == "unix" {
            if cfg!(unix) {
                At::Socket(PathBuf::from(format!("/tmp/.X11-unix/X{number}")))
            } else {
                At::Tcp("127.0.0.1".into())
            }
        } else {
            At::Tcp(host.trim_start_matches('[').trim_end_matches(']').to_string())
        };
        Ok(Display { at, number, screen })
    }

    /// Whether the X server runs on this host, so that its cookie is filed
    /// under this host's name.
    fn local(&self) -> bool {
        match &self.at {
            At::Socket(_) => true,
            At::Tcp(host) => matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"),
        }
    }
}

/// A duplex stream to an X server.
pub(crate) trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// A connection to the X server of `display`.
pub(crate) async fn connect(display: &Display) -> std::io::Result<Box<dyn Duplex>> {
    match &display.at {
        #[cfg(unix)]
        At::Socket(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
        #[cfg(not(unix))]
        At::Socket(path) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("{}: a Unix socket, which this system has not", path.display()),
        )),
        At::Tcp(host) => Ok(Box::new(tokio::net::TcpStream::connect((host.as_str(), 6000 + display.number)).await?)),
    }
}

/// The family of an entry of an authority file: any host, this host by its
/// name, an IPv4 address, an IPv6 address (Xlib's `Family*`).
const WILD: u16 = 65535;
const LOCAL: u16 = 256;
const INTERNET: u16 = 0;
const INTERNET6: u16 = 6;

/// The `MIT-MAGIC-COOKIE-1` of `display` in an authority file, as Xlib
/// chooses it: an entry of the display's number, or of none, for any host,
/// for this host by `local_host` (any name when it is not known) when the
/// display is local, or for the display's address.
pub fn cookie_in(file: &[u8], display: &Display, local_host: Option<&str>) -> Option<Zeroizing<Vec<u8>>> {
    let number = display.number.to_string();
    let address: Option<Vec<u8>> = match &display.at {
        At::Tcp(host) => match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => Some(ip.octets().to_vec()),
            Ok(std::net::IpAddr::V6(ip)) => Some(ip.octets().to_vec()),
            Err(_) => None,
        },
        At::Socket(_) => None,
    };
    let mut rest = file;
    while rest.len() >= 2 {
        let family = u16::from_be_bytes([rest[0], rest[1]]);
        rest = &rest[2..];
        let mut fields = [&[][..]; 4];
        for field in &mut fields {
            *field = take_field(&mut rest)?;
        }
        let [host, entry_number, name, data] = fields;
        let for_host = match family {
            WILD => true,
            LOCAL => display.local() && local_host.is_none_or(|h| h.as_bytes() == host),
            INTERNET | INTERNET6 => address.as_deref() == Some(host),
            _ => false,
        };
        let for_number = entry_number.is_empty() || entry_number == number.as_bytes();
        if for_host && for_number && name == PROTOCOL.as_bytes() && !data.is_empty() {
            return Some(Zeroizing::new(data.to_vec()));
        }
    }
    None
}

/// One field of an entry: a big-endian length, then its bytes.
fn take_field<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
    let field = rest.get(2..2 + len)?;
    *rest = &rest[2 + len..];
    Some(field)
}

/// The authority file: `XAUTHORITY`, else `.Xauthority` in the home.
pub fn authority_file(var: Option<&str>, home: Option<&Path>) -> Option<PathBuf> {
    var.filter(|v| !v.is_empty()).map(PathBuf::from).or_else(|| home.map(|h| h.join(".Xauthority")))
}

/// Whether the X server of `display` answers a connection.
pub async fn answers(display: &Display) -> Result<(), String> {
    tokio::time::timeout(LIMIT, connect(display))
        .await
        .map_err(|_| format!("the X server did not answer within {} s", LIMIT.as_secs()))?
        .map(drop)
        .map_err(|e| format!("the X server cannot be reached: {e}"))
}

/// Whether the X server of `display` takes a connection with no
/// authorization: some on Windows take any, with access control off.
pub async fn takes_no_cookie(display: &Display) -> Result<bool, String> {
    let mut conn = tokio::time::timeout(LIMIT, connect(display))
        .await
        .map_err(|_| format!("the X server did not answer within {} s", LIMIT.as_secs()))?
        .map_err(|e| format!("the X server cannot be reached: {e}"))?;
    // A setup request with no authorization (X11, chapter 8): little-endian,
    // protocol 11.0.
    let setup = [b'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut status = [0u8; 1];
    let asked = async {
        conn.write_all(&setup).await?;
        conn.read_exact(&mut status).await
    };
    tokio::time::timeout(LIMIT, asked)
        .await
        .map_err(|_| "the X server did not answer a setup request".to_string())?
        .map_err(|e| format!("the X server: {e}"))?;
    Ok(status[0] == 1)
}

/// What one connection forwards: the display, its real cookie (none for an
/// X server that takes a connection with none), and the spoofed cookie that
/// the server is given in its place.
#[derive(Clone)]
pub struct Forward {
    display: Display,
    real: Option<Zeroizing<Vec<u8>>>,
    spoofed: Vec<u8>,
    /// `-X`'s cookie lasts until then (`ForwardX11Timeout`); after it, a new
    /// X11 channel is refused, as OpenSSH refuses it.
    until: Option<Instant>,
    said: Arc<AtomicBool>,
}

impl std::fmt::Debug for Forward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forward").field("display", &self.display).field("until", &self.until).finish()
    }
}

impl Forward {
    /// `real` of 16 bytes, as a cookie is; the spoofed one is as long, at
    /// random.
    pub fn new(display: Display, real: Option<Zeroizing<Vec<u8>>>, lasts: Option<Duration>) -> Self {
        let len = real.as_ref().map_or(16, |r| r.len());
        let spoofed = (0..len).map(|_| rand::random::<u8>()).collect();
        Forward {
            display,
            real,
            spoofed,
            until: lasts.map(|d| Instant::now() + d),
            said: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The spoofed cookie in hexadecimal, as `x11-req` carries it.
    pub fn spoofed_hex(&self) -> String {
        self.spoofed.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Ask the server on `channel` for X11 forwarding, before the shell or the
/// command, with the spoofed cookie: a refusal is said, and the session goes
/// on without it.
pub async fn request(
    channel: &mut Channel<Msg>,
    early: &mut Vec<ChannelMsg>,
    forward: &Forward,
    log: &Log,
) -> Result<(), String> {
    log.verbose("requesting X11 forwarding (x11-req)");
    channel
        .request_x11(true, false, PROTOCOL, forward.spoofed_hex(), forward.display.screen)
        .await
        .map_err(|e| format!("could not request X11 forwarding: {e}"))?;
    if !crate::session::wait_reply(channel, early).await? {
        log.info("the server refused X11 forwarding; the session goes on without it");
    }
    Ok(())
}

/// Join an `x11` channel that the server opened to the local X server, in a
/// task of its own: the first packet of the X client must carry the spoofed
/// cookie, which the real one replaces. The handler must not wait here.
pub fn join(forward: Forward, channel: Channel<Msg>, reply: ChannelOpenHandle, log: Arc<Log>) {
    tokio::spawn(async move {
        let refuse = |why: String| {
            let line = format!("X11 forwarding: {why}; refused");
            if forward.said.swap(true, Ordering::SeqCst) {
                log.verbose(&line)
            } else {
                log.info(&line)
            }
        };
        if forward.until.is_some_and(|until| Instant::now() > until) {
            refuse("the untrusted cookie has expired (ForwardX11Timeout)".into());
            return reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        }
        let mut local = match tokio::time::timeout(LIMIT, connect(&forward.display)).await {
            Ok(Ok(local)) => local,
            failed => {
                refuse(match failed {
                    Ok(Err(e)) => format!("the X server cannot be reached: {e}"),
                    _ => "the X server did not answer".into(),
                });
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return;
            }
        };
        reply.accept().await;
        let mut stream = channel.into_stream();
        let first = match tokio::time::timeout(LIMIT, setup(&mut stream, &forward)).await {
            Ok(Ok(first)) => first,
            Ok(Err(why)) => return refuse(why),
            Err(_) => return refuse("the X client sent no first packet".into()),
        };
        if local.write_all(&first).await.is_ok() {
            crate::agent_forward::splice(stream, local, Duration::from_secs(5)).await;
        }
    });
}

/// The lengths of the authorization's name and data in the first 12 bytes
/// of a setup request, in the byte order of its first byte.
fn lengths(head: &[u8; 12]) -> Result<(usize, usize), String> {
    let card16 = |at: usize| {
        let pair = [head[at], head[at + 1]];
        usize::from(if head[0] == b'B' { u16::from_be_bytes(pair) } else { u16::from_le_bytes(pair) })
    };
    match head[0] {
        b'B' | b'l' => Ok((card16(6), card16(8))),
        _ => Err("the X client's first packet is no setup request".into()),
    }
}

/// The padding of a field of `n` bytes to 4.
fn pad(n: usize) -> usize {
    (4 - n % 4) % 4
}

/// The X client's first packet, its setup request, read from `stream`, with
/// the real cookie in place of the spoofed one; an error when it carries
/// another.
async fn setup<S: AsyncRead + Unpin>(stream: &mut S, forward: &Forward) -> Result<Vec<u8>, String> {
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).await.map_err(|e| format!("the X client's first packet: {e}"))?;
    let (name_len, data_len) = lengths(&head)?;
    let mut rest = vec![0u8; name_len + pad(name_len) + data_len + pad(data_len)];
    stream.read_exact(&mut rest).await.map_err(|e| format!("the X client's first packet: {e}"))?;
    swap(&head, &rest, forward)
}

/// The setup request of `head` and `rest` with the real cookie, or with
/// none for an X server that takes none.
fn swap(head: &[u8; 12], rest: &[u8], forward: &Forward) -> Result<Vec<u8>, String> {
    let (name_len, data_len) = lengths(head)?;
    let name = &rest[..name_len];
    let data = &rest[name_len + pad(name_len)..name_len + pad(name_len) + data_len];
    if name != PROTOCOL.as_bytes() || data != forward.spoofed.as_slice() {
        return Err("an X client gave another cookie than the one that the server was given".into());
    }
    let (name, data): (&[u8], &[u8]) = match &forward.real {
        Some(real) => (PROTOCOL.as_bytes(), real),
        None => (&[], &[]),
    };
    let to16 = |n: usize| if head[0] == b'B' { (n as u16).to_be_bytes() } else { (n as u16).to_le_bytes() };
    let mut out = head.to_vec();
    out[6..8].copy_from_slice(&to16(name.len()));
    out[8..10].copy_from_slice(&to16(data.len()));
    for part in [name, data] {
        out.extend_from_slice(part);
        out.extend(std::iter::repeat_n(0, pad(part.len())));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "x11_tests.rs"]
mod tests;
