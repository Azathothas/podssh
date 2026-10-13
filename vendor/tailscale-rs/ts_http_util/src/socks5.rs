//! A tunnel through a SOCKS5 proxy (RFC 1928), with the user and the
//! password of RFC 1929 when the proxy URL has them (podssh's patch 0022).
//!
//! The host name goes to the proxy (address type 3), so this host needs no
//! DNS for it, as with [`crate::proxy`]'s `CONNECT`. A proxy that takes no
//! names (reply 8) gets one more connection, with an address of the system
//! resolver's. The reply is read to exactly its end: the bytes after it
//! belong to TLS.

use std::{io, net::IpAddr};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

const VERSION: u8 = 5;
const NO_AUTHENTICATION: u8 = 0x00;
const USER_PASSWORD: u8 = 0x02;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CONNECT: u8 = 0x01;
const IPV4: u8 = 0x01;
const NAME: u8 = 0x03;
const IPV6: u8 = 0x04;
/// The reply of a proxy that takes no host names.
const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// The user and the password of RFC 1929, decoded, 1 to 255 bytes each.
pub(crate) type Credentials = (Vec<u8>, Vec<u8>);

/// Where the proxy is asked to go.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Target<'a> {
    /// A host name, with the address type 3.
    Name(&'a str),
    /// An address: the host was one, or the proxy takes no names.
    Addr(IpAddr),
}

impl<'a> Target<'a> {
    /// `host` as a target: an address when it is one (with or without the
    /// brackets of an IPv6 address), else the name.
    pub(crate) fn of(host: &'a str) -> Self {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        match bare.parse::<IpAddr>() {
            Ok(addr) => Target::Addr(addr),
            Err(_) => Target::Name(host),
        }
    }
}

/// Why no tunnel was opened.
#[derive(Debug)]
pub(crate) enum Failure {
    /// Reply 8 to a host name: the proxy takes no names, and an address may
    /// get through.
    NoNames,
    /// Each other failure, with what the proxy did. No message holds the
    /// user or the password.
    Io(io::Error),
}

impl From<io::Error> for Failure {
    fn from(err: io::Error) -> Self {
        Failure::Io(err)
    }
}

impl Failure {
    /// The failure as an I/O error.
    pub(crate) fn into_io(self) -> io::Error {
        match self {
            Failure::NoNames => io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "the SOCKS5 proxy takes no host names (reply 8, address type not supported)",
            ),
            Failure::Io(err) => err,
        }
    }
}

/// A tunnel to `host:port` through the SOCKS5 proxy at `proxy_host:port`:
/// by name, and once more with an address of the system resolver's when the
/// proxy takes no names. The caller bounds the whole.
pub(crate) async fn connect(
    proxy_host: &str,
    proxy_port: u16,
    credentials: Option<&Credentials>,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    let target = Target::of(host);
    let mut stream = TcpStream::connect((proxy_host, proxy_port)).await?;
    match exchange(&mut stream, credentials, target, port).await {
        Ok(()) => Ok(stream),
        Err(Failure::NoNames) => {
            let addr = tokio::net::lookup_host((host, port))
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("the SOCKS5 proxy takes no host names, and {host} has no address"),
                    )
                })?
                .ip();
            let mut stream = TcpStream::connect((proxy_host, proxy_port)).await?;
            exchange(&mut stream, credentials, Target::Addr(addr), port)
                .await
                .map_err(Failure::into_io)?;
            Ok(stream)
        }
        Err(failure) => Err(failure.into_io()),
    }
}

/// `%XX` escapes decoded, as in a URL's user name and password, as bytes:
/// RFC 1929 sends bytes.
pub(crate) fn percent_decode_bytes(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let value = text
                .get(i + 1..i + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                .ok_or_else(|| {
                    "a % escape in the proxy credentials is not two hex digits".to_string()
                })?;
            out.push(value);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// The user and the password of a SOCKS5 proxy URL, each decoded, as RFC
/// 1929 takes them: 1 to 255 bytes each. `None` when the URL has neither.
/// No error quotes them.
pub(crate) fn credentials(
    user: &str,
    password: Option<&str>,
) -> Result<Option<Credentials>, String> {
    if user.is_empty() && password.is_none() {
        return Ok(None);
    }
    let user = percent_decode_bytes(user)?;
    let password = percent_decode_bytes(password.unwrap_or(""))?;
    for (what, value) in [("user", &user), ("password", &password)] {
        if value.is_empty() || value.len() > 255 {
            return Err(format!(
                "the SOCKS5 {what} has {} bytes; RFC 1929 takes 1 to 255",
                value.len()
            ));
        }
    }
    Ok(Some((user, password)))
}

/// The text of a reply (RFC 1928, section 6).
fn reply_text(reply: u8) -> &'static str {
    match reply {
        0x01 => "general failure",
        0x02 => "connection not allowed by its rules",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "a reply that RFC 1928 does not name",
    }
}

fn protocol(detail: String) -> Failure {
    Failure::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the SOCKS5 proxy did not answer as its protocol says: {detail}"),
    ))
}

/// The greeting, the user and password when the proxy asks for them, and
/// `CONNECT`. Any stream, so that a test can play the proxy.
pub(crate) async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    credentials: Option<&Credentials>,
    target: Target<'_>,
    port: u16,
) -> Result<(), Failure> {
    let methods: &[u8] = match credentials {
        Some(_) => &[NO_AUTHENTICATION, USER_PASSWORD],
        None => &[NO_AUTHENTICATION],
    };
    let mut greeting = vec![VERSION, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await?;
    if chosen[0] != VERSION {
        return Err(protocol(format!(
            "its answer to the greeting has the version {}, not 5",
            chosen[0]
        )));
    }
    match (chosen[1], credentials) {
        (NO_AUTHENTICATION, _) => {}
        (USER_PASSWORD, Some((user, password))) => authenticate(stream, user, password).await?,
        (NO_ACCEPTABLE_METHOD, None) => {
            return Err(Failure::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the SOCKS5 proxy needs a user and a password, and the proxy URL has none",
            )));
        }
        (NO_ACCEPTABLE_METHOD, Some(_)) => {
            return Err(Failure::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the SOCKS5 proxy takes neither no authentication nor a user and a password",
            )));
        }
        (other, _) => {
            return Err(protocol(format!(
                "it chose the method {other:#04x}, which was not offered"
            )));
        }
    }
    let mut request = vec![VERSION, CONNECT, 0x00];
    match target {
        Target::Name(name) => {
            let len = u8::try_from(name.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} is longer than the 255 bytes of SOCKS5"),
                )
            })?;
            request.push(NAME);
            request.push(len);
            request.extend_from_slice(name.as_bytes());
        }
        Target::Addr(IpAddr::V4(addr)) => {
            request.push(IPV4);
            request.extend_from_slice(&addr.octets());
        }
        Target::Addr(IpAddr::V6(addr)) => {
            request.push(IPV6);
            request.extend_from_slice(&addr.octets());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(protocol(format!("its reply has the version {}, not 5", head[0])));
    }
    match (head[1], target) {
        (0x00, _) => {}
        (ADDRESS_TYPE_NOT_SUPPORTED, Target::Name(_)) => return Err(Failure::NoNames),
        // A refusal: what follows is not read, as the stream is not used.
        (reply, _) => {
            return Err(Failure::Io(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "the SOCKS5 proxy refused CONNECT: reply {reply}, {}",
                    reply_text(reply)
                ),
            )));
        }
    }
    // The bound address, which the dial does not use, to exactly its end.
    let rest = match head[3] {
        IPV4 => 4 + 2,
        IPV6 => 16 + 2,
        NAME => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0]) + 2
        }
        other => return Err(protocol(format!("its reply has the address type {other}"))),
    };
    let mut bound = vec![0u8; rest];
    stream.read_exact(&mut bound).await?;
    Ok(())
}

/// The user and the password of RFC 1929; their lengths were checked.
async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    user: &[u8],
    password: &[u8],
) -> Result<(), Failure> {
    let mut message = vec![0x01, user.len() as u8];
    message.extend_from_slice(user);
    message.push(password.len() as u8);
    message.extend_from_slice(password);
    stream.write_all(&message).await?;
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await?;
    // RFC 1929 gives this answer the version 1. A few servers give it the
    // version of SOCKS, 5, and curl reads the status alone: both are taken.
    match status {
        [0x01 | VERSION, 0x00] => Ok(()),
        [0x01 | VERSION, _] => Err(Failure::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the SOCKS5 proxy refused the user and the password",
        ))),
        [version, _] => Err(protocol(format!(
            "its answer to the password has the version {version}, not 1"
        ))),
    }
}
