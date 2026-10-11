//! A tunnel through a SOCKS5 proxy (RFC 1928), with the user and the
//! password of RFC 1929 when the proxy URL has them (T-070). The host name
//! goes to the proxy (address type 3), so this host needs no DNS: the hosts
//! that podssh is made for often have none. A proxy that takes no names
//! (reply 8) gets one more try, with an address that podssh resolves in its
//! own order. The reply is read to exactly its length: the bytes after it
//! belong to TLS.

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::dial::{authority, connect_direct, DialError, Proxy};

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
/// The reply of a proxy that has no CONNECT at all.
const COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// Where the proxy goes: the name, or an address.
#[derive(Clone, Copy)]
enum Target<'a> {
    Name(&'a str),
    Addr(IpAddr),
}

/// Why an exchange failed.
enum Step {
    /// The proxy could not be reached: the error of the connection to it.
    Unreachable(DialError),
    Io(std::io::Error),
    /// The proxy broke the protocol.
    Protocol(String),
    /// No method that podssh offered, or the user and password, refused.
    Auth(String),
    /// A reply other than success.
    Reply(u8),
}

/// A tunnel to `host:port` through `proxy`, the whole within `deadline`.
pub(crate) async fn connect(
    proxy: &Proxy,
    host: &str,
    port: u16,
    deadline: Instant,
    budget: Duration,
) -> Result<TcpStream, DialError> {
    crate::dial::check_name(&proxy.host)?;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let target = match bare.parse::<IpAddr>() {
        Ok(addr) => Target::Addr(addr),
        Err(_) if host.len() > 255 => {
            return Err(DialError::InvalidTarget(format!("{host:?} is longer than the 255 bytes of SOCKS5")))
        }
        Err(_) => Target::Name(host),
    };
    match attempt(proxy, target, port, deadline, budget).await {
        Err(Some(Step::Reply(ADDRESS_TYPE_NOT_SUPPORTED))) if matches!(target, Target::Name(_)) => {
            // The proxy takes no names: once more, with an address of ours.
            let addrs = crate::resolve::resolve(host, port, deadline)
                .await
                .map_err(|detail| DialError::Resolve { host: host.to_string(), detail })?;
            let addr = crate::dial::interleave(addrs)
                .first()
                .map(|a| a.ip())
                .ok_or_else(|| DialError::Resolve { host: host.to_string(), detail: "no address".into() })?;
            attempt(proxy, Target::Addr(addr), port, deadline, budget)
                .await
                .map_err(|e| failure(proxy, &authority(&addr.to_string(), port), e, budget))
        }
        result => result.map_err(|e| failure(proxy, &authority(host, port), e, budget)),
    }
}

/// One connection to the proxy and one exchange. `Err(None)`: the time ran
/// out during the exchange.
async fn attempt(
    proxy: &Proxy,
    target: Target<'_>,
    port: u16,
    deadline: Instant,
    budget: Duration,
) -> Result<TcpStream, Option<Step>> {
    let mut stream =
        connect_direct(&proxy.host, proxy.port, deadline, budget).await.map_err(|e| Some(Step::Unreachable(e)))?;
    match tokio::time::timeout_at(deadline, exchange(&mut stream, proxy, target, port)).await {
        Ok(Ok(())) => Ok(stream),
        Ok(Err(step)) => Err(Some(step)),
        Err(_) => Err(None),
    }
}

/// The error of a failed attempt, in the terms of an HTTP proxy's, so that
/// the failover and the exit codes treat both the same.
fn failure(proxy: &Proxy, target: &str, step: Option<Step>, budget: Duration) -> DialError {
    let proxy_name = proxy.to_string();
    match step {
        None => DialError::Timeout { step: format!("the SOCKS5 exchange with {proxy_name}"), after: budget },
        Some(Step::Unreachable(DialError::Timeout { .. })) => {
            DialError::Timeout { step: format!("connecting to the SOCKS5 proxy {proxy_name}"), after: budget }
        }
        Some(Step::Unreachable(e)) => DialError::ProxyUnreachable { proxy: proxy_name, detail: e.to_string() },
        Some(Step::Io(e)) => DialError::ProxyProtocol { proxy: proxy_name, detail: format!("SOCKS5: {e}") },
        Some(Step::Protocol(detail)) => {
            DialError::ProxyProtocol { proxy: proxy_name, detail: format!("SOCKS5: {detail}") }
        }
        Some(Step::Auth(why)) => DialError::ProxyRefused {
            proxy: proxy_name,
            target: target.into(),
            status: 407,
            reason: format!("SOCKS5: {why}"),
        },
        Some(Step::Reply(COMMAND_NOT_SUPPORTED)) => DialError::ProxyProtocol {
            proxy: proxy_name,
            detail: format!("SOCKS5 reply {COMMAND_NOT_SUPPORTED}, command not supported: it has no CONNECT"),
        },
        Some(Step::Reply(reply)) => DialError::ProxyRefused {
            proxy: proxy_name,
            target: target.into(),
            // Its rules refused: as an HTTP proxy's 403. The rest is the far
            // side, as a 502, and another relay host may get through.
            status: if reply == 0x02 { 403 } else { 502 },
            reason: format!("SOCKS5 reply {reply}, {}", reply_text(reply)),
        },
    }
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

/// The greeting, the user and password when the proxy asks for them, and
/// CONNECT. Any stream, so that the fuzzer can play the proxy.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    proxy: &Proxy,
    target: Target<'_>,
    port: u16,
) -> Result<(), Step> {
    let credentials = proxy.credentials();
    let methods: &[u8] = match credentials {
        Some(_) => &[NO_AUTHENTICATION, USER_PASSWORD],
        None => &[NO_AUTHENTICATION],
    };
    let mut greeting = vec![VERSION, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await.map_err(Step::Io)?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await.map_err(Step::Io)?;
    if chosen[0] != VERSION {
        return Err(Step::Protocol(format!("its answer to the greeting has version {}, not 5", chosen[0])));
    }
    match (chosen[1], credentials) {
        (NO_AUTHENTICATION, _) => {}
        (USER_PASSWORD, Some((user, password))) => authenticate(stream, user, password).await?,
        (NO_ACCEPTABLE_METHOD, None) => {
            return Err(Step::Auth("it needs a user and a password, and the proxy URL has none".into()))
        }
        (NO_ACCEPTABLE_METHOD, Some(_)) => {
            return Err(Step::Auth("it takes neither no authentication nor a user and a password".into()))
        }
        (other, _) => {
            return Err(Step::Protocol(format!("it chose the method {other:#04x}, which podssh did not offer")))
        }
    }
    let mut request = vec![VERSION, CONNECT, 0x00];
    match target {
        Target::Name(name) => {
            request.push(NAME);
            request.push(name.len() as u8);
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
    stream.write_all(&request).await.map_err(Step::Io)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(Step::Io)?;
    if head[0] != VERSION {
        return Err(Step::Protocol(format!("its reply has version {}, not 5", head[0])));
    }
    if head[1] != 0x00 {
        // A refusal: what follows is not read, as the stream is not used.
        return Err(Step::Reply(head[1]));
    }
    // The bound address, which podssh does not use, to exactly its end.
    let rest = match head[3] {
        IPV4 => 4 + 2,
        IPV6 => 16 + 2,
        NAME => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(Step::Io)?;
            usize::from(len[0]) + 2
        }
        other => return Err(Step::Protocol(format!("its reply has the address type {other}"))),
    };
    let mut bound = vec![0u8; rest];
    stream.read_exact(&mut bound).await.map_err(Step::Io)?;
    Ok(())
}

/// The user and the password of RFC 1929; their lengths were checked when
/// the proxy URL was read.
async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    user: &str,
    password: &str,
) -> Result<(), Step> {
    let mut message = vec![0x01, user.len() as u8];
    message.extend_from_slice(user.as_bytes());
    message.push(password.len() as u8);
    message.extend_from_slice(password.as_bytes());
    stream.write_all(&message).await.map_err(Step::Io)?;
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.map_err(Step::Io)?;
    // RFC 1929 gives this answer the version 1. A few servers give it the
    // version of SOCKS, 5, and curl reads the status alone: both are taken.
    match status {
        [0x01 | VERSION, 0x00] => Ok(()),
        [0x01 | VERSION, _] => Err(Step::Auth("it refused the user and the password".into())),
        [version, _] => Err(Step::Protocol(format!("its answer to the password has version {version}, not 1"))),
    }
}

/// The exchange with a proxy that answers `answer` and then ends, for the
/// fuzzer (`fuzz/`): whether a tunnel came of it. The proxy's side is always
/// ready, so one poll ends the exchange; a second would be a wait on nothing.
#[cfg(fuzzing)]
pub fn fuzz_exchange(answer: &[u8], credentials: bool, by_name: bool) -> bool {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    /// The proxy's side: `answer` to read, then the end; each write taken.
    struct Scripted<'a>(&'a [u8]);

    impl AsyncRead for Scripted<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let n = buf.remaining().min(self.0.len());
            buf.put_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Scripted<'_> {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let url = if credentials { "socks5://user:password@proxy.invalid" } else { "socks5://proxy.invalid" };
    let proxy = Proxy::parse(url).expect("a SOCKS5 URL");
    let target = if by_name { Target::Name("relay.invalid") } else { Target::Addr(IpAddr::from([192, 0, 2, 1])) };
    let mut stream = Scripted(answer);
    let mut exchange = std::pin::pin!(exchange(&mut stream, &proxy, target, 443));
    match exchange.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(done) => done.is_ok(),
        Poll::Pending => panic!("the SOCKS5 exchange waited on a proxy that is always ready"),
    }
}
