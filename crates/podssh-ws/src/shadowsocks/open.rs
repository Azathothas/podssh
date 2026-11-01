//! A stream to a target through a Shadowsocks server: TCP to the server,
//! through the proxy of the environment as each road dials; the salt and
//! the target's address in the first chunk; then, where the target speaks
//! first (an SSH server), the server's salt and its first chunk within a
//! limit. That answer tells a server that took the key from one that did
//! not: a server is silent to a stream that it cannot open, and a proxy
//! that waits for TLS on port 443 carries nothing and says nothing either
//! (T-317), so silence names both.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use super::codec::{self, ChunkError, Decoder, Encoder};
use super::{carry, Carried, Node};
use crate::dial::{DialError, ProxyChoice};

/// How long the server's first chunk may take, after the salt and the
/// target went: the SSH server behind it speaks at once, as T-363's road
/// waits for its version line.
pub const ANSWER_WAIT: Duration = Duration::from_secs(10);

/// What the dial of a server needs, beside the server and the target.
pub struct Dial<'a> {
    pub proxy: &'a ProxyChoice,
    /// Bound on the TCP dial, and on the send of the first chunk.
    pub timeout: Duration,
    /// How long to wait for the server's first chunk; `None` waits for
    /// nothing.
    pub answer: Option<Duration>,
    /// Whether a server that is silent through the whole wait is taken:
    /// a target whose client speaks first (a pipe's) sends nothing until
    /// it hears. A close, a reset or a chunk that does not open still
    /// fails.
    pub silence_is_ready: bool,
}

/// A stream that the server carries.
#[derive(Debug)]
pub struct Opened {
    pub carried: Carried,
    /// From the dial to the server's first chunk, when one came within the
    /// wait.
    pub answered_in: Option<Duration>,
}

/// Why a server carried no stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The target cannot go in an address header; no server takes it.
    Target(String),
    /// The TCP connection to the server, directly or through the proxy.
    Dial(DialError),
    /// Sending the salt and the target failed.
    Send(String),
    /// Nothing came back: through the wait (`ended` is `None`), or before
    /// a close or a reset (`ended` says which). `proxy` is the proxy that
    /// carried the connection, if one did.
    Silent { ended: Option<String>, after: Duration, proxy: Option<String> },
    /// Bytes came, and the server's first chunk did not open.
    Chunk(ChunkError),
    /// The server's answer ended inside its salt or its first chunk.
    Cut(String),
}

impl OpenError {
    /// The line that says it, the server named as `shown` and the target as
    /// `target`. Never a password.
    pub fn line(&self, shown: &str, target: &str) -> String {
        match self {
            OpenError::Target(why) => format!("{target} cannot go in a Shadowsocks address: {why}"),
            OpenError::Dial(e) => format!("the Shadowsocks server {shown}: {e}"),
            OpenError::Send(why) => {
                format!("the Shadowsocks server {shown}: sending the salt and {target} failed: {why}")
            }
            OpenError::Silent { ended, after, proxy } => {
                let what = match ended {
                    None => format!("no answer within {} of the salt and {target}", seconds(*after)),
                    Some(how) => format!("{how}, with no answer to the salt and {target}"),
                };
                let cause = match proxy {
                    Some(proxy) => format!(
                        "the proxy {proxy} took the CONNECT, and no byte of the Shadowsocks server came back: it may \
                         expect TLS and carry no Shadowsocks; else the password or the method is not the server's, \
                         or the server cannot reach {target}"
                    ),
                    None => format!(
                        "the password or the method may not be the server's, as a server is silent to a stream that \
                         it cannot open, or the server cannot reach {target}"
                    ),
                };
                format!("the Shadowsocks server {shown}: {what}: {cause}")
            }
            OpenError::Chunk(e) => format!("the Shadowsocks server {shown}: its first chunk did not open: {e}"),
            OpenError::Cut(why) => format!("the Shadowsocks server {shown}: {why}"),
        }
    }
}

/// `10 s`, or `0.4 s` for a wait of a part of a second.
fn seconds(wait: Duration) -> String {
    match wait.subsec_millis() {
        0 => format!("{} s", wait.as_secs()),
        _ => format!("{:.1} s", wait.as_secs_f64()),
    }
}

/// A stream to `host:port` through `node`.
pub async fn open(node: &Node, host: &str, port: u16, dial: &Dial<'_>) -> Result<Opened, OpenError> {
    let header = codec::address(host, port).map_err(OpenError::Target)?;
    let proxy = match dial.proxy {
        ProxyChoice::Direct => None,
        ProxyChoice::Via(proxy) => Some(proxy.to_string()),
        ProxyChoice::FromEnvironment => crate::dial::proxy_from_env(&node.host).ok().flatten().map(|p| p.to_string()),
    };
    let started = Instant::now();
    let mut tcp = crate::dial::dial(&node.host, node.port, dial.proxy, dial.timeout).await.map_err(OpenError::Dial)?;
    let master = node.master_key();
    let mut encoder = Encoder::new(node.method, &master).map_err(|e| OpenError::Send(e.to_string()))?;
    let mut first = Vec::new();
    encoder.seal(&header, &mut first).map_err(|e| OpenError::Send(e.to_string()))?;
    let sent = async {
        tcp.write_all(&first).await?;
        tcp.flush().await
    };
    match tokio::time::timeout(dial.timeout, sent).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(OpenError::Send(e.to_string())),
        Err(_) => return Err(OpenError::Send(format!("no progress in {} s", dial.timeout.as_secs()))),
    }
    let mut decoder = Decoder::new(node.method, &master);
    let (early, answered_in) = match dial.answer {
        Some(wait) => match first_chunk(&mut tcp, &mut decoder, wait, dial.silence_is_ready).await {
            Ok(Some(plain)) => (plain, Some(started.elapsed())),
            Ok(None) => (Vec::new(), None),
            Err(Waited::Silent(ended)) => return Err(OpenError::Silent { ended, after: wait, proxy }),
            Err(Waited::Chunk(e)) => return Err(OpenError::Chunk(e)),
            Err(Waited::Cut(why)) => return Err(OpenError::Cut(why)),
        },
        None => (Vec::new(), None),
    };
    Ok(Opened { carried: carry::spawn(tcp, encoder, decoder, early), answered_in })
}

/// How the wait for the first chunk failed.
enum Waited {
    Silent(Option<String>),
    Chunk(ChunkError),
    Cut(String),
}

/// The plaintext of the server's first chunk within `wait`; `None` when it
/// was silent and `silence_is_ready`.
async fn first_chunk<S: AsyncRead + Unpin>(
    stream: &mut S,
    decoder: &mut Decoder,
    wait: Duration,
    silence_is_ready: bool,
) -> Result<Option<Vec<u8>>, Waited> {
    let deadline = Instant::now() + wait;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        if let Some(plain) = decoder.chunk().map_err(Waited::Chunk)? {
            return Ok(Some(plain));
        }
        let read = tokio::time::timeout_at(deadline, stream.read(&mut buf)).await;
        let untouched = decoder.untouched();
        match read {
            Err(_) if untouched && silence_is_ready => return Ok(None),
            Err(_) if untouched => return Err(Waited::Silent(None)),
            Err(_) => {
                return Err(Waited::Cut(format!("its answer stopped inside its first chunk ({})", seconds(wait))))
            }
            Ok(Ok(0)) if untouched => return Err(Waited::Silent(Some("it closed the connection".into()))),
            Ok(Ok(0)) => return Err(Waited::Cut("its answer ended inside its first chunk".into())),
            Ok(Ok(n)) => decoder.feed(&buf[..n]),
            Ok(Err(e)) if untouched => return Err(Waited::Silent(Some(format!("the connection failed ({e})")))),
            Ok(Err(e)) => return Err(Waited::Cut(format!("the connection failed inside its first chunk: {e}"))),
        }
    }
}
