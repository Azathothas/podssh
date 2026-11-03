//! The probes' HTTP/1.1 (T-325): one request on one connection, and the
//! moment that each part of its answer came; a body sent in pieces at their
//! moments while the answer is read, so that an answer before the body's end
//! (a refusal of its size) is seen. TLS checked for the host with doctor's
//! trust, or plain TCP for an `http://` URL, through the proxy of the
//! environment as each road dials. Each wait has its bound.

use std::time::Duration;

use podssh_relay::relay::Relay;
use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::url::{Stream, USER_AGENT};
use podssh_ws::Trust;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

/// The bound on the connection, its TLS and the request's head.
pub(super) const CONNECT_WAIT: Duration = Duration::from_secs(10);
/// The probes' paths at podssh's relay role.
pub(super) const PREFIX: &str = "/v1/probe";
/// The longest head of an answer.
const MAX_HEAD: usize = 16 * 1024;
/// The bytes of an answer's body that are kept; the rest are counted.
const KEPT: usize = 64 * 1024;
/// What a body is made of: a request's body is compressed by no path.
static PATTERN: [u8; 16 * 1024] = [b'p'; 16 * 1024];

const FORM: &str = "give https://HOST[:PORT][/PATH] or http://HOST[:PORT][/PATH]";

/// A server of the probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::doctor) struct Server {
    pub(super) tls: bool,
    /// A name or an address, an IPv6 one with no brackets.
    pub(super) host: String,
    pub(super) port: u16,
    /// The probes' paths are under it: [`PREFIX`] when the URL names none.
    pub(super) prefix: String,
}

impl Server {
    /// `https://HOST[:PORT][/PATH]` or `http://...`. A user and a password
    /// are refused, as a credential does not go in a URL, and so are a query
    /// and a fragment, as the probes add their own.
    pub(in crate::doctor) fn parse(text: &str) -> Result<Server, String> {
        let (tls, rest) = match text.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => (true, rest),
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => (false, rest),
            // The text is not shown: it may hold a secret.
            _ => return Err(FORM.into()),
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err("the URL takes no user and no password: a credential does not go in a URL".into());
        }
        if tail.contains(['?', '#']) {
            return Err("the URL takes no query and no fragment: the probes add their own".into());
        }
        let (host, port) = host_port(authority, if tls { 443 } else { 80 })?;
        let path = tail.trim_end_matches('/');
        if !path.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("the URL's path holds a space, a control character or a byte that is not ASCII".into());
        }
        let prefix = if path.is_empty() { PREFIX.to_string() } else { path.to_string() };
        Ok(Server { tls, host, port, prefix })
    }

    /// The relay host `relay`, as a server of the probes at its role's paths.
    pub(in crate::doctor) fn of_relay(relay: &Relay) -> Server {
        Server { tls: true, host: relay.host.clone(), port: relay.port, prefix: PREFIX.to_string() }
    }

    /// The value of `Host`: the port only when it is not the scheme's own.
    fn host_header(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let default = if self.tls { 443 } else { 80 };
        match self.port == default {
            true => host,
            false => format!("{host}:{}", self.port),
        }
    }

    /// The server as a line names it: its scheme, host, port and prefix.
    pub(in crate::doctor) fn shown(&self) -> String {
        format!("{}://{}{}", if self.tls { "https" } else { "http" }, self.host_header(), self.prefix)
    }

    /// The target of the probe `tail` (`/drip?...`), under the prefix.
    pub(super) fn target(&self, tail: &str) -> String {
        format!("{}{tail}", self.prefix)
    }

    /// TCP through the proxy of the environment, and TLS for the host.
    async fn open(&self, trust: &Trust) -> Result<Stream, String> {
        let proxy = ProxyChoice::FromEnvironment;
        if self.tls {
            let tls = podssh_ws::client::open_tls(&self.host, self.port, &self.host, trust, &proxy, CONNECT_WAIT)
                .await
                .map_err(|e| e.to_string())?;
            return Ok(Stream::Tls(Box::new(tls)));
        }
        let tcp = dial::dial(&self.host, self.port, &proxy, CONNECT_WAIT).await.map_err(|e| e.to_string())?;
        Ok(Stream::Plain(tcp))
    }
}

/// `HOST`, `HOST:PORT`, `[IPV6]` or `[IPV6]:PORT`; `default` with no port.
fn host_port(authority: &str, default: u16) -> Result<(String, u16), String> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']').ok_or("the URL's '[' is not closed")?;
            host.parse::<std::net::Ipv6Addr>().map_err(|_| "the URL's brackets hold no IPv6 address")?;
            match after {
                "" => (host, None),
                _ => (host, Some(after.strip_prefix(':').ok_or("the URL has text after its ']'")?)),
            }
        }
        None => {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            podssh_ws::names::check_host(host).map_err(|why| format!("the URL's host: {why}"))?;
            (host, port)
        }
    };
    let port = match port {
        None => default,
        Some(text) => text.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{text:?} is not a port"))?,
    };
    Ok((host.to_string(), port))
}

/// When each part of an answer came, from the moment its request was sent.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct Timed {
    /// The status and its reason; none when no head came.
    pub(super) head: Option<(u16, String)>,
    pub(super) head_at: Option<Duration>,
    /// Each read of the body: when it came, and the body's bytes by then.
    pub(super) reads: Vec<(Duration, u64)>,
    /// The first bytes of the body.
    pub(super) body: Vec<u8>,
    pub(super) end: End,
}

/// How an answer ended.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum End {
    /// Whole: the length that its head named came, or the last chunk, or
    /// the server's end of a body with neither.
    Whole(Duration),
    /// The connection ended, or failed, before the answer did.
    Cut { at: Duration, why: String },
    /// Nothing more came within the probe's bound.
    Waited(Duration),
}

impl Default for End {
    fn default() -> Self {
        End::Waited(Duration::ZERO)
    }
}

impl Timed {
    /// When the body's first and last bytes came.
    pub(super) fn body_span(&self) -> Option<(Duration, Duration)> {
        Some((self.reads.first()?.0, self.reads.last()?.0))
    }

    /// The body's bytes, as counted.
    pub(super) fn body_bytes(&self) -> u64 {
        self.reads.last().map_or(0, |(_, n)| *n)
    }
}

/// The words of an error that ended a read, by its kind, never by the
/// system's words, which differ between systems.
pub(super) fn cut_words(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => "a reset".into(),
        std::io::ErrorKind::UnexpectedEof => "an end with no close of TLS".into(),
        _ => podssh_ws::text::one_line(&e.to_string()),
    }
}

/// Read an answer from `reader` until it is whole, it is cut, or `until`.
async fn read_answer<R: AsyncRead + Unpin>(reader: &mut R, sent: Instant, until: Instant) -> Timed {
    let mut timed = Timed::default();
    let (mut head, mut chunk) = (Vec::new(), vec![0u8; 64 * 1024]);
    let (mut length, mut chunked, mut got, mut tail) = (None::<u64>, false, 0u64, Vec::new());
    loop {
        let n = match tokio::time::timeout_at(until, reader.read(&mut chunk)).await {
            Err(_) => {
                timed.end = End::Waited(sent.elapsed());
                return timed;
            }
            Ok(Err(e)) => {
                timed.end = End::Cut { at: sent.elapsed(), why: cut_words(&e) };
                return timed;
            }
            Ok(Ok(0)) => {
                let at = sent.elapsed();
                timed.end = match (&timed.head, length, chunked) {
                    // A body with no length ends with its connection.
                    (Some(_), None, false) => End::Whole(at),
                    _ => End::Cut { at, why: "an end of the connection".into() },
                };
                return timed;
            }
            Ok(Ok(n)) => n,
        };
        let at = sent.elapsed();
        let mut fresh = &chunk[..n];
        if timed.head.is_none() {
            head.extend_from_slice(fresh);
            let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
                if head.len() > MAX_HEAD {
                    timed.end = End::Cut { at, why: "no end of the answer's head within 16 KiB".into() };
                    return timed;
                }
                continue;
            };
            let text = String::from_utf8_lossy(&head[..end]).into_owned();
            let Ok((status, reason, headers)) = podssh_ws::http::parse_head(&text) else {
                timed.end = End::Cut { at, why: "an answer that is not HTTP/1.1".into() };
                return timed;
            };
            let named = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.to_ascii_lowercase());
            chunked = named("transfer-encoding").is_some_and(|v| v.contains("chunked"));
            length = if chunked { None } else { named("content-length").and_then(|v| v.parse().ok()) };
            if status < 200 || status == 204 || status == 304 {
                length = Some(0);
            }
            timed.head = Some((status, podssh_ws::text::one_line(&reason)));
            timed.head_at = Some(at);
            let rest = head.len() - end;
            fresh = &chunk[n - rest..n];
        }
        if !fresh.is_empty() {
            got += fresh.len() as u64;
            timed.reads.push((at, got));
            let room = KEPT.saturating_sub(timed.body.len());
            timed.body.extend_from_slice(&fresh[..fresh.len().min(room)]);
            tail.extend_from_slice(fresh);
            let keep = tail.len().saturating_sub(5);
            tail.drain(..keep);
        }
        // A chunked body is timed as it came, its framing with it.
        let whole = match length {
            Some(length) => got >= length,
            None => chunked && tail.ends_with(b"0\r\n\r\n"),
        };
        if whole {
            timed.end = End::Whole(at);
            return timed;
        }
    }
}

/// `GET target` on a connection of its own, its answer read until `wait`.
pub(super) async fn get(server: &Server, trust: &Trust, target: &str, wait: Duration) -> Result<Timed, String> {
    let mut stream = server.open(trust).await?;
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nCache-Control: no-cache\r\n\
         Connection: close\r\n\r\n",
        server.host_header()
    );
    let wrote = async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await
    };
    match tokio::time::timeout(CONNECT_WAIT, wrote).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("the request could not be sent: {}", cut_words(&e))),
        Err(_) => return Err(format!("the request could not be sent within {} s", CONNECT_WAIT.as_secs())),
    }
    let sent = Instant::now();
    Ok(read_answer(&mut stream, sent, sent + wait).await)
}

/// A piece of a body: its bytes, sent at `at` from the request's head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Piece {
    pub(super) at: Duration,
    pub(super) bytes: usize,
}

/// `POST target` with a body of `pieces`, each at its moment, while its
/// answer is read until `wait`: an answer that comes before the body's end
/// (a refusal of its size) ends the sending, and a sending that fails
/// leaves the answer to tell why.
pub(super) async fn post(
    server: &Server,
    trust: &Trust,
    target: &str,
    pieces: &[Piece],
    wait: Duration,
) -> Result<Timed, String> {
    let stream = server.open(trust).await?;
    let total: usize = pieces.iter().map(|p| p.bytes).sum();
    let head = format!(
        "POST {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {total}\r\nConnection: close\r\n\r\n",
        server.host_header()
    );
    let (mut reader, mut writer) = tokio::io::split(stream);
    let sent = Instant::now();
    let send = async {
        writer.write_all(head.as_bytes()).await?;
        writer.flush().await?;
        for piece in pieces {
            tokio::time::sleep_until(sent + piece.at).await;
            let mut left = piece.bytes;
            while left > 0 {
                let n = left.min(PATTERN.len());
                writer.write_all(&PATTERN[..n]).await?;
                left -= n;
            }
            writer.flush().await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let read = read_answer(&mut reader, sent, sent + wait);
    tokio::pin!(send, read);
    let mut sending = true;
    let answer = loop {
        tokio::select! {
            _ = &mut send, if sending => sending = false,
            answer = &mut read => break answer,
        }
    };
    Ok(answer)
}
