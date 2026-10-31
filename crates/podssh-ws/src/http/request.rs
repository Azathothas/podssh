//! The head of an HTTP/1 request, as a server of podssh reads it (T-367): the
//! CONNECT of `podssh pipe http-listen:`, and the upgrade of `ws-listen:`
//! (T-368). The request line and its headers within 16 KiB, as a response's
//! head is read. A line ends with CRLF or a bare LF (RFC 9112 section 2.2);
//! a bare CR, a space before a header's colon, a folded line and a control
//! byte are refused, as a head that two readers would read two ways is how a
//! request is smuggled past one of them.

use tokio::io::{AsyncRead, AsyncReadExt};

/// The longest request head read, as the longest response head.
pub const MAX_HEAD: usize = 16 * 1024;

/// A request's head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// As sent: a method is case-sensitive (RFC 9110 section 9.1).
    pub method: String,
    /// The request-target, as sent.
    pub target: String,
    /// The minor version of HTTP/1: 0 or 1.
    pub minor: u8,
    /// Header names lower-cased, values trimmed, in arrival order.
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// The first value of a header, by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_str())
    }

    /// Whether a header of `name` is present at all.
    pub fn has(&self, name: &str) -> bool {
        self.header(name).is_some()
    }

    /// Whether the lists of the headers of `name` hold `token`, with any case:
    /// `Connection: keep-alive, Upgrade` holds `upgrade` (RFC 9110 section 5.6.1).
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(n, _)| *n == name)
            .flat_map(|(_, v)| v.split(','))
            .any(|item| item.trim().eq_ignore_ascii_case(token))
    }
}

/// Why a request's head was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The connection ended, or failed, before the head did: nobody to answer.
    Gone(String),
    /// No end of the head within [`MAX_HEAD`]: 431.
    TooLarge,
    /// Not a request of HTTP/1: 400, or 505 for another version of HTTP.
    Malformed { status: u16, why: String },
}

impl RequestError {
    /// The status that answers it, when a client is there to read one.
    pub fn status(&self) -> Option<u16> {
        match self {
            RequestError::Gone(_) => None,
            RequestError::TooLarge => Some(431),
            RequestError::Malformed { status, .. } => Some(*status),
        }
    }
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::Gone(why) => write!(f, "the client left before its request ended: {why}"),
            RequestError::TooLarge => write!(f, "no end of the request's headers within {} KiB", MAX_HEAD / 1024),
            RequestError::Malformed { why, .. } => write!(f, "not a request of HTTP/1.1: {why}"),
        }
    }
}

impl std::error::Error for RequestError {}

fn malformed(why: impl Into<String>) -> RequestError {
    RequestError::Malformed { status: 400, why: why.into() }
}

/// Read a request's head from `stream`, whose first bytes may be in
/// `buffered`: the request, and the bytes that came after its head, which a
/// client of a tunnel may send before the answer, and which belong to it.
pub async fn read_request<S>(stream: &mut S, mut buffered: Vec<u8>) -> Result<(Request, Vec<u8>), RequestError>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 4096];
    let (start, end) = loop {
        if let Some(found) = head_bounds(&buffered) {
            break found;
        }
        if buffered.len() > MAX_HEAD {
            return Err(RequestError::TooLarge);
        }
        let n = stream.read(&mut chunk).await.map_err(|e| RequestError::Gone(e.to_string()))?;
        if n == 0 {
            return Err(RequestError::Gone("the connection closed".into()));
        }
        buffered.extend_from_slice(&chunk[..n]);
    };
    if end - start > MAX_HEAD {
        return Err(RequestError::TooLarge);
    }
    let rest = buffered.split_off(end);
    Ok((parse_request(&buffered[start..])?, rest))
}

/// Where the head is in `buf`: after the empty lines that may come first
/// (RFC 9112 section 2.2), up to and with the empty line that ends it.
fn head_bounds(buf: &[u8]) -> Option<(usize, usize)> {
    let mut start = 0;
    loop {
        if buf[start..].starts_with(b"\r\n") {
            start += 2;
        } else if buf[start..].starts_with(b"\n") {
            start += 1;
        } else {
            break;
        }
    }
    let mut at = start;
    while let Some(lf) = buf[at..].iter().position(|&b| b == b'\n') {
        let next = at + lf + 1;
        if buf[next..].starts_with(b"\n") {
            return Some((start, next + 1));
        }
        if buf[next..].starts_with(b"\r\n") {
            return Some((start, next + 2));
        }
        at = next;
    }
    None
}

/// A request's head: its request line, then its headers, each line ended by
/// CRLF or LF, and the empty line.
pub fn parse_request(head: &[u8]) -> Result<Request, RequestError> {
    let mut lines = Vec::new();
    for raw in head.split(|&b| b == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.contains(&b'\r') {
            return Err(malformed("a bare CR in a line"));
        }
        if line.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(malformed("a control byte in a line"));
        }
        lines.push(line);
    }
    // The split leaves the empty line, and what follows its LF.
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let Some((first, fields)) = lines.split_first() else { return Err(malformed("no request line")) };
    let (method, target, minor) = request_line(first)?;
    let mut headers = Vec::with_capacity(fields.len());
    for field in fields {
        headers.push(header_field(field)?);
    }
    Ok(Request { method, target, minor, headers })
}

/// `METHOD SP TARGET SP HTTP/1.x`, one space each (RFC 9112 section 3).
fn request_line(line: &[u8]) -> Result<(String, String, u8), RequestError> {
    let text = std::str::from_utf8(line).map_err(|_| malformed("the request line is not ASCII"))?;
    let parts: Vec<&str> = text.split(' ').collect();
    let [method, target, version] = parts[..] else {
        return Err(malformed("the request line is not METHOD TARGET HTTP/1.1"));
    };
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(malformed("the method is not a token"));
    }
    if target.is_empty() || !target.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(malformed("the request-target is empty or not ASCII"));
    }
    let minor = match version {
        "HTTP/1.1" => 1,
        "HTTP/1.0" => 0,
        other if other.starts_with("HTTP/") => {
            return Err(RequestError::Malformed { status: 505, why: format!("{other}: this server speaks HTTP/1.1") });
        }
        _ => return Err(malformed("the request line names no version of HTTP")),
    };
    Ok((method.to_string(), target.to_string(), minor))
}

/// `NAME: VALUE`, with no space before the colon (RFC 9112 section 5.1) and
/// no folded line (section 5.2).
fn header_field(line: &[u8]) -> Result<(String, String), RequestError> {
    if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
        return Err(malformed("a folded header line"));
    }
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return Err(malformed("a header line with no colon"));
    };
    let name = &line[..colon];
    if name.is_empty() || !name.iter().copied().all(is_tchar) {
        return Err(malformed("a header's name is not a token, or a space comes before its colon"));
    }
    let value = String::from_utf8_lossy(&line[colon + 1..]);
    let name = String::from_utf8_lossy(name).to_ascii_lowercase();
    Ok((name, value.trim_matches([' ', '\t']).to_string()))
}

/// A character of a token (RFC 9110 section 5.6.2).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The target of `CONNECT HOST:PORT`, the authority form of RFC 9110 section
/// 9.3.6: a name or an IPv4 address, or an IPv6 address in brackets, and a
/// port from 1, the host checked as each target of a road is.
pub fn connect_target(target: &str) -> Result<(String, u16), String> {
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']').ok_or_else(|| format!("{target:?}: '[' is not closed"))?;
            (host, after.strip_prefix(':').ok_or_else(|| format!("{target:?} names no port"))?)
        }
        None => match target.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, port),
            Some(_) => return Err(format!("{target:?}: an IPv6 address goes in brackets, [ADDR]:PORT")),
            None => return Err(format!("{target:?} names no port: CONNECT takes HOST:PORT")),
        },
    };
    let port = port.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{target:?}: not a port"))?;
    if target.starts_with('[') && host.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(format!("{target:?}: brackets hold an IPv6 address"));
    }
    crate::names::check_target(host)?;
    Ok((host.to_string(), port))
}

/// The reason phrase of each status that podssh's servers send.
pub fn reason(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "Connection Established",
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        426 => "Upgrade Required",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}

/// A refusal of `status`: its reason phrase, with `words` after it when there
/// are some, `headers`, and `words` again as a body of text. Each part is
/// made one line, as the words may be a peer's. The connection closes after
/// it: these servers answer one request on a connection.
pub fn refusal(status: u16, words: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let words = crate::text::one_line(words);
    let mut phrase = reason(status).to_string();
    if !words.is_empty() {
        phrase.push_str(": ");
        phrase.push_str(&cut(&words, 200));
    }
    let body = if words.is_empty() { String::new() } else { format!("{words}\n") };
    let mut out = format!("HTTP/1.1 {status} {phrase}\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{}: {}\r\n", crate::text::one_line(name), crate::text::one_line(value)));
    }
    if !body.is_empty() {
        out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    }
    out.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()));
    out.into_bytes()
}

/// The answer to a CONNECT whose tunnel is open: no header, and no length,
/// which a 2xx answer to CONNECT must not have (RFC 9110 section 9.3.6).
pub fn established() -> Vec<u8> {
    format!("HTTP/1.1 200 {}\r\n\r\n", reason(200)).into_bytes()
}

/// `text` cut to `max` bytes on a character boundary.
fn cut(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Request, RequestError> {
        parse_request(text.as_bytes())
    }

    /// The CONNECT that curl 8 sends through `-x`, as `curl -v` shows it.
    #[test]
    fn a_connect_of_curl_reads_with_its_target_and_headers() {
        let head = "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nUser-Agent: curl/8.11.1\r\n\
                    Proxy-Connection: Keep-Alive\r\n\r\n";
        let request = parse(head).unwrap();
        assert_eq!((request.method.as_str(), request.target.as_str()), ("CONNECT", "example.org:443"));
        assert_eq!(request.minor, 1);
        assert_eq!(request.header("HOST"), Some("example.org:443"));
        assert_eq!(request.header("user-agent"), Some("curl/8.11.1"));
        assert!(request.has("proxy-connection") && !request.has("proxy-authorization"));
        assert_eq!(connect_target(&request.target), Ok(("example.org".to_string(), 443)));
    }

    #[test]
    fn a_line_may_end_with_lf_alone_and_empty_lines_may_come_first() {
        let request = parse("CONNECT [2001:db8::1]:22 HTTP/1.0\nHost: x\n\n").unwrap();
        assert_eq!((request.minor, request.header("host")), (0, Some("x")));
        assert_eq!(head_bounds(b"\r\n\nGET / HTTP/1.1\r\n\r\nrest"), Some((3, 21)));
        assert_eq!(head_bounds(b"GET / HTTP/1.1\nHost: x\n\nrest"), Some((0, 24)));
        assert_eq!(head_bounds(b"GET / HTTP/1.1\r\nHost: x\r\n"), None, "the head has not ended");
        assert_eq!(connect_target("[2001:db8::1]:22"), Ok(("2001:db8::1".to_string(), 22)));
    }

    /// Each head that two readers could read two ways is refused (400), and
    /// another version of HTTP gets 505.
    #[test]
    fn a_head_that_could_be_read_two_ways_is_refused() {
        for bad in [
            "CONNECT a:1 HTTP/1.1\r\nHost : a\r\n\r\n",
            "CONNECT a:1 HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
            "CONNECT a:1 HTTP/1.1\r\nX: a\rb\r\n\r\n",
            "CONNECT a:1 HTTP/1.1\r\nX: \x00\r\n\r\n",
            "CONNECT  a:1 HTTP/1.1\r\n\r\n",
            "CONNECT a:1\r\n\r\n",
            "CONNECT a:1 HTTP/1.1 x\r\n\r\n",
            "CONN(ECT a:1 HTTP/1.1\r\n\r\n",
            "CONNECT a:1 HTTP/1.1\r\nno colon\r\n\r\n",
            "CONNECT a:1 SPDY/3\r\n\r\n",
        ] {
            let err = parse(bad).expect_err(bad);
            assert_eq!(err.status(), Some(400), "{bad:?}: {err}");
        }
        assert_eq!(parse("PRI * HTTP/2.0\r\n\r\n").unwrap_err().status(), Some(505));
    }

    #[test]
    fn a_list_header_holds_its_tokens_in_any_case() {
        let request = parse("GET / HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\n").unwrap();
        assert!(request.has_token("connection", "upgrade") && request.has_token("Upgrade", "websocket"));
        assert!(!request.has_token("connection", "close"));
    }

    #[test]
    fn a_connect_target_is_host_and_port_and_checked_as_each_target() {
        for bad in ["example.org", "example.org:0", "example.org:x", "2001:db8::1:22", "[x]:22", "[::1", "a/b:22"] {
            assert!(connect_target(bad).is_err(), "{bad}");
        }
        assert!(connect_target("a b:22").is_err() && connect_target(":22").is_err());
        assert_eq!(connect_target("127.0.0.1:8080"), Ok(("127.0.0.1".to_string(), 8080)));
    }

    /// The bytes after the head are the tunnel's, kept for it; a client that
    /// leaves first has nobody to answer, and a head over 16 KiB gets 431.
    #[tokio::test]
    async fn the_bytes_after_the_head_are_kept_and_a_long_head_is_431() {
        let (mut ours, mut theirs) = tokio::io::duplex(64 * 1024);
        let sent = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n\x16\x03\x01".to_vec();
        tokio::io::AsyncWriteExt::write_all(&mut theirs, &sent).await.unwrap();
        let (request, rest) = read_request(&mut ours, Vec::new()).await.unwrap();
        assert_eq!((request.target.as_str(), rest.as_slice()), ("a.test:443", &b"\x16\x03\x01"[..]));
        drop(theirs);
        let gone = read_request(&mut ours, Vec::new()).await.unwrap_err();
        assert_eq!(gone.status(), None, "{gone}");
        let long = format!("GET / HTTP/1.1\r\nX: {}\r\n", "y".repeat(MAX_HEAD));
        let (mut ours, mut theirs) = tokio::io::duplex(64 * 1024);
        tokio::io::AsyncWriteExt::write_all(&mut theirs, long.as_bytes()).await.unwrap();
        assert_eq!(read_request(&mut ours, Vec::new()).await.unwrap_err(), RequestError::TooLarge);
    }

    #[test]
    fn a_refusal_says_its_words_on_one_line_and_closes() {
        let answer = String::from_utf8(refusal(403, "not in the ALLOW list\r\nX: y", &[("A", "b")])).unwrap();
        assert!(answer.starts_with("HTTP/1.1 403 Forbidden: not in the ALLOW list X: y\r\nA: b\r\n"), "{answer}");
        assert!(answer.contains("Connection: close\r\n") && answer.ends_with("\r\n\r\nnot in the ALLOW list X: y\n"));
        let bare = String::from_utf8(refusal(405, "", &[("Allow", "CONNECT")])).unwrap();
        assert_eq!(
            bare,
            "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(established(), b"HTTP/1.1 200 Connection Established\r\n\r\n");
    }
}
