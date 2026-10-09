//! The little HTTP/1.1 podssh needs besides the WebSocket upgrade: one request
//! and one response over an already-open stream, with bounded sizes. It reads
//! `Content-Length`, `Transfer-Encoding: chunked`, and read-until-close bodies.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The longest response head accepted.
const MAX_HEAD: usize = 16 * 1024;

/// One HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    /// Header names lower-cased, values trimmed, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// The first value of a header, by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_str())
    }

    /// The body as text, for error messages: lossy UTF-8 made safe for a
    /// terminal (see [`crate::text::one_line`]), cut to `max` characters.
    pub fn body_text(&self, max: usize) -> String {
        let text = crate::text::one_line(&String::from_utf8_lossy(&self.body));
        match text.char_indices().nth(max) {
            Some((cut, _)) => format!("{}…", &text[..cut]),
            None => text.to_string(),
        }
    }
}

/// Send one request and read the response, closing nothing. `extra_headers`
/// must not contain CR or LF (they are refused). The response body is capped
/// at `max_body` bytes.
pub async fn exchange<S>(
    stream: &mut S,
    method: &str,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    max_body: usize,
) -> std::io::Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for part in [method, host, path].into_iter().chain(extra_headers.iter().flat_map(|(n, v)| [*n, *v])) {
        if part.contains(['\r', '\n']) {
            return Err(invalid("a request line or header contains CR or LF"));
        }
    }
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: podssh/{}\r\nConnection: close\r\n",
        env!("CARGO_PKG_VERSION")
    );
    for (name, value) in extra_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() || method != "GET" {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    read_response(stream, Vec::new(), max_body).await
}

/// Read a response whose first bytes may already be in `buffered`.
pub async fn read_response<S>(stream: &mut S, mut buffered: Vec<u8>, max_body: usize) -> std::io::Result<Response>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(end) = find(&buffered, b"\r\n\r\n") {
            break end + 4;
        }
        if buffered.len() > MAX_HEAD {
            return Err(invalid("no end of the response headers within 16 KiB"));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the connection closed before the response headers ended",
            ));
        }
        buffered.extend_from_slice(&chunk[..n]);
    };
    let rest = buffered.split_off(head_end);
    let head = String::from_utf8_lossy(&buffered).into_owned();
    let (status, reason, headers) = parse_head(&head).map_err(invalid)?;
    let mut response = Response { status, reason, headers, body: Vec::new() };
    response.body = read_body(stream, &response, rest, max_body).await?;
    Ok(response)
}

/// Parse a response head into status, reason and lower-cased headers.
pub fn parse_head(head: &str) -> Result<(u16, String, Vec<(String, String)>), String> {
    let (status, reason) = crate::dial::parse_status_line(head)?;
    let headers = head
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Ok((status, reason, headers))
}

async fn read_body<S>(stream: &mut S, head: &Response, mut have: Vec<u8>, max_body: usize) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    // No body for 1xx, 204 and 304.
    if head.status < 200 || head.status == 204 || head.status == 304 {
        return Ok(Vec::new());
    }
    let chunked = head.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let length = head.header("content-length").and_then(|v| v.parse::<usize>().ok());
    let mut chunk = [0u8; 4096];
    loop {
        if chunked {
            if let Some(body) = decode_chunked(&have, max_body).map_err(invalid)? {
                return Ok(body);
            }
        } else if let Some(len) = length {
            if len > max_body {
                return Err(invalid("the response body is larger than allowed"));
            }
            if have.len() >= len {
                have.truncate(len);
                return Ok(have);
            }
        } else if have.len() > max_body {
            return Err(invalid("the response body is larger than allowed"));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            // A read-until-close body ends here; a framed one was cut short.
            return if chunked || length.is_some() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the connection closed in the middle of the response body",
                ))
            } else {
                Ok(have)
            };
        }
        have.extend_from_slice(&chunk[..n]);
        if have.len() > max_body.saturating_mul(2).saturating_add(MAX_HEAD) {
            return Err(invalid("the response body is larger than allowed"));
        }
    }
}

/// Decode a complete chunked body. `Ok(None)` means more bytes are needed.
/// Trailers are ignored; chunk extensions are skipped.
pub fn decode_chunked(raw: &[u8], max_body: usize) -> Result<Option<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let Some(line_end) = find(&raw[at..], b"\r\n") else { return Ok(None) };
        let size_line =
            std::str::from_utf8(&raw[at..at + line_end]).map_err(|_| "a chunk size line is not text".to_string())?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| format!("bad chunk size {size_hex:?}"))?;
        at += line_end + 2;
        if size == 0 {
            // Optional trailers, then the final CRLF.
            return match find(&raw[at..], b"\r\n\r\n") {
                Some(_) => Ok(Some(out)),
                None if raw[at..].starts_with(b"\r\n") => Ok(Some(out)),
                None => Ok(None),
            };
        }
        if out.len() + size > max_body {
            return Err("the response body is larger than allowed".into());
        }
        if raw.len() < at + size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&raw[at..at + size]);
        if &raw[at + size..at + size + 2] != b"\r\n" {
            return Err("a chunk is not followed by CRLF".into());
        }
        at += size + 2;
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn invalid(why: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, why.into())
}
