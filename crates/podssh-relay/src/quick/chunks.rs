//! HTTP/1.1's chunked coding (RFC 9112, section 7.1), sans-IO, as a stream:
//! a funnel's TARGET may answer in chunks, and the edge takes a body's bytes
//! alone, so each chunk's data goes on as it comes, never the whole body in
//! memory (T-180). The encoder gives a request's body to TARGET in chunks
//! where the visitor named no length.

/// The longest line of a chunk's size, with its extensions; and of a
/// trailer's field.
const MAX_LINE: usize = 4096;

/// Where the decoder stands.
#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    /// The size line, read so far.
    Size(Vec<u8>),
    /// The bytes of data left in this chunk.
    Data(u64),
    /// The CRLF after a chunk's data: how many of its two bytes are left.
    DataEnd(u8),
    /// A trailer's line, read so far; an empty line ends the body.
    Trailer(Vec<u8>),
    Done,
}

/// A chunked body, decoded as its bytes come.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunks {
    state: State,
}

impl Default for Chunks {
    fn default() -> Chunks {
        Chunks { state: State::Size(Vec::new()) }
    }
}

impl Chunks {
    /// Whether the last chunk and the trailer came.
    pub fn done(&self) -> bool {
        self.state == State::Done
    }

    /// Read `input`, put the data that it holds in `out`, and say how much
    /// of `input` was taken: all of it, unless the body ended within it.
    /// `Err` for a body that is not chunked as RFC 9112 says.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, String> {
        let mut at = 0;
        while at < input.len() {
            match &mut self.state {
                State::Done => return Ok(at),
                State::Size(line) => {
                    let b = input[at];
                    at += 1;
                    if b != b'\n' {
                        line.push(b);
                        if line.len() > MAX_LINE {
                            return Err("a chunk's size line is too long".into());
                        }
                        continue;
                    }
                    let size = size_of(line)?;
                    self.state = match size {
                        0 => State::Trailer(Vec::new()),
                        n => State::Data(n),
                    };
                }
                State::Data(left) => {
                    let n = (*left).min((input.len() - at) as u64) as usize;
                    out.extend_from_slice(&input[at..at + n]);
                    at += n;
                    *left -= n as u64;
                    if *left == 0 {
                        self.state = State::DataEnd(2);
                    }
                }
                State::DataEnd(left) => {
                    let want = if *left == 2 { b'\r' } else { b'\n' };
                    let b = input[at];
                    at += 1;
                    // A bare LF after the data is read as its end, as servers do.
                    if *left == 2 && b == b'\n' {
                        self.state = State::Size(Vec::new());
                        continue;
                    }
                    if b != want {
                        return Err("a chunk's data does not end with CRLF".into());
                    }
                    *left -= 1;
                    if *left == 0 {
                        self.state = State::Size(Vec::new());
                    }
                }
                State::Trailer(line) => {
                    let b = input[at];
                    at += 1;
                    if b != b'\n' {
                        line.push(b);
                        if line.len() > MAX_LINE {
                            return Err("a trailer's line is too long".into());
                        }
                        continue;
                    }
                    // The trailer's fields are dropped: the edge has sent the
                    // answer's headers already.
                    let empty = line.is_empty() || line.as_slice() == b"\r";
                    self.state = if empty { State::Done } else { State::Trailer(Vec::new()) };
                }
            }
        }
        Ok(at)
    }
}

/// The size of a chunk's line, its extensions after `;` ignored.
fn size_of(line: &[u8]) -> Result<u64, String> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let digits = line.split(|b| *b == b';').next().unwrap_or_default();
    let text = std::str::from_utf8(digits).map_err(|_| "a chunk's size is not text".to_string())?.trim();
    if text.is_empty() || text.len() > 15 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("a chunk's size {text:?} is not hex digits"));
    }
    u64::from_str_radix(text, 16).map_err(|e| e.to_string())
}

/// `data` as one chunk; none for no data, as an empty chunk would end the
/// body.
pub fn encode(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = format!("{:x}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

/// The last chunk, with no trailer.
pub const LAST: &[u8] = b"0\r\n\r\n";

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9112's form, with an extension and a trailer, fed whole and a
    /// byte at a time: the same data, and the bytes after the body left.
    #[test]
    fn a_chunked_body_decodes_whole_or_a_byte_at_a_time() {
        let body = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nExpires: never\r\n\r\nNEXT";
        let mut whole = Chunks::default();
        let mut out = Vec::new();
        let taken = whole.feed(body, &mut out).unwrap();
        assert_eq!(out, b"Wikipedia in\r\n\r\nchunks.");
        assert!(whole.done());
        assert_eq!(&body[taken..], b"NEXT");
        let (mut slow, mut out) = (Chunks::default(), Vec::new());
        for b in body.iter().take(body.len() - 4) {
            assert_eq!(slow.feed(std::slice::from_ref(b), &mut out).unwrap(), 1);
        }
        assert_eq!(out, b"Wikipedia in\r\n\r\nchunks.");
        assert!(slow.done());
    }

    #[test]
    fn a_bad_size_or_a_missing_crlf_is_refused() {
        let mut out = Vec::new();
        assert!(Chunks::default().feed(b"zz\r\n", &mut out).is_err());
        assert!(Chunks::default().feed(b"\r\n", &mut out).is_err(), "no digits");
        assert!(Chunks::default().feed(b"2\r\nabX", &mut out).is_err());
        assert!(Chunks::default().feed(b"ffffffffffffffff0\r\n", &mut out).is_err(), "too large");
    }

    #[test]
    fn the_encoder_s_chunks_decode_back() {
        let mut wire = encode(b"hello ");
        wire.extend(encode(b""));
        wire.extend(encode(&[7u8; 300]));
        wire.extend_from_slice(LAST);
        let (mut chunks, mut out) = (Chunks::default(), Vec::new());
        assert_eq!(chunks.feed(&wire, &mut out).unwrap(), wire.len());
        assert!(chunks.done());
        assert_eq!(&out[..6], b"hello ");
        assert_eq!(out.len(), 306);
    }
}
