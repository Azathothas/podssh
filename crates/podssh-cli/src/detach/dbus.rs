//! A minimal client of D-Bus over a Unix socket of this host (T-381, Q61):
//! the EXTERNAL login with this user's id, `Hello` on a bus, and one method
//! call whose reply it reads, on the wire format of the D-Bus specification
//! (little-endian, each value at its alignment from the message's start).
//! It carries what a detached run asks the user's systemd, and nothing more.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// The types of message that a reply can be.
const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;
/// The header fields that a call names and a reply is read for.
const PATH: u8 = 1;
const INTERFACE: u8 = 2;
const MEMBER: u8 = 3;
const ERROR_NAME: u8 = 4;
const REPLY_SERIAL: u8 = 5;
const DESTINATION: u8 = 6;
const SIGNATURE: u8 = 8;
/// A message larger than this is no reply of ours.
const MESSAGE_MAX: usize = 1 << 20;
/// Messages read for one reply at most: a bus sends signals too.
const MESSAGES_MAX: usize = 64;

/// The bytes of a message's header or body, each value at its alignment.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn align(&mut self, n: usize) {
        while !self.buf.len().is_multiple_of(n) {
            self.buf.push(0);
        }
    }
    pub fn byte(&mut self, b: u8) {
        self.buf.push(b);
    }
    pub fn u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    /// A string or an object path: its length, its bytes and a NUL.
    pub fn string(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }
    /// A signature: a byte of length, its bytes and a NUL.
    pub fn signature(&mut self, s: &str) {
        self.buf.push(s.len() as u8);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }
    /// An array: its length in bytes, then `elements` at `align`; the
    /// length counts no padding before the first element.
    pub fn array(&mut self, align: usize, elements: impl FnOnce(&mut Writer)) {
        self.u32(0);
        let at = self.buf.len() - 4;
        self.align(align);
        let start = self.buf.len();
        elements(self);
        let len = (self.buf.len() - start) as u32;
        self.buf[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }
}

/// A method call: its header, then `body` of `signature`.
pub struct Call<'a> {
    pub destination: Option<&'a str>,
    pub path: &'a str,
    pub interface: &'a str,
    pub member: &'a str,
    pub signature: &'a str,
    pub body: &'a [u8],
}

/// The bytes of `call` with `serial`.
pub fn message(serial: u32, call: &Call<'_>) -> Vec<u8> {
    let mut h = Writer::default();
    for b in [b'l', METHOD_CALL, 0, 1] {
        h.byte(b);
    }
    h.u32(call.body.len() as u32);
    h.u32(serial);
    h.array(8, |h| {
        let mut field = |code: u8, kind: &str, value: &str| {
            h.align(8);
            h.byte(code);
            h.signature(kind);
            match kind {
                "g" => h.signature(value),
                _ => h.string(value),
            }
        };
        field(PATH, "o", call.path);
        field(INTERFACE, "s", call.interface);
        field(MEMBER, "s", call.member);
        if let Some(destination) = call.destination {
            field(DESTINATION, "s", destination);
        }
        if !call.signature.is_empty() {
            field(SIGNATURE, "g", call.signature);
        }
    });
    h.align(8);
    h.buf.extend_from_slice(call.body);
    h.buf
}

/// A connection, logged in.
pub struct Bus {
    stream: UnixStream,
    serial: u32,
}

impl Bus {
    /// Connect to the socket at `path` and log in as this user; on a bus
    /// (not a peer such as systemd's private socket), `Hello` too. Each read
    /// and write waits `limit` at most.
    pub fn connect(path: &Path, bus: bool, limit: Duration) -> Result<Bus, String> {
        let stream = UnixStream::connect(path).map_err(|e| format!("{}: {e}", path.display()))?;
        stream.set_read_timeout(Some(limit)).map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(limit)).map_err(|e| e.to_string())?;
        let mut me = Bus { stream, serial: 0 };
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() }.to_string();
        let hex: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
        me.stream.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes()).map_err(|e| e.to_string())?;
        let answer = me.line()?;
        if !answer.starts_with("OK ") {
            return Err(format!("the login was refused: {answer}"));
        }
        me.stream.write_all(b"BEGIN\r\n").map_err(|e| e.to_string())?;
        if bus {
            let hello = Call {
                destination: Some("org.freedesktop.DBus"),
                path: "/org/freedesktop/DBus",
                interface: "org.freedesktop.DBus",
                member: "Hello",
                signature: "",
                body: &[],
            };
            me.call(&hello)?;
        }
        Ok(me)
    }

    /// One line of the login, up to its CR LF.
    fn line(&mut self) -> Result<String, String> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\r\n") {
            if line.len() > 512 {
                return Err("a line of the login of more than 512 bytes".into());
            }
            match self.stream.read(&mut byte) {
                Ok(1) => line.push(byte[0]),
                Ok(_) => return Err("the socket ended during the login".into()),
                Err(e) => return Err(format!("the login: {e}")),
            }
        }
        Ok(String::from_utf8_lossy(&line[..line.len() - 2]).into_owned())
    }

    /// Send `call` and read its reply: the reply's body, or the error's
    /// name and message.
    pub fn call(&mut self, call: &Call<'_>) -> Result<Vec<u8>, String> {
        self.serial += 1;
        let serial = self.serial;
        self.stream.write_all(&message(serial, call)).map_err(|e| format!("{}: {e}", call.member))?;
        for _ in 0..MESSAGES_MAX {
            let reply = self.read()?;
            if reply.reply_serial != Some(serial) {
                continue;
            }
            return match reply.kind {
                METHOD_RETURN => Ok(reply.body),
                ERROR => Err(format!(
                    "{}: {}{}",
                    call.member,
                    reply.error.unwrap_or_else(|| "an error".into()),
                    first_string(&reply.body).map_or_else(String::new, |m| format!(" ({m})"))
                )),
                other => Err(format!("{}: a reply of the type {other}", call.member)),
            };
        }
        Err(format!("{}: no reply among {MESSAGES_MAX} messages", call.member))
    }

    fn read(&mut self) -> Result<Received, String> {
        let mut fixed = [0u8; 16];
        self.stream.read_exact(&mut fixed).map_err(|e| format!("a reply: {e}"))?;
        let little = match fixed[0] {
            b'l' => true,
            b'B' => false,
            other => return Err(format!("a message of the byte order {other:#x}")),
        };
        let u32_at = |b: &[u8], at: usize| {
            let v = [b[at], b[at + 1], b[at + 2], b[at + 3]];
            if little {
                u32::from_le_bytes(v)
            } else {
                u32::from_be_bytes(v)
            }
        };
        let body_len = u32_at(&fixed, 4) as usize;
        let fields_len = u32_at(&fixed, 12) as usize;
        let header = (16 + fields_len).div_ceil(8) * 8;
        if header + body_len > MESSAGE_MAX {
            return Err(format!("a message of {} bytes", header + body_len));
        }
        let mut rest = vec![0u8; header - 16 + body_len];
        self.stream.read_exact(&mut rest).map_err(|e| format!("a reply: {e}"))?;
        let mut whole = fixed.to_vec();
        whole.extend_from_slice(&rest);
        let mut received = Received { kind: fixed[1], reply_serial: None, error: None, body: whole[header..].to_vec() };
        // The fields: (code, variant), each at 8 from the message's start.
        let mut at = 16;
        while at < 16 + fields_len {
            at = at.div_ceil(8) * 8;
            let code = whole[at];
            let sig_len = whole[at + 1] as usize;
            let kind = whole.get(at + 2..at + 2 + sig_len).unwrap_or_default().to_vec();
            at += 3 + sig_len;
            match kind.as_slice() {
                b"u" => {
                    at = at.div_ceil(4) * 4;
                    if code == REPLY_SERIAL {
                        received.reply_serial = Some(u32_at(&whole, at));
                    }
                    at += 4;
                }
                b"s" | b"o" => {
                    at = at.div_ceil(4) * 4;
                    let len = u32_at(&whole, at) as usize;
                    let text = whole.get(at + 4..at + 4 + len).unwrap_or_default();
                    if code == ERROR_NAME {
                        received.error = Some(String::from_utf8_lossy(text).into_owned());
                    }
                    at += 4 + len + 1;
                }
                b"g" => at += 1 + whole[at] as usize + 1,
                _ => break,
            }
        }
        Ok(received)
    }
}

/// A message read: its type, the serial that it answers, an error's name,
/// and its body.
struct Received {
    kind: u8,
    reply_serial: Option<u32>,
    error: Option<String>,
    body: Vec<u8>,
}

/// The first string of a little-endian body that begins with one.
fn first_string(body: &[u8]) -> Option<String> {
    let len = u32::from_le_bytes(body.get(..4)?.try_into().ok()?) as usize;
    body.get(4..4 + len).map(|b| String::from_utf8_lossy(b).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_array_counts_no_padding_before_its_first_element() {
        let mut w = Writer::default();
        w.byte(7);
        w.array(8, |w| w.u32(5));
        // 1 byte, 3 of padding, the length 4, then the element at 8.
        assert_eq!(w.buf, [7, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0]);
    }

    #[test]
    fn a_call_s_header_ends_at_8_and_names_its_fields() {
        let call = Call {
            destination: Some("org.freedesktop.DBus"),
            path: "/org/freedesktop/DBus",
            interface: "org.freedesktop.DBus",
            member: "Hello",
            signature: "",
            body: &[],
        };
        let m = message(1, &call);
        assert_eq!(&m[..4], &[b'l', METHOD_CALL, 0, 1]);
        assert_eq!(m.len() % 8, 0);
        let fields = u32::from_le_bytes(m[12..16].try_into().unwrap()) as usize;
        assert_eq!((16 + fields).div_ceil(8) * 8, m.len(), "no body");
        assert_eq!(&m[16..20], &[PATH, 1, b'o', 0]);
    }
}
