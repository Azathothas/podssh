//! The messages of IAP's TCP forwarding (T-351), version 4 of its relay
//! protocol, with no I/O. Each WebSocket message holds one: a tag of two
//! bytes, big-endian, then its fields. Read in gcloud 570.0.0
//! (`googlecloudsdk/api_lib/compute/iap_tunnel_websocket_utils.py`) and in
//! Google's IAP Desktop (`Google.Solutions.Iap/Protocol/SshRelayFormat.cs`):
//!
//! - the connect's success (tag 1): a length of four bytes, then the id of
//!   the session, which a reconnect names;
//! - a reconnect's success (2): eight bytes, the client's bytes that the
//!   server took before the link was lost;
//! - data (4): a length of four bytes, then at most 16 KiB of the stream;
//! - an acknowledgement (7): eight bytes, the bytes of the stream received
//!   so far;
//! - a long close (10): a code and a length of four bytes each, then the
//!   reason (IAP Desktop's; gcloud skips it as a tag that it does not know).
//!
//! A tag that podssh does not know is skipped, and so are bytes after a
//! message's fields, as both clients skip them.

use std::fmt;

pub const TAG_CONNECT_SUCCESS_SID: u16 = 0x0001;
pub const TAG_RECONNECT_SUCCESS_ACK: u16 = 0x0002;
pub const TAG_DATA: u16 = 0x0004;
pub const TAG_ACK: u16 = 0x0007;
pub const TAG_LONG_CLOSE: u16 = 0x000a;

/// The most that one data message carries, as both clients send.
pub const MAX_DATA: usize = 16 * 1024;
/// The longest message that podssh sends: data of [`MAX_DATA`] and its head.
pub const MAX_MESSAGE: usize = 6 + MAX_DATA;

/// One message of the relay protocol.
#[derive(Clone, PartialEq, Eq)]
pub enum Message {
    /// The session is open: its id, for a reconnect.
    ConnectSuccessSid(Vec<u8>),
    /// A reconnect took the session up: the client's bytes that the server
    /// took.
    ReconnectSuccessAck(u64),
    /// Bytes of the stream.
    Data(Vec<u8>),
    /// The bytes of the peer's stream received so far.
    Ack(u64),
    /// The server's reason to end the session, longer than a Close holds.
    LongClose { code: u32, reason: String },
    /// A tag that podssh does not know.
    Unknown(u16),
}

impl fmt::Debug for Message {
    // The id lets a reconnect take the session up, and data is the
    // session's: neither is shown, only their lengths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::ConnectSuccessSid(sid) => write!(f, "ConnectSuccessSid({} bytes)", sid.len()),
            Message::ReconnectSuccessAck(n) => write!(f, "ReconnectSuccessAck({n})"),
            Message::Data(data) => write!(f, "Data({} bytes)", data.len()),
            Message::Ack(n) => write!(f, "Ack({n})"),
            Message::LongClose { code, reason } => write!(f, "LongClose({code}, {reason:?})"),
            Message::Unknown(tag) => write!(f, "Unknown({tag})"),
        }
    }
}

/// Why a message could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer bytes than the fields of the message need.
    Short { tag: Option<u16>, need: usize, have: usize },
    /// Data to send of no byte, or of more than [`MAX_DATA`].
    DataSize(usize),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Short { tag: None, have, .. } => {
                write!(f, "a message of IAP of {have} bytes, too short for its tag")
            }
            FrameError::Short { tag: Some(tag), need, have } => {
                write!(f, "a message of IAP with tag {tag} needs {need} bytes and has {have}")
            }
            FrameError::DataSize(n) => write!(f, "data of {n} bytes: IAP takes 1 to {MAX_DATA} in a message"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Data of `payload`: 1 to [`MAX_DATA`] bytes.
pub fn data(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.is_empty() || payload.len() > MAX_DATA {
        return Err(FrameError::DataSize(payload.len()));
    }
    let mut out = Vec::with_capacity(6 + payload.len());
    out.extend_from_slice(&TAG_DATA.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// The acknowledgement of `received` bytes of the server's stream.
pub fn ack(received: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(&TAG_ACK.to_be_bytes());
    out.extend_from_slice(&received.to_be_bytes());
    out
}

/// The message in one WebSocket message.
pub fn decode(message: &[u8]) -> Result<Message, FrameError> {
    let Some((tag, body)) = message.split_first_chunk::<2>() else {
        return Err(FrameError::Short { tag: None, need: 2, have: message.len() });
    };
    let tag = u16::from_be_bytes(*tag);
    match tag {
        TAG_CONNECT_SUCCESS_SID => array(tag, body).map(|sid| Message::ConnectSuccessSid(sid.to_vec())),
        TAG_RECONNECT_SUCCESS_ACK => number(tag, body).map(Message::ReconnectSuccessAck),
        TAG_DATA => array(tag, body).map(|data| Message::Data(data.to_vec())),
        TAG_ACK => number(tag, body).map(Message::Ack),
        TAG_LONG_CLOSE => long_close(body),
        other => Ok(Message::Unknown(other)),
    }
}

/// A length of four bytes and as many bytes after it.
fn array(tag: u16, body: &[u8]) -> Result<&[u8], FrameError> {
    let short = |need: usize| FrameError::Short { tag: Some(tag), need: need.saturating_add(2), have: body.len() + 2 };
    let Some((len, rest)) = body.split_first_chunk::<4>() else { return Err(short(4)) };
    let len = u32::from_be_bytes(*len) as usize;
    rest.get(..len).ok_or_else(|| short(4usize.saturating_add(len)))
}

/// A number of eight bytes.
fn number(tag: u16, body: &[u8]) -> Result<u64, FrameError> {
    let Some((n, _)) = body.split_first_chunk::<8>() else {
        return Err(FrameError::Short { tag: Some(tag), need: 10, have: body.len() + 2 });
    };
    Ok(u64::from_be_bytes(*n))
}

fn long_close(body: &[u8]) -> Result<Message, FrameError> {
    let short = |need: usize| FrameError::Short {
        tag: Some(TAG_LONG_CLOSE),
        need: need.saturating_add(2),
        have: body.len() + 2,
    };
    let Some((code, rest)) = body.split_first_chunk::<4>() else { return Err(short(8)) };
    let Some((len, rest)) = rest.split_first_chunk::<4>() else { return Err(short(8)) };
    let len = u32::from_be_bytes(*len) as usize;
    let reason = rest.get(..len).ok_or_else(|| short(8usize.saturating_add(len)))?;
    // The server's text goes to the user's terminal.
    let reason = crate::text::one_line(&String::from_utf8_lossy(reason));
    Ok(Message::LongClose { code: u32::from_be_bytes(*code), reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    // Written by gcloud 570.0.0's own client (its IapTunnelWebSocket, over
    // the TLS of a stand-in on the loopback), 2026-10-31: the data of
    // `SSH-2.0-capture\r\n`, and the acknowledgement of 49174 bytes that it
    // sent once 3 x 16 KiB and 22 bytes had come.
    const GCLOUD_DATA: &str = "0004000000115353482d322e302d636170747572650d0a";
    const GCLOUD_ACK: &str = "0007000000000000c016";
    // After a reconnect whose success said 10 of its 17 bytes: the 7 that
    // it sent again, then its acknowledgement of the 5 bytes it had.
    const GCLOUD_RESENT: &str = "00040000000770747572650d0a";
    const GCLOUD_ACK_5: &str = "00070000000000000005";

    #[test]
    fn iap_messages_that_gcloud_wrote_decode() {
        assert_eq!(decode(&hex(GCLOUD_DATA)).unwrap(), Message::Data(b"SSH-2.0-capture\r\n".to_vec()));
        assert_eq!(decode(&hex(GCLOUD_ACK)).unwrap(), Message::Ack(49174));
        assert_eq!(decode(&hex(GCLOUD_RESENT)).unwrap(), Message::Data(b"pture\r\n".to_vec()));
        assert_eq!(decode(&hex(GCLOUD_ACK_5)).unwrap(), Message::Ack(5));
        // Its data message of 16 KiB: the head, then the bytes.
        let mut big = hex("000400004000");
        big.extend((0..16384).map(|i| (i % 256) as u8));
        let Message::Data(got) = decode(&big).unwrap() else { panic!("data") };
        assert_eq!(got.len(), 16384);
        assert!(got.iter().enumerate().all(|(i, b)| *b == (i % 256) as u8));
    }

    #[test]
    fn iap_messages_that_podssh_writes_are_those_of_gcloud() {
        assert_eq!(data(b"SSH-2.0-capture\r\n").unwrap(), hex(GCLOUD_DATA));
        assert_eq!(ack(49174), hex(GCLOUD_ACK));
        assert_eq!(data(b"pture\r\n").unwrap(), hex(GCLOUD_RESENT));
        assert_eq!(ack(5), hex(GCLOUD_ACK_5));
        assert_eq!(data(&[]), Err(FrameError::DataSize(0)));
        assert_eq!(data(&[0; MAX_DATA + 1]), Err(FrameError::DataSize(MAX_DATA + 1)));
        assert_eq!(data(&[7; MAX_DATA]).unwrap().len(), MAX_MESSAGE);
    }

    /// The server's messages as the stand-in of the capture sent them, which
    /// gcloud took: its connect's success with the id `sid-of-the-capture`,
    /// and a reconnect's success of 10 bytes; IAP Desktop's long close.
    #[test]
    fn iap_messages_of_the_server_decode() {
        let sid = decode(&hex("0001000000127369642d6f662d7468652d63617074757265")).unwrap();
        assert_eq!(sid, Message::ConnectSuccessSid(b"sid-of-the-capture".to_vec()));
        assert_eq!(decode(&hex("0002000000000000000a")).unwrap(), Message::ReconnectSuccessAck(10));
        let close = decode(&hex("000a00000fbd0000000868656c6c6f1b5b41")).unwrap();
        assert_eq!(close, Message::LongClose { code: 4029, reason: "hello[A".into() }, "ESC is taken out");
        assert_eq!(decode(&hex("0003")).unwrap(), Message::Unknown(3));
        // Bytes after the fields are skipped, as gcloud skips them.
        assert_eq!(decode(&hex("0007000000000000000501")).unwrap(), Message::Ack(5));
    }

    #[test]
    fn iap_short_messages_are_refused_with_their_tag() {
        assert_eq!(decode(&[]), Err(FrameError::Short { tag: None, need: 2, have: 0 }));
        assert_eq!(decode(&[0]), Err(FrameError::Short { tag: None, need: 2, have: 1 }));
        assert_eq!(decode(&hex("000400")), Err(FrameError::Short { tag: Some(4), need: 6, have: 3 }));
        assert_eq!(decode(&hex("00040000000541")), Err(FrameError::Short { tag: Some(4), need: 11, have: 7 }));
        assert_eq!(decode(&hex("00070000")), Err(FrameError::Short { tag: Some(7), need: 10, have: 4 }));
        assert_eq!(decode(&hex("00020000000000")), Err(FrameError::Short { tag: Some(2), need: 10, have: 7 }));
        assert!(decode(&hex("000a0000")).is_err());
        assert!(decode(&hex("000a000000010000000541")).is_err());
        // A length near 4 GiB is no allocation, only a refusal.
        assert!(decode(&hex("0001ffffffff41")).is_err());
        let said = decode(&hex("000400")).unwrap_err().to_string();
        assert!(said.contains("tag 4"), "{said}");
    }

    #[test]
    fn iap_debug_shows_no_id_and_no_data() {
        let sid = format!("{:?}", Message::ConnectSuccessSid(b"secret-sid".to_vec()));
        let data = format!("{:?}", Message::Data(b"secret-bytes".to_vec()));
        assert!(!sid.contains("secret") && sid.contains("10 bytes"), "{sid}");
        assert!(!data.contains("secret") && data.contains("12 bytes"), "{data}");
    }
}
