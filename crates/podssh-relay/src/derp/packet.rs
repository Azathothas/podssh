//! The packets of a link, inside DERP's: podssh's own, as a server forwards
//! any bytes from one key to another. Each starts with [`MAGIC`], its kind
//! and the id of its link, which the client chose; anyone who knows a key may
//! send to it, so a packet that is not one of these is dropped. Numbers are
//! big-endian. Sans-IO.
//!
//! | Kind | Packet | Body |
//! | --- | --- | --- |
//! | 1 | `OPEN` | nothing: a client opens the link, and sends it again until the node answers |
//! | 2 | `DATA` | the segment's number, 8 bytes; a flag byte (1: the end of this direction); the bytes |
//! | 3 | `ACK` | the next number expected, 8 bytes; the window in segments, 2 bytes; a count byte, then each range of numbers held past it, 8 and 8 bytes |
//! | 4 | `RESET` | the reason, UTF-8: the link is gone |

use std::fmt;

/// What each packet of a link starts with: podssh's DERP link, version 1.
pub const MAGIC: &[u8; 4] = b"pdl1";
/// A link's id.
pub const ID: usize = 16;
/// The magic, the kind and the id.
pub const HEAD: usize = MAGIC.len() + 1 + ID;
/// The number and the flag of a `DATA`.
pub const DATA_HEAD: usize = 9;
/// The most ranges of an `ACK`.
pub const MAX_RANGES: usize = 8;
/// The longest reason of a `RESET`.
pub const MAX_REASON: usize = 200;

/// A link's id: 16 random bytes of the client's.
pub type LinkId = [u8; ID];

const OPEN: u8 = 1;
const DATA: u8 = 2;
const ACK: u8 = 3;
const RESET: u8 = 4;
const FIN: u8 = 1;

/// What a receiver holds: each number below `next`, and those of `ranges`
/// (each from its start to before its end), with room for `window`
/// segments from `next` on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ack {
    pub next: u64,
    pub window: u16,
    pub ranges: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Open,
    Data { seq: u64, fin: bool, data: Vec<u8> },
    Ack(Ack),
    Reset(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub link: LinkId,
    pub body: Body,
}

/// Why a packet is not one of a link's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// No magic: another program's packet, or none.
    NotOurs,
    /// A kind that this version has not.
    Kind(u8),
    /// Too short, or ranges that do not hold.
    Malformed(&'static str),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::NotOurs => f.write_str("a packet that is not podssh's"),
            PacketError::Kind(kind) => write!(f, "a packet of the kind {kind}, which this podssh has not"),
            PacketError::Malformed(why) => write!(f, "a malformed packet: {why}"),
        }
    }
}

impl std::error::Error for PacketError {}

fn head(kind: u8, link: &LinkId, more: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEAD + more);
    out.extend_from_slice(MAGIC);
    out.push(kind);
    out.extend_from_slice(link);
    out
}

/// A `DATA` of `link`, written from the segment's bytes with no copy before.
pub fn data(link: &LinkId, seq: u64, fin: bool, bytes: &[u8]) -> Vec<u8> {
    let mut out = head(DATA, link, DATA_HEAD + bytes.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.push(if fin { FIN } else { 0 });
    out.extend_from_slice(bytes);
    out
}

impl Packet {
    pub fn encode(&self) -> Vec<u8> {
        match &self.body {
            Body::Open => head(OPEN, &self.link, 0),
            Body::Data { seq, fin, data: bytes } => data(&self.link, *seq, *fin, bytes),
            Body::Ack(ack) => {
                let ranges = &ack.ranges[..ack.ranges.len().min(MAX_RANGES)];
                let mut out = head(ACK, &self.link, 11 + 16 * ranges.len());
                out.extend_from_slice(&ack.next.to_be_bytes());
                out.extend_from_slice(&ack.window.to_be_bytes());
                out.push(ranges.len() as u8);
                for (start, end) in ranges {
                    out.extend_from_slice(&start.to_be_bytes());
                    out.extend_from_slice(&end.to_be_bytes());
                }
                out
            }
            Body::Reset(reason) => {
                let reason = cut(reason);
                let mut out = head(RESET, &self.link, reason.len());
                out.extend_from_slice(reason.as_bytes());
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Packet, PacketError> {
        if bytes.len() < HEAD || &bytes[..MAGIC.len()] != MAGIC {
            return Err(PacketError::NotOurs);
        }
        let kind = bytes[MAGIC.len()];
        let mut link = [0u8; ID];
        link.copy_from_slice(&bytes[MAGIC.len() + 1..HEAD]);
        let body = &bytes[HEAD..];
        let body = match kind {
            OPEN => Body::Open,
            DATA => {
                if body.len() < DATA_HEAD {
                    return Err(PacketError::Malformed("a DATA with no number"));
                }
                Body::Data { seq: u64_at(body, 0), fin: body[8] & FIN != 0, data: body[DATA_HEAD..].to_vec() }
            }
            ACK => Body::Ack(ack(body)?),
            // The peer's words go to a terminal: made safe first.
            RESET => {
                let reason = String::from_utf8_lossy(&body[..body.len().min(MAX_REASON)]);
                Body::Reset(podssh_ws::text::one_line(&reason))
            }
            other => return Err(PacketError::Kind(other)),
        };
        Ok(Packet { link, body })
    }
}

fn u64_at(body: &[u8], at: usize) -> u64 {
    let mut eight = [0u8; 8];
    eight.copy_from_slice(&body[at..at + 8]);
    u64::from_be_bytes(eight)
}

fn ack(body: &[u8]) -> Result<Ack, PacketError> {
    if body.len() < 11 {
        return Err(PacketError::Malformed("an ACK too short"));
    }
    let next = u64_at(body, 0);
    let window = u16::from_be_bytes([body[8], body[9]]);
    let count = usize::from(body[10]);
    if count > MAX_RANGES || body.len() < 11 + 16 * count {
        return Err(PacketError::Malformed("an ACK whose ranges do not fit"));
    }
    let mut ranges = Vec::with_capacity(count);
    for i in 0..count {
        let (start, end) = (u64_at(body, 11 + 16 * i), u64_at(body, 19 + 16 * i));
        if start <= next || end <= start {
            return Err(PacketError::Malformed("an ACK range that is empty or below its next number"));
        }
        ranges.push((start, end));
    }
    Ok(Ack { next, window, ranges })
}

/// A reason cut to [`MAX_REASON`] bytes, at a character's boundary.
fn cut(reason: &str) -> &str {
    let mut end = reason.len().min(MAX_REASON);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: LinkId = [0xab; ID];

    fn round(body: Body) -> Body {
        Packet::decode(&Packet { link: LINK, body }.encode()).unwrap().body
    }

    #[test]
    fn each_kind_comes_back_as_it_went() {
        assert_eq!(round(Body::Open), Body::Open);
        let data = Body::Data { seq: 1 << 40, fin: true, data: b"bytes".to_vec() };
        assert_eq!(round(data.clone()), data);
        let ack = Body::Ack(Ack { next: 7, window: 24, ranges: vec![(9, 12), (20, 21)] });
        assert_eq!(round(ack.clone()), ack);
        assert_eq!(round(Body::Reset("gone".into())), Body::Reset("gone".into()));
        let empty = Body::Data { seq: 0, fin: false, data: Vec::new() };
        assert_eq!(round(empty.clone()), empty);
    }

    #[test]
    fn a_data_written_from_its_bytes_is_the_packet_of_the_same_body() {
        let body = Body::Data { seq: 3, fin: false, data: vec![1, 2, 3] };
        assert_eq!(data(&LINK, 3, false, &[1, 2, 3]), Packet { link: LINK, body }.encode());
        assert_eq!(data(&LINK, 3, false, &[]).len(), HEAD + DATA_HEAD);
    }

    #[test]
    fn a_packet_of_another_program_or_kind_or_shape_is_refused() {
        assert_eq!(Packet::decode(b"TS\xF0\x9F\x92\xac disco"), Err(PacketError::NotOurs));
        assert_eq!(Packet::decode(&head(9, &LINK, 0)), Err(PacketError::Kind(9)));
        assert!(matches!(Packet::decode(&head(DATA, &LINK, 0)), Err(PacketError::Malformed(_))));
        let mut bad = Packet { link: LINK, body: Body::Ack(Ack { next: 5, window: 1, ranges: vec![(6, 8)] }) }.encode();
        // A range below the next number.
        bad[HEAD + 11..HEAD + 19].copy_from_slice(&4u64.to_be_bytes());
        assert!(matches!(Packet::decode(&bad), Err(PacketError::Malformed(_))));
        let mut short = head(ACK, &LINK, 0);
        short.extend_from_slice(&[0u8; 10]);
        assert!(matches!(Packet::decode(&short), Err(PacketError::Malformed(_))));
    }

    #[test]
    fn a_long_reason_is_cut_at_a_character_and_made_safe() {
        let long = "é".repeat(MAX_REASON);
        let Body::Reset(reason) = round(Body::Reset(long)) else { panic!("a reset") };
        assert!(reason.len() <= MAX_REASON);
        assert!(reason.chars().all(|c| c == 'é'));
        let Body::Reset(reason) = round(Body::Reset("a\x1b[2Jb".into())) else { panic!("a reset") };
        assert!(!reason.contains('\x1b'));
    }

    #[test]
    fn no_more_than_eight_ranges_go_out() {
        let ranges: Vec<(u64, u64)> = (0..12).map(|i| (10 + 3 * i, 11 + 3 * i)).collect();
        let Body::Ack(ack) = round(Body::Ack(Ack { next: 1, window: 0, ranges })) else { panic!("an ack") };
        assert_eq!(ack.ranges.len(), MAX_RANGES);
    }
}
