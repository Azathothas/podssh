//! connect-ip's capsules over HTTP/2 (RFC 9297, section 3.2), sans-IO: a
//! type and a length, each a variable-length integer of QUIC (RFC 9000,
//! section 16), then the payload. WARP's edge carries each IP packet in a
//! capsule of type 0, DATAGRAM, with no context ID before the packet where
//! RFC 9484 puts one (connect-ip-go's fork, `client_h2.go`, read on
//! 2026-10-31; GitHub #63's first comment says the same). A capsule of
//! another type is skipped, as that client skips it.

/// The type of a capsule that holds one IP packet.
pub const DATAGRAM: u64 = 0;
/// The largest value of a variable-length integer.
pub const MAX_VARINT: u64 = (1 << 62) - 1;
/// The longest capsule that the reader keeps: an IP packet is 65,535 bytes
/// at most, and a capsule of another type is no larger in any client read.
/// A longer one ends the tunnel, rather than a buffer that grows.
pub const MAX_CAPSULE: u64 = 1 << 20;

/// `value` as a variable-length integer, in the fewest bytes, appended to
/// `out`. A value above [`MAX_VARINT`] has no encoding; none is sent here.
pub fn put_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => out.extend_from_slice(&(0x4000 | value as u16).to_be_bytes()),
        16_384..=1_073_741_823 => out.extend_from_slice(&(0x8000_0000 | value as u32).to_be_bytes()),
        _ => out.extend_from_slice(&(0xc000_0000_0000_0000 | value.min(MAX_VARINT)).to_be_bytes()),
    }
}

/// The variable-length integer at the start of `buf`, and its length; `None`
/// while its bytes have not all come.
pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let value = bytes[1..].iter().fold(u64::from(first & 0x3f), |value, byte| (value << 8) | u64::from(*byte));
    Some((value, len))
}

/// The capsule of one IP packet, as the edge reads it.
pub fn datagram(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + 4);
    put_varint(&mut out, DATAGRAM);
    put_varint(&mut out, packet.len() as u64);
    out.extend_from_slice(packet);
    out
}

/// One capsule, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    pub kind: u64,
    pub payload: Vec<u8>,
}

/// The capsules of a stream's bytes, as they come in pieces: HTTP/2 cuts a
/// body where its frames end, not where capsules do.
#[derive(Debug, Default)]
pub struct Reader {
    buf: Vec<u8>,
    /// Where the next capsule starts in `buf`: the bytes before it were read,
    /// and go at the next push, so that a read copies nothing.
    start: usize,
    /// The capsules of another type than [`DATAGRAM`] that were skipped.
    pub skipped: u64,
}

impl Reader {
    /// The next bytes of the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole capsule, `None` until its last byte has come, or why
    /// the stream holds no capsule that podssh can read.
    pub fn next_capsule(&mut self) -> Result<Option<Capsule>, String> {
        let rest = &self.buf[self.start..];
        let Some((kind, kind_len)) = read_varint(rest) else { return Ok(None) };
        let Some((len, len_len)) = read_varint(&rest[kind_len..]) else { return Ok(None) };
        if len > MAX_CAPSULE {
            return Err(format!("the edge sent a capsule of {len} bytes, more than podssh reads ({MAX_CAPSULE})"));
        }
        let head = kind_len + len_len;
        let Some(payload) = rest.get(head..head + len as usize) else { return Ok(None) };
        let capsule = Capsule { kind, payload: payload.to_vec() };
        self.start += head + len as usize;
        if kind != DATAGRAM {
            self.skipped += 1;
        }
        Ok(Some(capsule))
    }

    /// The next IP packet: each capsule of another type before it is
    /// skipped.
    pub fn next_packet(&mut self) -> Result<Option<Vec<u8>>, String> {
        while let Some(capsule) = self.next_capsule()? {
            if capsule.kind == DATAGRAM {
                return Ok(Some(capsule.payload));
            }
        }
        Ok(None)
    }

    /// The bytes that wait for the rest of their capsule.
    pub fn waiting(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9000's own examples (Appendix A.1), in both directions: each
    /// value in its encoding, and the two-byte form of 37 read too.
    #[test]
    fn the_varints_of_rfc_9000_read_and_write() {
        let examples: [(&[u8], u64); 4] = [
            (&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c], 151_288_809_941_952_652),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for (bytes, value) in examples {
            assert_eq!(read_varint(bytes), Some((value, bytes.len())), "{bytes:02x?}");
            let mut out = Vec::new();
            put_varint(&mut out, value);
            assert_eq!(out, bytes, "{value}");
        }
        assert_eq!(read_varint(&[0x40, 0x25]), Some((37, 2)));
        // Each byte of an encoding must have come.
        assert_eq!(read_varint(&[0x9d, 0x7f, 0x3e]), None);
        assert_eq!(read_varint(&[]), None);
    }

    /// Each value at each edge of a length takes the fewest bytes, and reads
    /// back, as connect-ip-go's `TestParseVarint` checks its own.
    #[test]
    fn each_edge_of_a_length_reads_back() {
        for (value, len) in [(0, 1), (63, 1), (64, 2), (16_383, 2), (16_384, 4), (1_073_741_823, 4), (1 << 30, 8)] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            assert_eq!(out.len(), len, "{value}");
            assert_eq!(read_varint(&out), Some((value, len)), "{value}");
        }
    }

    /// The bytes that connect-ip-go's `TestH2DatagramStreamSendDatagram`
    /// expects of the payload 45 00 00 14: type 0, length 4, the packet,
    /// with no context ID.
    #[test]
    fn a_packet_goes_as_connect_ip_go_sends_it() {
        assert_eq!(datagram(&[0x45, 0x00, 0x00, 0x14]), [0x00, 0x04, 0x45, 0x00, 0x00, 0x14]);
        // A packet of 1280 bytes takes two bytes of length: 0x4500.
        let long = datagram(&[0u8; 1280]);
        assert_eq!(&long[..3], &[0x00, 0x45, 0x00]);
        assert_eq!(long.len(), 1283);
    }

    /// connect-ip-go's `TestH2DatagramStreamReceiveDatagram`: a capsule of
    /// type 7 ("ignore"), then a datagram of 60 00 00 00, gives that packet.
    #[test]
    fn a_capsule_of_another_type_is_skipped_as_connect_ip_go_skips_it() {
        let mut other = vec![0x07, 0x06];
        other.extend_from_slice(b"ignore");
        let mut reader = Reader::default();
        reader.push(&[other, vec![0x00, 0x04, 0x60, 0x00, 0x00, 0x00]].concat());
        assert_eq!(reader.next_packet(), Ok(Some(vec![0x60, 0x00, 0x00, 0x00])));
        assert_eq!(reader.skipped, 1);
        assert_eq!(reader.next_packet(), Ok(None));
        assert_eq!(reader.waiting(), 0);
    }

    /// A capsule cut at each byte comes whole once its last byte has come,
    /// and the next one after it.
    #[test]
    fn a_capsule_in_pieces_comes_whole() {
        let packet: Vec<u8> = (0..200u8).collect();
        let bytes = [datagram(&packet), datagram(b"second")].concat();
        for cut in 1..bytes.len() {
            let mut reader = Reader::default();
            reader.push(&bytes[..cut]);
            let mut got = Vec::new();
            while let Some(p) = reader.next_packet().unwrap() {
                got.push(p);
            }
            reader.push(&bytes[cut..]);
            while let Some(p) = reader.next_packet().unwrap() {
                got.push(p);
            }
            assert_eq!(got, vec![packet.clone(), b"second".to_vec()], "cut at {cut}");
        }
    }

    /// A length beyond what podssh keeps ends the reading, before any byte
    /// of it is kept.
    #[test]
    fn a_capsule_too_long_is_refused() {
        let mut head = Vec::new();
        put_varint(&mut head, DATAGRAM);
        put_varint(&mut head, MAX_CAPSULE + 1);
        let mut reader = Reader::default();
        reader.push(&head);
        let why = reader.next_capsule().unwrap_err();
        assert!(why.contains("more than podssh reads"), "{why}");
    }
}
