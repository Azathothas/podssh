//! The probe of UDP before QUIC (T-400): one QUIC packet of a reserved
//! version to the edge's port, which a server of QUIC answers with a Version
//! Negotiation in one round trip (RFC 9000, sections 6 and 17.2.1); cfrs's
//! testers saw the edge answer so, with 27 bytes (`docs/design.md`,
//! "Measured by cfrs's testers"). A network that drops UDP answers nothing,
//! and the node's race gives QUIC up at the probe's end, where QUIC's own
//! handshake waits 5 s at each address. Each socket is connected to one
//! address of the edge: it sends there and takes datagrams from there alone,
//! nothing listens, and a port that the system says is closed (ICMP) comes
//! back on it as a refusal.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::edge::{self, Edge};

/// A version that no server supports, of the form 0x?a?a?a?a that RFC 9000
/// reserves (section 15), as cfrs's testers sent it.
pub const RESERVED: [u8; 4] = [0x1a, 0x2a, 0x3a, 0x4a];
/// The least size of the datagram of a client's first packet: a server
/// answers no smaller one (RFC 9000, section 14.1).
pub const PADDED: usize = 1200;
/// How long the probe waits for its answer: a few round trips to the edge,
/// which answered within 60 ms where T-299 and T-359 measured it.
pub const WAIT: Duration = Duration::from_millis(300);
/// The length of the packet's Destination Connection ID: 8 bytes, the least
/// of a client's first packet (RFC 9000, section 7.2).
const DCID: usize = 8;

/// The probe's packet: a long header of the type Initial with the reserved
/// version, `dcid`, no Source Connection ID, then zeros to [`PADDED`]; a
/// server reads no more of a version that it does not know.
pub fn packet(dcid: &[u8; DCID]) -> Vec<u8> {
    // The Header Form and the Fixed Bit, the type Initial, and four zeros.
    let mut packet = vec![0xc0];
    packet.extend_from_slice(&RESERVED);
    packet.push(DCID as u8);
    packet.extend_from_slice(dcid);
    packet.push(0);
    packet.resize(PADDED, 0);
    packet
}

/// Whether `datagram` is the Version Negotiation that answers the packet of
/// `dcid` (RFC 9000, section 17.2.1; RFC 8999, section 6): the long form,
/// the version 0, the packet's Source Connection ID (none) as its
/// Destination, `dcid` as its Source, and one version or more, none of them
/// the reserved one that the packet named (RFC 9000, section 6.2).
pub fn answers(datagram: &[u8], dcid: &[u8; DCID]) -> bool {
    let Some((&first, rest)) = datagram.split_first() else { return false };
    if first & 0x80 == 0 || rest.len() < 4 || rest[..4] != [0u8; 4] {
        return false;
    }
    let Some((ours, rest)) = connection_id(&rest[4..]) else { return false };
    let Some((theirs, versions)) = connection_id(rest) else { return false };
    ours.is_empty()
        && theirs == &dcid[..]
        && !versions.is_empty()
        && versions.len() % 4 == 0
        && versions.chunks(4).all(|version| version != &RESERVED[..])
}

/// A Connection ID of a long header, its length first: the ID, and the
/// bytes after it.
fn connection_id(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = bytes.split_first()?;
    (rest.len() >= usize::from(len)).then(|| rest.split_at(usize::from(len)))
}

/// One packet to `addr`, from a socket connected to it, and its answer: the
/// round trip, or why none came. The wait is the caller's.
async fn one(addr: SocketAddr) -> Result<Duration, String> {
    let any: SocketAddr = match addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(any).await.map_err(|e| format!("no UDP socket: {e}"))?;
    socket.connect(addr).await.map_err(|e| e.to_string())?;
    let dcid: [u8; DCID] = rand::random();
    let sent = Instant::now();
    socket.send(&packet(&dcid)).await.map_err(|e| e.to_string())?;
    let mut datagram = vec![0u8; 2048];
    loop {
        let n = socket.recv(&mut datagram).await.map_err(|e| e.to_string())?;
        // Another datagram from the address answers no packet of this one.
        if answers(&datagram[..n], &dcid) {
            return Ok(sent.elapsed());
        }
    }
}

/// The probe: a packet to each of `addrs` at once; the address that answered
/// first within `wait`, and its round trip; else what each address did.
pub async fn probe(addrs: &[SocketAddr], wait: Duration) -> Result<(SocketAddr, Duration), String> {
    let mut tries = tokio::task::JoinSet::new();
    for &addr in addrs {
        tries.spawn(async move { (addr, one(addr).await) });
    }
    let mut failed: Vec<(SocketAddr, String)> = Vec::new();
    let answered = tokio::time::timeout(wait, async {
        while let Some(joined) = tries.join_next().await {
            match joined {
                Ok((addr, Ok(took))) => return Some((addr, took)),
                Ok((addr, Err(why))) => failed.push((addr, why)),
                // A try that panicked counts as an address that said nothing.
                Err(_) => {}
            }
        }
        None
    })
    .await;
    // Each try that still waits ends with the set.
    if let Ok(Some(answer)) = answered {
        return Ok(answer);
    }
    let mut said: Vec<String> = failed.iter().map(|(addr, why)| format!("{addr}: {why}")).collect();
    let silent: Vec<String> =
        addrs.iter().filter(|a| !failed.iter().any(|(f, _)| f == *a)).map(|a| a.to_string()).collect();
    if !silent.is_empty() {
        said.push(format!("{} said nothing within {} ms", silent.join(" and "), wait.as_millis()));
    }
    Err(format!("UDP to the edge got no answer to a QUIC packet: {}", said.join("; ")))
}

/// The probe to `found`: the first address of each family of its first
/// region that resolves within the dial's limit.
pub async fn edge(found: &Edge, wait: Duration) -> Result<(SocketAddr, Duration), String> {
    let deadline = Instant::now() + edge::DIAL_LIMIT;
    let mut unresolved = Vec::new();
    for region in &found.regions {
        match podssh_ws::resolve::resolve(region, found.port, deadline).await {
            Ok(addrs) => {
                let firsts = [addrs.iter().find(|a| a.is_ipv4()), addrs.iter().find(|a| a.is_ipv6())];
                let firsts: Vec<SocketAddr> = firsts.into_iter().flatten().copied().collect();
                if !firsts.is_empty() {
                    return probe(&firsts, wait).await;
                }
                unresolved.push(format!("{region}: no address"));
            }
            Err(e) => unresolved.push(format!("{region}: {e}")),
        }
    }
    Err(format!("UDP to the edge was not probed: no region resolved: {}", unresolved.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    #[test]
    fn the_packet_is_a_long_header_of_the_reserved_version_padded_to_1200_bytes() {
        let packet = packet(&ID);
        assert_eq!(packet.len(), 1200);
        // The Header Form and the Fixed Bit set, the type Initial (RFC 9000,
        // section 17.2.2).
        assert_eq!(packet[0], 0b1100_0000);
        assert_eq!(packet[1..5], [0x1a, 0x2a, 0x3a, 0x4a]);
        assert_eq!((packet[5], &packet[6..14]), (8, &ID[..]));
        assert_eq!(packet[14], 0, "no Source Connection ID");
        assert!(packet[15..].iter().all(|b| *b == 0));
    }

    /// A Version Negotiation as RFC 9000 lays it out (section 17.2.1, figure
    /// 14), field by field, of 27 bytes, the size that cfrs's testers saw
    /// from the edge: the edge's three versions are this test's choice.
    fn negotiation() -> Vec<u8> {
        // Header Form 1, then seven bits that a server picks.
        let mut bytes = vec![0x80 | 0x2a];
        bytes.extend_from_slice(&[0, 0, 0, 0]); // Version 0
        bytes.push(0); // Destination Connection ID Length: the packet's Source, none
        bytes.push(8); // Source Connection ID Length
        bytes.extend_from_slice(&ID); // Source Connection ID: the packet's Destination
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC version 1
        bytes.extend_from_slice(&[0x6b, 0x33, 0x43, 0xcf]); // QUIC version 2 (RFC 9369)
        bytes.extend_from_slice(&[0xff, 0x00, 0x00, 0x1d]); // draft 29
        bytes
    }

    #[test]
    fn a_version_negotiation_answers_the_packet_and_nothing_else_does() {
        let good = negotiation();
        assert_eq!(good.len(), 27);
        assert!(answers(&good, &ID));
        let mut other_id = ID;
        other_id[7] ^= 1;
        assert!(!answers(&good, &other_id), "an answer to another packet");
        let changed = |at: usize, byte: u8| {
            let mut bytes = negotiation();
            bytes[at] = byte;
            bytes
        };
        // A short header; a version that is not 0; a Destination that is not
        // the packet's Source; a Source of another length.
        for odd in [changed(0, 0x40), changed(4, 1), changed(5, 1), changed(6, 7)] {
            assert!(!answers(&odd, &ID), "{odd:02x?}");
        }
        // No version, a version cut short, one that names the reserved
        // version, and pieces of a header.
        let mut naming = negotiation();
        naming.extend_from_slice(&RESERVED);
        for odd in [good[..15].to_vec(), good[..26].to_vec(), naming, good[..6].to_vec(), Vec::new()] {
            assert!(!answers(&odd, &ID), "{odd:02x?}");
        }
    }

    #[test]
    fn a_length_past_the_datagram_reads_as_no_id() {
        assert_eq!(connection_id(&[3, 1, 2]), None);
        assert_eq!(connection_id(&[2, 1, 2, 9]), Some((&[1u8, 2][..], &[9u8][..])));
    }
}
