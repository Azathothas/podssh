//! RFC 1035's messages as RFC 8484 carries them over HTTPS
//! (`application/dns-message`): a query of one question, and the A, AAAA and
//! SRV records of an answer (T-344). By hand, for three record types: a
//! parser of untrusted bytes that the fuzzer reaches
//! (`fuzz/fuzz_targets/dns_wire.rs`), where a general DNS crate would be a
//! large one that podssh does not fuzz.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;

use super::{dns_safe, Srv, NXDOMAIN};

/// The record types that podssh asks for (RFC 1035, RFC 3596, RFC 2782).
pub const A: u16 = 1;
pub const AAAA: u16 = 28;
pub const SRV: u16 = 33;
/// The class of each question and record here: the Internet.
const IN: u16 = 1;

/// A message's header: an ID, the flags and four counts.
const HEADER: usize = 12;
/// The longest name in its wire form, its length bytes included (RFC 1035,
/// section 3.1).
const MAX_NAME: usize = 255;
/// The flag of a response (QR), and the mask of its RCODE.
const RESPONSE: u16 = 0x8000;
const RCODE: u16 = 0x000F;

const CUT: &str = "not a DNS message: it ends before its last record";

/// The type of `kind` (`A`, `AAAA` or `SRV`), as the JSON form names it.
pub fn code(kind: &str) -> Option<u16> {
    match kind {
        "A" => Some(A),
        "AAAA" => Some(AAAA),
        "SRV" => Some(SRV),
        _ => None,
    }
}

/// The query for the records of `kind` of `name`: ID 0, as RFC 8484 section
/// 4.1 asks for a cache's sake, recursion desired, and one question of class
/// IN. A name that a resolver should not be asked for is refused.
pub fn query(name: &str, kind: u16) -> Result<Vec<u8>, String> {
    let name = name.trim_end_matches('.');
    let refused = || format!("{name:?} is not a name to ask a resolver for");
    if !dns_safe(name) {
        return Err(refused());
    }
    let mut out = Vec::with_capacity(HEADER + name.len() + 6);
    // ID 0; RD set; one question, no other record.
    out.extend_from_slice(&[0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(refused());
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    if out.len() - HEADER > MAX_NAME {
        return Err(refused());
    }
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&IN.to_be_bytes());
    Ok(out)
}

/// [`query`] as the `dns` parameter of a GET: base64url, with no padding
/// (RFC 8484, section 6).
pub fn query_param(name: &str, kind: u16) -> Result<String, String> {
    query(name, kind).map(|q| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(q))
}

/// The addresses of an answer to the question of `kind` (A or AAAA) for
/// `name`: each record of that type, as the JSON form takes each `data` of
/// its type. A record of another length is left out.
pub fn addrs(msg: &[u8], name: &str, kind: u16) -> Result<Vec<IpAddr>, String> {
    let mut ips = Vec::new();
    for (start, len) in records(msg, name, kind)? {
        let data = &msg[start..start + len];
        let ip = match (kind, <[u8; 4]>::try_from(data), <[u8; 16]>::try_from(data)) {
            (A, Ok(v4), _) => IpAddr::V4(Ipv4Addr::from(v4)),
            (AAAA, _, Ok(v6)) => IpAddr::V6(Ipv6Addr::from(v6)),
            _ => continue,
        };
        ips.push(ip);
    }
    Ok(ips)
}

/// The SRV records of an answer for `name`: each one's priority, weight and
/// port, and its target, whose name may be compressed; a target that is not
/// a name to ask for ("." among them: no service) is left out.
pub fn srv(msg: &[u8], name: &str) -> Result<Vec<Srv>, String> {
    let mut found = Vec::new();
    for (start, len) in records(msg, name, SRV)? {
        let Some(fixed) = msg.get(start..start + 6).filter(|_| len > 6) else { continue };
        let number = |at: usize| u16::from_be_bytes([fixed[at], fixed[at + 1]]);
        let Ok((target, end)) = read_name(msg, start + 6) else { continue };
        if end == start + len && dns_safe(&target) {
            found.push(Srv { priority: number(0), weight: number(2), port: number(4), target });
        }
    }
    Ok(found)
}

/// Where the data of each record of `kind` and class IN is in the answer
/// section of `msg`, as `(offset, length)`, once the header and the question
/// say that `msg` answers this question: a response, with RCODE 0 (3 is
/// [`NXDOMAIN`], each other "DNS status N", as the JSON form says), whose
/// question, when it has one, is `name` and `kind`.
fn records(msg: &[u8], name: &str, kind: u16) -> Result<Vec<(usize, usize)>, String> {
    let header = msg.get(..HEADER).ok_or("not a DNS message: shorter than its header")?;
    let word = |at: usize| u16::from_be_bytes([header[at], header[at + 1]]);
    if (word(2) & RESPONSE) == 0 {
        return Err("not a DNS answer: the message is a query".into());
    }
    match word(2) & RCODE {
        0 => {}
        3 => return Err(NXDOMAIN.to_string()),
        rcode => return Err(format!("DNS status {rcode}")),
    }
    let mut at = HEADER;
    for i in 0..word(4) {
        let (asked, end) = read_name(msg, at)?;
        let fixed = msg.get(end..end + 4).ok_or(CUT)?;
        let asked_kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        // A cache between that answered another question is no answer.
        if i == 0 && (!asked.eq_ignore_ascii_case(name.trim_end_matches('.')) || asked_kind != kind) {
            return Err(format!("the answer is for another question ({asked} type {asked_kind})"));
        }
        at = end + 4;
    }
    let mut found = Vec::new();
    for _ in 0..word(6) {
        at = skip_name(msg, at)?;
        let fixed = msg.get(at..at + 10).ok_or(CUT)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let start = at + 10;
        if msg.len() - start < len {
            return Err(CUT.into());
        }
        if rtype == kind && class == IN {
            found.push((start, len));
        }
        at = start + len;
    }
    Ok(found)
}

/// The offset just after the name at `at`, which ends at its zero byte or at
/// its first pointer; its labels are not read.
fn skip_name(msg: &[u8], mut at: usize) -> Result<usize, String> {
    loop {
        let len = *msg.get(at).ok_or(CUT)?;
        match len & 0xC0 {
            0x00 if len == 0 => return Ok(at + 1),
            0x00 => at += 1 + usize::from(len),
            0xC0 if at + 1 < msg.len() => return Ok(at + 2),
            0xC0 => return Err(CUT.into()),
            _ => return Err("a name holds a label of a type that RFC 1035 does not define".into()),
        }
    }
}

/// The name at `start`, in lower case with no final dot, and the offset just
/// after it where it is: after its zero byte, or after its first pointer
/// (RFC 1035, section 4.1.4). Each pointer must go back before the start of
/// the run of labels that holds it, so that the walk ends; a name is at most
/// [`MAX_NAME`] bytes in its wire form, and a label holds printable ASCII
/// and no dot, as each host name does.
pub fn read_name(msg: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut name = String::new();
    let (mut at, mut run, mut end, mut wire) = (start, start, None, 1usize);
    loop {
        let len = *msg.get(at).ok_or(CUT)?;
        match len & 0xC0 {
            0x00 if len == 0 => return Ok((name, end.unwrap_or(at + 1))),
            0x00 => {
                let label = msg.get(at + 1..at + 1 + usize::from(len)).ok_or(CUT)?;
                wire += label.len() + 1;
                if wire > MAX_NAME {
                    return Err("a name is longer than RFC 1035 allows".into());
                }
                if label.iter().any(|b| !b.is_ascii_graphic() || *b == b'.') {
                    return Err("a label of a name holds a dot, or a byte that no host name has".into());
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
                at += label.len() + 1;
            }
            0xC0 => {
                let low = *msg.get(at + 1).ok_or(CUT)?;
                let to = usize::from(u16::from_be_bytes([len & 0x3F, low]));
                if to >= run {
                    return Err("a name's pointer does not go back to an earlier name".into());
                }
                end.get_or_insert(at + 2);
                (at, run) = (to, to);
            }
            _ => return Err("a name holds a label of a type that RFC 1035 does not define".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8484's answer of section 4.2.2: one AAAA record for
    /// www.example.com, its owner a pointer to the question's name.
    const RFC_ANSWER: [u8; 61] = [
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x07, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00,
        0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x7d, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x00, 0x12, 0x00,
        0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
    ];

    /// The queries of RFC 8484, section 4.1.1, byte for byte: a short name,
    /// and the one whose base64url differs from base64 and has no padding.
    #[test]
    fn a_query_is_rfc_8484_s_own_example() {
        assert_eq!(query_param("www.example.com", A).unwrap(), "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB");
        let long = "a.62characterlabel-makes-base64url-distinct-from-standard-base64.example.com";
        assert_eq!(
            query_param(long, A).unwrap(),
            "AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJlbC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1z\
             dGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ"
        );
        assert_eq!(query("www.example.com.", A).unwrap().len(), 33, "the final dot is the root, not a label");
        let (label_too_long, name_too_long) = ("x".repeat(64), ["abcdefgh"; 32].join("."));
        for bad in ["", "a..b", "space here.example", label_too_long.as_str(), name_too_long.as_str()] {
            assert!(query(bad, A).is_err(), "{bad:?}");
        }
    }

    /// RFC 8484's answer decodes to its address, and to nothing for the
    /// question that it does not answer.
    #[test]
    fn rfc_8484_s_answer_decodes_to_its_address() {
        let ips = addrs(&RFC_ANSWER, "WWW.example.com.", AAAA).unwrap();
        assert_eq!(ips, vec!["2001:db8:abcd:12:1:2:3:4".parse::<IpAddr>().unwrap()]);
        assert!(addrs(&RFC_ANSWER, "www.example.com", A).unwrap_err().contains("another question"));
        assert!(addrs(&RFC_ANSWER, "www.example.org", AAAA).unwrap_err().contains("another question"));
        // A query is no answer, and each cut of the answer is refused, never a panic.
        assert!(addrs(&query("www.example.com", AAAA).unwrap(), "www.example.com", AAAA).is_err());
        for cut in 0..RFC_ANSWER.len() {
            assert!(addrs(&RFC_ANSWER[..cut], "www.example.com", AAAA).is_err(), "cut at {cut}");
        }
    }

    /// RCODE 3 is NXDOMAIN, as the JSON form says it, and another is its number.
    #[test]
    fn a_status_is_named_as_the_json_form_names_it() {
        let mut answer = RFC_ANSWER;
        answer[3] = 0x83;
        assert_eq!(addrs(&answer, "www.example.com", AAAA).unwrap_err(), NXDOMAIN);
        answer[3] = 0x82;
        assert_eq!(addrs(&answer, "www.example.com", AAAA).unwrap_err(), "DNS status 2");
    }

    /// A pointer that does not go back, or that points at itself, is refused,
    /// and so is a name longer than 255 bytes.
    #[test]
    fn pointers_that_loop_and_names_too_long_are_refused() {
        let mut looped = RFC_ANSWER;
        // The answer's owner points at itself.
        looped[34] = 33;
        assert!(addrs(&looped, "www.example.com", AAAA).is_ok(), "skip_name does not follow a pointer");
        assert!(read_name(&looped, 33).unwrap_err().contains("does not go back"));
        // Two pointers that point at each other.
        let pair = [0xc0, 2, 0xc0, 0];
        assert!(read_name(&pair, 2).is_err() && read_name(&pair, 0).is_err());
        let mut long = Vec::new();
        for _ in 0..5 {
            long.push(63);
            long.extend_from_slice(&[b'a'; 63]);
        }
        long.push(0);
        assert!(read_name(&long, 0).unwrap_err().contains("longer"));
        assert_eq!(read_name(&long[64 * 2..], 0).unwrap().0.len(), 63 * 3 + 2);
    }
}
