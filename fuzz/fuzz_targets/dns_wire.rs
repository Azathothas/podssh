//! An answer of DNS over HTTPS in RFC 8484's wire form
//! (`podssh_ws::resolve::wire`, T-344), as a resolver sends it: each decoder
//! ends on any bytes, an address has the family of the type asked, an SRV
//! target is a name in lower case that a resolver can be asked for, NXDOMAIN
//! is said for RCODE 3 of a response and for nothing else, and a name read
//! from any offset ends within the bytes, at most 253 characters long.
#![no_main]

use libfuzzer_sys::fuzz_target;
use podssh_ws::resolve::{wire, NXDOMAIN};

const NAME: &str = "tcp.ssh.relay.ajam.dev";
const SRV_NAME: &str = "_v2-origintunneld._tcp.argotunnel.com";

fuzz_target!(|data: &[u8]| {
    let rcode3 = data.len() >= 12 && (data[2] & 0x80) != 0 && (data[3] & 0x0f) == 3;
    for (kind, v6) in [(wire::A, false), (wire::AAAA, true)] {
        match wire::addrs(data, NAME, kind) {
            Ok(ips) => assert!(ips.iter().all(|ip| ip.is_ipv6() == v6), "{ips:?}"),
            Err(e) => assert_eq!(e == NXDOMAIN, rcode3, "{e}"),
        }
    }
    match wire::srv(data, SRV_NAME) {
        Ok(records) => {
            for r in records {
                let safe = r.target.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b));
                assert!(safe && !r.target.is_empty() && r.target.len() <= 253, "{r:?}");
            }
        }
        Err(e) => assert_eq!(e == NXDOMAIN, rcode3, "{e}"),
    }
    let start = data.first().map_or(0, |&b| usize::from(b) % data.len().max(1));
    if let Ok((name, end)) = wire::read_name(data, start) {
        assert!(end <= data.len() && name.len() <= 253, "{name:?} ends at {end}");
    }
});
