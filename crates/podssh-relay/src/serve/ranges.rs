//! A range of addresses, `ADDR/BITS` or one address alone: the words of the
//! net's routes and of its policy (T-432), the private ranges of an exit
//! (`podssh node --exit --routes`), and those that the relay role dials
//! beside public targets (`podssh relay serve --routes`, T-635).
//!
//! A flag reads its ranges strictly ([`Range::strict`], [`list`]): a prefix
//! with a bit set past it, `10.0.0.5/8`, names a wider network than its
//! writer may have meant, and is refused with the network that it would
//! name, as `ip route` refuses it. A word of a net's signed document keeps
//! the reading that it had ([`Range::parse`]), so a document signed before
//! reaches what it reached.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A range of addresses: `ADDR/BITS`, or one address alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    addr: IpAddr,
    bits: u8,
}

impl Range {
    /// `word` as a word of a net's document reads it: a prefix with bits
    /// set past it is the network of its first bits.
    pub fn parse(word: &str) -> Option<Range> {
        let (addr, bits) = match word.split_once('/') {
            Some((addr, bits)) => (addr, Some(bits)),
            None => (word, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let most = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => most,
            // Digits alone: `u8`'s parser takes a sign too.
            Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
                text.parse::<u8>().ok().filter(|&bits| bits <= most)?
            }
            Some(_) => return None,
        };
        Some(Range { addr, bits })
    }

    /// `word` as a flag reads it: a range whose address sets no bit past its
    /// prefix. `Err` says why, with the network that such a prefix names.
    pub fn strict(word: &str) -> Result<Range, String> {
        let range = Range::parse(word)
            .ok_or_else(|| format!("{word:?} is not a range: ADDR/BITS or one address, separated by commas"))?;
        let network = range.network();
        if network != range.addr {
            let bits = range.bits;
            return Err(format!(
                "{word:?} sets bits past its prefix of {bits}: the range is {network}/{bits}, which names more than \
                 {}; give it as such, or the address alone",
                range.addr
            ));
        }
        Ok(range)
    }

    /// How many first bits it fixes: the more, the narrower, so `--exit
    /// auto` takes the narrowest of the net's routes that holds an address.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Whether it names `addr` alone, as an exit needs for its own
    /// addresses and the loopback (T-432).
    pub fn names_alone(&self, addr: IpAddr) -> bool {
        self.addr == addr && self.bits == if addr.is_ipv4() { 32 } else { 128 }
    }

    /// Whether `addr` is in the range: of the same family, and the same in
    /// the range's first bits.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(one)) => same_prefix(&net.octets(), &one.octets(), self.bits),
            (IpAddr::V6(net), IpAddr::V6(one)) => same_prefix(&net.octets(), &one.octets(), self.bits),
            _ => false,
        }
    }

    /// Its first address: each bit past the prefix clear.
    pub fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(v4) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.bits)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.bits)).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        }
    }
}

/// Whether `a` and `b` have the same first `bits` bits.
fn same_prefix(a: &[u8], b: &[u8], bits: u8) -> bool {
    let (whole, rest) = (usize::from(bits / 8), bits % 8);
    if a[..whole] != b[..whole] {
        return false;
    }
    let mask = 0xffu8.checked_shl(u32::from(8 - rest)).unwrap_or(0);
    rest == 0 || a[whole] & mask == b[whole] & mask
}

/// The ranges of a flag's `RANGES`, each read strictly, separated by
/// commas, each with its word as given; `Err` says why the first word that
/// is not one is not, with the network of a prefix that sets bits past it.
pub fn list(text: &str) -> Result<Vec<(String, Range)>, String> {
    text.split(',').map(str::trim).map(|word| Range::strict(word).map(|range| (word.to_string(), range))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_range_holds_the_addresses_of_its_first_bits_and_one_address_itself() {
        let ten = Range::parse("10.4.0.0/16").unwrap();
        assert!(ten.contains(ip("10.4.200.9")) && !ten.contains(ip("10.5.0.1")) && !ten.contains(ip("::1")));
        let one = Range::parse("10.4.0.9").unwrap();
        assert_eq!((one.bits(), one.contains(ip("10.4.0.9")), one.contains(ip("10.4.0.8"))), (32, true, false));
        assert!(one.names_alone(ip("10.4.0.9")));
        let six = Range::parse("fd00::/8").unwrap();
        assert!(six.contains(ip("fd12::1")) && !six.contains(ip("fe80::1")));
        assert_eq!(Range::parse("::1"), Range::parse("::1/128"));
        assert!(Range::parse("0.0.0.0/0").unwrap().contains(ip("203.0.113.9")));
        for wrong in ["10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/+8", "10.0.0.0/", "db.internal", "", "fd00::/129"] {
            assert_eq!(Range::parse(wrong), None, "{wrong}");
        }
    }

    // T-635: `10.0.0.5/8` is refused by a flag, with the network that it
    // names; a document's word keeps its reading.
    #[test]
    fn a_prefix_with_bits_past_it_is_refused_by_a_flag_with_its_network() {
        let why = Range::strict("10.0.0.5/8").unwrap_err();
        assert!(why.contains("\"10.0.0.5/8\"") && why.contains("the range is 10.0.0.0/8"), "{why}");
        let why = Range::strict("fd00::1/8").unwrap_err();
        assert!(why.contains("the range is fd00::/8"), "{why}");
        assert_eq!(Range::strict("10.0.0.0/8"), Ok(Range::parse("10.0.0.0/8").unwrap()));
        assert_eq!(Range::strict("10.0.0.5"), Ok(Range::parse("10.0.0.5/32").unwrap()));
        assert!(Range::strict("10.0.0.0/33").unwrap_err().contains("is not a range"));
        let read = Range::parse("10.0.0.5/8").unwrap();
        assert!(read.contains(ip("10.9.9.9")), "a document's word reads as its network");
        assert_eq!(read.network(), ip("10.0.0.0"));
    }

    #[test]
    fn a_list_keeps_each_word_and_names_the_first_that_is_not_a_range() {
        let ranges = list("10.4.0.9, 10.4.1.0/24,fd00::/8").unwrap();
        let words: Vec<&str> = ranges.iter().map(|(w, _)| w.as_str()).collect();
        assert_eq!(words, ["10.4.0.9", "10.4.1.0/24", "fd00::/8"]);
        assert!(list("10.4.0.9,db.internal").unwrap_err().starts_with("\"db.internal\" is not a range"));
        assert!(list("10.4.1.7/24").unwrap_err().contains("the range is 10.4.1.0/24"));
        assert!(list("").unwrap_err().contains("is not a range"));
    }
}
