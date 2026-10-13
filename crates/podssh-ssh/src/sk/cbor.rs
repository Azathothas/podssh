//! The part of CBOR (RFC 8949) that CTAP2 speaks: integers, byte and text
//! strings, arrays, maps, booleans and null, each with a definite length.
//! podssh writes CTAP2's canonical form (the shortest head, and the keys of
//! a map in the order that the caller gives, which is the canonical one);
//! it reads what a device answers, and refuses floats, indefinite lengths
//! and a nesting deeper than a device needs.

/// One CBOR item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

/// Deeper than each answer of CTAP2 (a map in a map in an array), so that a
/// device cannot make podssh recurse without end.
const MAX_DEPTH: usize = 16;

impl Value {
    /// A text item.
    pub fn text(text: &str) -> Value {
        Value::Text(text.to_string())
    }

    /// The item in canonical CBOR.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Value::Int(n) if *n >= 0 => head(out, 0, *n as u64),
            // -1 - n, for a negative n, never overflows.
            Value::Int(n) => head(out, 1, (-1 - *n) as u64),
            Value::Bytes(bytes) => {
                head(out, 2, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
            Value::Text(text) => {
                head(out, 3, text.len() as u64);
                out.extend_from_slice(text.as_bytes());
            }
            Value::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.encode(out);
                }
            }
            Value::Map(pairs) => {
                head(out, 5, pairs.len() as u64);
                for (key, value) in pairs {
                    key.encode(out);
                    value.encode(out);
                }
            }
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Null => out.push(0xf6),
        }
    }

    /// The item as bytes of CBOR.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// The value of `key` in a map.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value of the integer key `key` in a map, as CTAP2 keys its
    /// commands and COSE its keys.
    pub fn at(&self, key: i64) -> Option<&Value> {
        self.get(&Value::Int(key))
    }

    /// The value of the text key `key` in a map.
    pub fn field(&self, key: &str) -> Option<&Value> {
        self.get(&Value::text(key))
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Text, which podssh reads only in its tests: a device's answers that
    /// it reads hold none.
    #[cfg(test)]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// The head of an item: its major type and its count, in the fewest bytes.
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    if n < 24 {
        out.push(major | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[major | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(major | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(major | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// The first item of `input`, and the bytes after it.
pub(crate) fn decode(input: &[u8]) -> Result<(Value, &[u8]), String> {
    item(input, 0)
}

/// The one item of `input`, with nothing after it.
pub(crate) fn decode_all(input: &[u8]) -> Result<Value, String> {
    match decode(input)? {
        (value, []) => Ok(value),
        (_, rest) => Err(format!("{} bytes after the CBOR item", rest.len())),
    }
}

fn item(input: &[u8], depth: usize) -> Result<(Value, &[u8]), String> {
    if depth > MAX_DEPTH {
        return Err("CBOR nested too deep".into());
    }
    let (&first, rest) = input.split_first().ok_or("the CBOR ended early")?;
    let (major, info) = (first >> 5, first & 0x1f);
    if major == 7 {
        return match info {
            20 => Ok((Value::Bool(false), rest)),
            21 => Ok((Value::Bool(true), rest)),
            22 | 23 => Ok((Value::Null, rest)),
            25..=27 => Err("a CBOR float, which CTAP2 does not send".into()),
            _ => Err(format!("the CBOR simple value {info}")),
        };
    }
    let (n, mut rest) = count(info, rest)?;
    match major {
        0 => Ok((Value::Int(i64::try_from(n).map_err(|_| "a CBOR integer too large")?), rest)),
        1 => Ok((Value::Int(-1 - i64::try_from(n).map_err(|_| "a CBOR integer too small")?), rest)),
        2 | 3 => {
            let n = usize::try_from(n).ok().filter(|n| *n <= rest.len()).ok_or("a CBOR string past the end")?;
            let (bytes, rest) = rest.split_at(n);
            if major == 2 {
                return Ok((Value::Bytes(bytes.to_vec()), rest));
            }
            let text = std::str::from_utf8(bytes).map_err(|_| "a CBOR text that is not UTF-8")?;
            Ok((Value::Text(text.to_string()), rest))
        }
        4 => {
            // Each item takes one byte at least, so a count past the end is
            // refused before anything is kept for it.
            let n = usize::try_from(n).ok().filter(|n| *n <= rest.len()).ok_or("a CBOR array past the end")?;
            let mut items = Vec::with_capacity(n);
            for _ in 0..n {
                let (value, after) = item(rest, depth + 1)?;
                items.push(value);
                rest = after;
            }
            Ok((Value::Array(items), rest))
        }
        5 => {
            let n = usize::try_from(n).ok().filter(|n| *n <= rest.len() / 2).ok_or("a CBOR map past the end")?;
            let mut pairs = Vec::with_capacity(n);
            for _ in 0..n {
                let (key, after) = item(rest, depth + 1)?;
                let (value, after) = item(after, depth + 1)?;
                pairs.push((key, value));
                rest = after;
            }
            Ok((Value::Map(pairs), rest))
        }
        // A tag says what its item means; CTAP2 gives none that podssh reads.
        _ => item(rest, depth + 1),
    }
}

/// The count of a head whose low bits are `info`, and the bytes after it.
fn count(info: u8, rest: &[u8]) -> Result<(u64, &[u8]), String> {
    let width = match info {
        0..=23 => return Ok((u64::from(info), rest)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        31 => return Err("a CBOR item of indefinite length, which CTAP2 does not send".into()),
        _ => return Err(format!("the reserved CBOR head {info}")),
    };
    if rest.len() < width {
        return Err("the CBOR ended early".into());
    }
    let (digits, rest) = rest.split_at(width);
    Ok((digits.iter().fold(0u64, |n, b| n << 8 | u64::from(*b)), rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The examples of RFC 8949, appendix A, that CTAP2 uses.
    #[test]
    fn items_encode_as_rfc_8949_gives_them() {
        let cases: &[(Value, &[u8])] = &[
            (Value::Int(0), &[0x00]),
            (Value::Int(23), &[0x17]),
            (Value::Int(24), &[0x18, 0x18]),
            (Value::Int(1000), &[0x19, 0x03, 0xe8]),
            (Value::Int(1_000_000), &[0x1a, 0x00, 0x0f, 0x42, 0x40]),
            (Value::Int(-1), &[0x20]),
            (Value::Int(-100), &[0x38, 0x63]),
            (Value::Int(-1000), &[0x39, 0x03, 0xe7]),
            (Value::Bool(false), &[0xf4]),
            (Value::Bool(true), &[0xf5]),
            (Value::Null, &[0xf6]),
            (Value::Bytes(vec![1, 2, 3, 4]), &[0x44, 0x01, 0x02, 0x03, 0x04]),
            (Value::text("IETF"), &[0x64, 0x49, 0x45, 0x54, 0x46]),
            (
                Value::Array(vec![Value::Int(1), Value::Array(vec![Value::Int(2), Value::Int(3)])]),
                &[0x82, 0x01, 0x82, 0x02, 0x03],
            ),
            (
                Value::Map(vec![(Value::Int(1), Value::Int(2)), (Value::Int(3), Value::Int(4))]),
                &[0xa2, 0x01, 0x02, 0x03, 0x04],
            ),
        ];
        for (value, bytes) in cases {
            assert_eq!(&value.to_vec(), bytes, "{value:?}");
            assert_eq!(&decode_all(bytes).unwrap(), value, "{bytes:02x?}");
        }
    }

    #[test]
    fn what_ctap2_never_sends_is_refused() {
        // An indefinite byte string, a float, a string past the end, an
        // array of 2^32 - 1 items in 5 bytes, text that is not UTF-8, and
        // nothing.
        let bad: [&[u8]; 6] = [
            &[0x5f, 0x41, 0x00, 0xff],
            &[0xf9, 0x3c, 0x00],
            &[0x44, 0x01, 0x02],
            &[0x9a, 0xff, 0xff, 0xff, 0xff],
            &[0x62, 0xc3, 0x28],
            &[],
        ];
        for bad in bad {
            assert!(decode(bad).is_err(), "{bad:02x?}");
        }
        let deep = [0x81u8; 40];
        assert!(decode(&deep).is_err(), "nesting without end");
        assert!(decode_all(&[0x01, 0x02]).is_err(), "a byte after the item");
    }

    #[test]
    fn a_map_is_read_by_its_keys() {
        let map = Value::Map(vec![
            (Value::Int(1), Value::Bytes(vec![9])),
            (Value::text("up"), Value::Bool(true)),
            (Value::Int(-2), Value::Int(7)),
        ]);
        let read = decode_all(&map.to_vec()).unwrap();
        assert_eq!(read.at(1).and_then(Value::as_bytes), Some(&[9u8][..]));
        assert_eq!(read.field("up").and_then(Value::as_bool), Some(true));
        assert_eq!(read.at(-2).and_then(Value::as_int), Some(7));
        assert!(read.at(2).is_none());
    }
}
