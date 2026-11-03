//! What the stand-in OpenTunnel server reads as the service does, written
//! here apart from podssh's code, so that a defect of one is not the other's:
//! a CSR (PKCS #10, RFC 2986), its key and its names, which the service
//! checks before each order ("Only a tunnel's own names",
//! anomalyco/opentunnel:docs/server.md at v0.6.1); and the SNI of a
//! visitor's ClientHello (RFC 8446, section 4.1.2; RFC 6066, section 3),
//! which picks the tunnel and the route.

/// One DER element at the start of `der`: its tag, its contents, and what
/// follows it.
pub fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 3 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |acc, b| acc << 8 | *b as usize), &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// Each element of a SEQUENCE's or a SET's contents.
fn each(mut contents: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while let Some((tag, value, rest)) = element(contents) {
        out.push((tag, value));
        contents = rest;
    }
    out
}

const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

/// What a CSR asks for: the point of its key, its common name, and the DNS
/// names of its subjectAltName.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Csr {
    pub point: Vec<u8>,
    pub common_name: Option<String>,
    pub names: Vec<String>,
}

/// The CSR in `der`.
pub fn csr(der: &[u8]) -> Option<Csr> {
    let (_, request, _) = element(der)?;
    let (_, info, _) = element(request)?;
    let (_, _version, rest) = element(info)?;
    let (_, subject, rest) = element(rest)?;
    let (_, spki, attributes) = element(rest)?;
    let (_, _algorithm, key) = element(spki)?;
    let (tag, bits, _) = element(key)?;
    if tag != 0x03 {
        return None;
    }
    let point = bits.get(1..)?.to_vec();
    Some(Csr { point, common_name: common_name(subject), names: names(attributes) })
}

/// The first common name of a `Name`: RDNs, each a SET of type and value.
fn common_name(name: &[u8]) -> Option<String> {
    for (_, rdn) in each(name) {
        for (_, pair) in each(rdn) {
            let (_, oid, value) = element(pair)?;
            if oid == COMMON_NAME {
                let (_, text, _) = element(value)?;
                return Some(String::from_utf8_lossy(text).into_owned());
            }
        }
    }
    None
}

/// The DNS names of the subjectAltName in a CSR's `[0]` attributes.
fn names(attributes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some((0xa0, attributes, _)) = element(attributes) else { return out };
    for (_, attribute) in each(attributes) {
        let Some((_, oid, values)) = element(attribute) else { continue };
        if oid != EXTENSION_REQUEST {
            continue;
        }
        let Some((_, set, _)) = element(values) else { continue };
        let Some((_, extensions, _)) = element(set) else { continue };
        for (_, extension) in each(extensions) {
            let Some((_, id, rest)) = element(extension) else { continue };
            if id != SUBJECT_ALT_NAME {
                continue;
            }
            // The optional BOOLEAN of `critical`, then the OCTET STRING.
            let Some((tag, value, after)) = element(rest) else { continue };
            let octets = if tag == 0x01 { element(after).map(|(_, v, _)| v).unwrap_or_default() } else { value };
            let Some((_, general, _)) = element(octets) else { continue };
            for (tag, name) in each(general) {
                if tag == 0x82 {
                    out.push(String::from_utf8_lossy(name).into_owned());
                }
            }
        }
    }
    out
}

/// The length of the first TLS record in `bytes`, once its head is there.
pub fn record_len(bytes: &[u8]) -> Option<usize> {
    let head = bytes.get(..5)?;
    Some(5 + u16::from_be_bytes([head[3], head[4]]) as usize)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]) as usize)
}

/// The SNI of the ClientHello in the first record of `bytes`.
pub fn sni(bytes: &[u8]) -> Option<String> {
    if *bytes.first()? != 0x16 {
        return None;
    }
    let body = bytes.get(5..record_len(bytes)?)?;
    if *body.first()? != 0x01 {
        return None;
    }
    // The handshake's head (4), the version (2), the random (32).
    let mut at = 4 + 2 + 32;
    at += 1 + *body.get(at)? as usize;
    at += 2 + u16_at(body, at)?;
    at += 1 + *body.get(at)? as usize;
    let end = at + 2 + u16_at(body, at)?;
    at += 2;
    while at + 4 <= end {
        let (kind, len) = (u16_at(body, at)?, u16_at(body, at + 2)?);
        let data = body.get(at + 4..at + 4 + len)?;
        if kind == 0 {
            // The list's length (2), the name's type (1), its length (2).
            let name_len = u16_at(data, 3)?;
            return Some(String::from_utf8_lossy(data.get(5..5 + name_len)?).into_owned());
        }
        at += 4 + len;
    }
    None
}

/// The tunnel's id and the route that `sni` names under `domain`: `@` for
/// the tunnel's own name; none for each other name.
pub fn tunnel_and_route(sni: &str, domain: &str) -> Option<(String, String)> {
    let sni = sni.to_ascii_lowercase();
    let under = sni.strip_suffix(domain)?.strip_suffix('.')?;
    match under.split('.').collect::<Vec<_>>()[..] {
        [id] if !id.is_empty() => Some((id.to_string(), "@".to_string())),
        [route, id] if !route.is_empty() && !id.is_empty() => Some((id.to_string(), route.to_string())),
        _ => None,
    }
}
