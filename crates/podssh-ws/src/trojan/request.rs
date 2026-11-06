//! Trojan's request (trojan-gfw `docs/protocol.md`; Xray-core
//! `proxy/trojan/protocol.go`, `ConnWriter.writeHeader`): the 56 bytes of
//! `hex(SHA224(password))`, CRLF, the command (`0x01`, CONNECT), the address
//! as SOCKS5 writes it (`0x01` and four bytes, `0x03`, a length and a name,
//! `0x04` and sixteen bytes), the port in network order, CRLF. The payload
//! follows with no answer between: the server dials the target and relays.

use std::net::IpAddr;

use super::link::Password;

/// CONNECT: a stream to the target. UDP's `0x03` is not spoken.
const CONNECT: u8 = 0x01;

/// The request for `host:port`, or why the target cannot go in it.
pub fn request(password: &Password, host: &str, port: u16) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(56 + 2 + 1 + 1 + 1 + host.len() + 2 + 2);
    out.extend_from_slice(password.hex());
    out.extend_from_slice(b"\r\n");
    out.push(CONNECT);
    // A literal in brackets is an address, as a link writes IPv6.
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let len = u8::try_from(bare.len()).map_err(|_| "a name of more than 255 bytes")?;
            if len == 0 {
                return Err("an empty name".into());
            }
            out.push(0x03);
            out.push(len);
            out.extend_from_slice(bare.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_is_the_hash_crlf_connect_the_address_the_port_crlf() {
        let password = Password::new("password").unwrap();
        let name = request(&password, "h.example", 22).unwrap();
        let mut want = b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n".to_vec();
        want.extend_from_slice(&[0x01, 0x03, 9]);
        want.extend_from_slice(b"h.example");
        want.extend_from_slice(&[0, 22, b'\r', b'\n']);
        assert_eq!(name, want);
        let v4 = request(&password, "192.0.2.7", 443).unwrap();
        assert_eq!(&v4[58..], &[0x01, 0x01, 192, 0, 2, 7, 0x01, 0xbb, b'\r', b'\n']);
        let v6 = request(&password, "[2001:db8::1]", 22).unwrap();
        assert_eq!((v6[59], v6.len()), (0x04, 58 + 2 + 16 + 2 + 2));
        assert!(request(&password, &"a".repeat(256), 22).is_err());
    }
}
