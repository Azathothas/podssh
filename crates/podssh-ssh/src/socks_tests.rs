//! The requests of SOCKS4 (its 1992 document), SOCKS4a and SOCKS5 (RFC
//! 1928), byte by byte, as clients send them, and the answers podssh sends.

use super::*;

/// The request read from `bytes`, and what podssh wrote meanwhile.
async fn read(bytes: &[u8]) -> (Result<Request, String>, Vec<u8>) {
    let mut input = bytes;
    let mut output = Vec::new();
    let request = read_request(&mut input, &mut output).await;
    (request, output)
}

fn wants(version: Version, host: &str, port: u16) -> Result<Request, String> {
    Ok(Request { version, host: host.into(), port })
}

#[tokio::test]
async fn socks5_connect_to_a_name_an_ipv4_and_an_ipv6_address() {
    // curl --socks5-hostname offers "no authentication" and asks by name.
    let mut name = vec![5, 1, 0, 5, 1, 0, 3, 11];
    name.extend_from_slice(b"example.org");
    name.extend_from_slice(&[0, 80]);
    assert_eq!(read(&name).await, (wants(Version::Five, "example.org", 80), vec![5, 0]));
    let v4 = [5, 2, 0, 2, 5, 1, 0, 1, 127, 0, 0, 1, 0x1f, 0x90];
    assert_eq!(read(&v4).await, (wants(Version::Five, "127.0.0.1", 8080), vec![5, 0]));
    let mut v6 = vec![5, 1, 0, 5, 1, 0, 4];
    v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    v6.extend_from_slice(&[0, 22]);
    assert_eq!(read(&v6).await, (wants(Version::Five, "::1", 22), vec![5, 0]));
}

#[tokio::test]
async fn socks5_refuses_authentication_bind_udp_and_unknown_addresses() {
    // Only user and password offered: no method is acceptable.
    let (request, written) = read(&[5, 1, 2]).await;
    assert!(request.is_err());
    assert_eq!(written, vec![5, 0xff]);
    // BIND, then UDP ASSOCIATE: the method is chosen, then refused, 7.
    for command in [2, 3] {
        let (request, written) = read(&[5, 1, 0, 5, command, 0, 1, 127, 0, 0, 1, 0, 80]).await;
        assert!(request.unwrap_err().contains("not CONNECT"));
        assert_eq!(written, vec![5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
    let (request, written) = read(&[5, 1, 0, 5, 1, 0, 9]).await;
    assert!(request.unwrap_err().contains("address type 9"));
    assert_eq!(written, vec![5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn socks4_and_socks4a_connect() {
    let v4 = [4, 1, 0, 80, 192, 0, 2, 1, b'u', b's', b'e', b'r', 0];
    assert_eq!(read(&v4).await, (wants(Version::Four, "192.0.2.1", 80), vec![]));
    // SOCKS4a: 0.0.0.1, an empty user id, then the name.
    let mut named = vec![4, 1, 0, 22, 0, 0, 0, 1, 0];
    named.extend_from_slice(b"db.internal\0");
    assert_eq!(read(&named).await, (wants(Version::Four, "db.internal", 22), vec![]));
}

#[tokio::test]
async fn socks4_refuses_bind_and_a_name_with_no_end() {
    let (request, written) = read(&[4, 2, 0, 80, 192, 0, 2, 1, 0]).await;
    assert!(request.unwrap_err().contains("not CONNECT"));
    assert_eq!(written, vec![0, 91, 0, 0, 0, 0, 0, 0]);
    let mut long = vec![4, 1, 0, 80, 192, 0, 2, 1];
    long.extend(std::iter::repeat_n(b'a', 300));
    assert!(read(&long).await.0.unwrap_err().contains("more than 255"));
    assert!(read(&[4, 1, 0]).await.0.unwrap_err().contains("short"));
}

#[tokio::test]
async fn other_versions_are_refused() {
    assert!(read(&[6, 1, 0]).await.0.unwrap_err().contains("not SOCKS 4 or 5"));
    assert!(read(&[]).await.0.unwrap_err().contains("no request"));
}

#[tokio::test]
async fn the_answers() {
    let mut out = Vec::new();
    answer(&mut out, Version::Five, Ok(())).await.unwrap();
    answer(&mut out, Version::Five, Err(Refusal::Refused)).await.unwrap();
    answer(&mut out, Version::Five, Err(Refusal::NotAllowed)).await.unwrap();
    answer(&mut out, Version::Four, Ok(())).await.unwrap();
    answer(&mut out, Version::Four, Err(Refusal::General)).await.unwrap();
    assert_eq!(
        out,
        [
            &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0][..],
            &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0],
            &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0],
            &[0, 90, 0, 0, 0, 0, 0, 0],
            &[0, 91, 0, 0, 0, 0, 0, 0],
        ]
        .concat()
    );
}
