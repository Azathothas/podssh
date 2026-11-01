//! The server's side of SOCKS5 (RFC 1928) with a user and a password
//! (RFC 1929), as far as Arti's client of a pluggable transport speaks it
//! (`tor-chanmgr`, `transport/proxied.rs`, at 0.47): one CONNECT, whose
//! target the transport does not need, and the bridge's arguments in the
//! user name and the password, as Tor's specification of pluggable
//! transports carries them. Arti joins the arguments as `k=v;k=v`, with a
//! backslash before each `\` and `;`, and before a `=` of a key; up to 255
//! bytes go in the user name with a password of one NUL, and the rest of
//! 510 at most in the password. [`settings`] undoes that.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The reply that lets the client's bytes through.
pub const SUCCEEDED: u8 = 0;
/// The reply of a transport that did not open.
pub const FAILED: u8 = 1;
/// The reply to a command other than CONNECT.
const NOT_SUPPORTED: u8 = 7;
/// The reply to a kind of address that SOCKS5 does not have.
const ADDRESS_NOT_SUPPORTED: u8 = 8;

/// Answer a client's greeting, its user and password, and its CONNECT; the
/// bytes of the arguments, the user name and the password joined, or none.
/// The CONNECT is left without a reply: [`reply`] gives one once the
/// transport opened, or did not.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<Vec<u8>, String> {
    let io = |e: std::io::Error| e.to_string();
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await.map_err(io)?;
    if head[0] != 5 {
        return Err(format!("not SOCKS5: version {}", head[0]));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    s.read_exact(&mut methods).await.map_err(io)?;
    // The user and the password carry the arguments; no arguments, no user.
    let method = match (methods.contains(&2), methods.contains(&0)) {
        (true, _) => 2,
        (false, true) => 0,
        (false, false) => {
            let _ = s.write_all(&[5, 0xff]).await;
            return Err("no method of SOCKS5 that podssh takes was offered".into());
        }
    };
    s.write_all(&[5, method]).await.map_err(io)?;
    let mut raw = Vec::new();
    if method == 2 {
        let mut version = [0u8; 2];
        s.read_exact(&mut version).await.map_err(io)?;
        if version[0] != 1 {
            return Err(format!("not RFC 1929's user and password: version {}", version[0]));
        }
        let mut user = vec![0u8; usize::from(version[1])];
        s.read_exact(&mut user).await.map_err(io)?;
        let mut length = [0u8; 1];
        s.read_exact(&mut length).await.map_err(io)?;
        let mut password = vec![0u8; usize::from(length[0])];
        s.read_exact(&mut password).await.map_err(io)?;
        s.write_all(&[1, 0]).await.map_err(io)?;
        raw = user;
        // A lone NUL is the password of arguments that fit in the user name.
        if password != [0] {
            raw.extend_from_slice(&password);
        }
    }
    let mut request = [0u8; 4];
    s.read_exact(&mut request).await.map_err(io)?;
    if request[0] != 5 {
        return Err(format!("not a request of SOCKS5: version {}", request[0]));
    }
    if request[1] != 1 {
        let _ = reply(s, NOT_SUPPORTED).await;
        return Err(format!("command {} is not CONNECT", request[1]));
    }
    let skip = match request[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0u8; 1];
            s.read_exact(&mut length).await.map_err(io)?;
            usize::from(length[0])
        }
        other => {
            let _ = reply(s, ADDRESS_NOT_SUPPORTED).await;
            return Err(format!("address type {other}"));
        }
    };
    // The bridge's address and port: the transport takes its own from the
    // arguments.
    let mut target = vec![0u8; skip + 2];
    s.read_exact(&mut target).await.map_err(io)?;
    Ok(raw)
}

/// The reply to the CONNECT: `status`, and an address of zeros.
pub async fn reply<S: AsyncWrite + Unpin>(s: &mut S, status: u8) -> std::io::Result<()> {
    s.write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    s.flush().await
}

/// The arguments in `raw`: `k=v` pairs split at each `;` that no backslash
/// escapes, each at its first `=` that none escapes, the escapes removed.
pub fn settings(raw: &[u8]) -> Result<Vec<(String, String)>, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "the bridge's arguments are not UTF-8".to_string())?;
    let mut out = Vec::new();
    if text.is_empty() {
        return Ok(out);
    }
    let (mut key, mut value) = (String::new(), None::<String>);
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        let c = match c {
            '\\' => chars.next().ok_or("the bridge's arguments end in a lone backslash")?,
            ';' => {
                let v = value.take().ok_or_else(|| format!("the argument {key:?} has no '='"))?;
                out.push((std::mem::take(&mut key), v));
                continue;
            }
            '=' if value.is_none() => {
                value = Some(String::new());
                continue;
            }
            c => c,
        };
        match value.as_mut() {
            Some(v) => v.push(c),
            None => key.push(c),
        }
    }
    let v = value.ok_or_else(|| format!("the argument {key:?} has no '='"))?;
    out.push((key, v));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Arti's own cases of its encoding (`proxied.rs`, `setting_encoding`),
    /// read back.
    #[test]
    fn arti_s_encoded_arguments_are_read_back() {
        assert_eq!(settings(b"").unwrap(), pairs(&[]));
        assert_eq!(settings(b"hello=world").unwrap(), pairs(&[("hello", "world")]));
        assert_eq!(settings(b"hey=verden;hello=world").unwrap(), pairs(&[("hey", "verden"), ("hello", "world")]));
        assert_eq!(settings(br"semi\;colon=equals=sign").unwrap(), pairs(&[("semi;colon", "equals=sign")]));
        assert_eq!(settings(br"equals\=sign=semi\;colon").unwrap(), pairs(&[("equals=sign", "semi;colon")]));
        let two = settings(br"semi\;colon=equals=sign;also=back\\slash").unwrap();
        assert_eq!(two, pairs(&[("semi;colon", "equals=sign"), ("also", r"back\slash")]));
        let url = settings(b"url=https://cdn.test/;front=www.test").unwrap();
        assert_eq!(url, pairs(&[("url", "https://cdn.test/"), ("front", "www.test")]));
        for bad in [&b"novalue"[..], b"a=1;b", b"a=1\\", b"\xff=1"] {
            assert!(settings(bad).is_err(), "{bad:?}");
        }
    }

    /// The bytes of Arti's client in tor-socksproto's own test
    /// (`socks5_with_auth_ok`): its offer, its user and password, its
    /// CONNECT; the server's answers, and the arguments joined.
    #[tokio::test]
    async fn arti_s_handshake_is_answered_and_its_arguments_read() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let served = tokio::spawn(async move {
            let raw = accept(&mut server).await;
            reply(&mut server, SUCCEEDED).await.unwrap();
            raw
        });
        client.write_all(&[0x05, 0x02, 0x02, 0x00]).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [5, 2]);
        client.write_all(b"\x01\x05hello\x05world").await.unwrap();
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [1, 0]);
        client.write_all(b"\x05\x01\x00\x03\x12www.torproject.org\x01\xbb").await.unwrap();
        let mut answered = [0u8; 10];
        client.read_exact(&mut answered).await.unwrap();
        assert_eq!(answered[..2], [5, 0]);
        assert_eq!(served.await.unwrap().unwrap(), b"helloworld");
    }

    /// A password of one NUL is no part of the arguments.
    #[tokio::test]
    async fn a_lone_nul_password_is_left_out() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let served = tokio::spawn(async move { accept(&mut server).await });
        client.write_all(&[5, 1, 2, 1, 3]).await.unwrap();
        client.write_all(b"a=1\x01\x00\x05\x01\x00\x01\x00\x00\x00\x01\x00\x01").await.unwrap();
        assert_eq!(served.await.unwrap().unwrap(), b"a=1");
    }
}
