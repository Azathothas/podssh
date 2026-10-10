//! The SOCKS side of `-D` (T-038): SOCKS4, SOCKS4a and SOCKS5 with CONNECT
//! and no authentication, as OpenSSH's `-D` serves them. BIND, UDP
//! ASSOCIATE and each authentication method are refused. podssh opens the
//! server's channel before it answers, so a client learns whether the
//! target was reached (OpenSSH answers first, then opens).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// What a client asked to reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub version: Version,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Four,
    Five,
}

/// Why a request was not carried, as SOCKS5 says it (SOCKS4 has one code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The server's channel failed for another reason (1).
    General,
    /// The server refused the channel by its rules (2).
    NotAllowed,
    /// The server could not reach the target (5).
    Refused,
    /// BIND or UDP ASSOCIATE (7).
    Command,
    /// An address type that SOCKS5 does not define (8).
    AddressType,
}

impl Refusal {
    fn code(self) -> u8 {
        match self {
            Refusal::General => 1,
            Refusal::NotAllowed => 2,
            Refusal::Refused => 5,
            Refusal::Command => 7,
            Refusal::AddressType => 8,
        }
    }
}

/// A user id or a host name of SOCKS4a: 255 bytes at most, as SOCKS5's.
const NAME_MAX: usize = 255;

/// Read a client's request. A refusal that the client can read is sent
/// here; `Err` says why, for a line with `-v`.
pub async fn read_request<R, W>(read: &mut R, write: &mut W) -> Result<Request, String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match read.read_u8().await.map_err(|e| format!("no request: {e}"))? {
        4 => four(read, write).await,
        5 => five(read, write).await,
        other => Err(format!("version {other} is not SOCKS 4 or 5")),
    }
}

/// SOCKS4 and SOCKS4a: CD, DSTPORT, DSTIP, USERID and NUL; with DSTIP
/// 0.0.0.x (x not 0), a host name and NUL follow.
async fn four<R, W>(read: &mut R, write: &mut W) -> Result<Request, String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut head = [0u8; 7];
    read.read_exact(&mut head).await.map_err(|e| format!("a short SOCKS4 request: {e}"))?;
    let port = u16::from_be_bytes([head[1], head[2]]);
    let ip = [head[3], head[4], head[5], head[6]];
    let _user = until_nul(read).await?;
    if head[0] != 1 {
        let _ = answer(write, Version::Four, Err(Refusal::Command)).await;
        return Err(format!("SOCKS4 command {} is not CONNECT", head[0]));
    }
    let host = if ip[..3] == [0, 0, 0] && ip[3] != 0 {
        String::from_utf8(until_nul(read).await?).map_err(|_| "a SOCKS4a host name that is not UTF-8".to_string())?
    } else {
        std::net::Ipv4Addr::from(ip).to_string()
    };
    Ok(Request { version: Version::Four, host, port })
}

/// SOCKS5: the methods, then VER CMD RSV ATYP DST.ADDR DST.PORT.
async fn five<R, W>(read: &mut R, write: &mut W) -> Result<Request, String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let count = read.read_u8().await.map_err(|e| format!("a short SOCKS5 greeting: {e}"))?;
    let mut methods = vec![0u8; usize::from(count)];
    read.read_exact(&mut methods).await.map_err(|e| format!("a short SOCKS5 greeting: {e}"))?;
    if !methods.contains(&0) {
        let _ = write.write_all(&[5, 0xff]).await;
        return Err("the client offered no method without authentication".into());
    }
    write.write_all(&[5, 0]).await.map_err(|e| format!("the client left: {e}"))?;
    let mut head = [0u8; 4];
    read.read_exact(&mut head).await.map_err(|e| format!("a short SOCKS5 request: {e}"))?;
    if head[0] != 5 {
        return Err(format!("a SOCKS5 request of version {}", head[0]));
    }
    let host = match head[3] {
        1 => {
            let mut ip = [0u8; 4];
            read.read_exact(&mut ip).await.map_err(|e| e.to_string())?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let len = read.read_u8().await.map_err(|e| e.to_string())?;
            let mut name = vec![0u8; usize::from(len)];
            read.read_exact(&mut name).await.map_err(|e| e.to_string())?;
            String::from_utf8(name).map_err(|_| "a SOCKS5 host name that is not UTF-8".to_string())?
        }
        4 => {
            let mut ip = [0u8; 16];
            read.read_exact(&mut ip).await.map_err(|e| e.to_string())?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        other => {
            let _ = answer(write, Version::Five, Err(Refusal::AddressType)).await;
            return Err(format!("SOCKS5 address type {other}"));
        }
    };
    let port = read.read_u16().await.map_err(|e| e.to_string())?;
    if head[1] != 1 {
        let _ = answer(write, Version::Five, Err(Refusal::Command)).await;
        return Err(format!("SOCKS5 command {} is not CONNECT", head[1]));
    }
    if host.is_empty() {
        let _ = answer(write, Version::Five, Err(Refusal::General)).await;
        return Err("an empty SOCKS5 host name".into());
    }
    Ok(Request { version: Version::Five, host, port })
}

/// Bytes up to a NUL, which is taken off; at most `NAME_MAX`.
async fn until_nul<R: AsyncRead + Unpin>(read: &mut R) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        match read.read_u8().await.map_err(|e| format!("a short SOCKS4 request: {e}"))? {
            0 => return Ok(out),
            _ if out.len() == NAME_MAX => return Err(format!("a SOCKS4 name of more than {NAME_MAX} bytes")),
            b => out.push(b),
        }
    }
}

/// The answer to a request: granted, or refused with its reason. The bound
/// address is all zeros, as OpenSSH sends it: the channel has none.
pub async fn answer<W: AsyncWrite + Unpin>(
    write: &mut W,
    version: Version,
    outcome: Result<(), Refusal>,
) -> std::io::Result<()> {
    let reply: Vec<u8> = match (version, outcome) {
        (Version::Four, Ok(())) => vec![0, 90, 0, 0, 0, 0, 0, 0],
        (Version::Four, Err(_)) => vec![0, 91, 0, 0, 0, 0, 0, 0],
        (Version::Five, Ok(())) => vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        (Version::Five, Err(why)) => vec![5, why.code(), 0, 1, 0, 0, 0, 0, 0, 0],
    };
    write.write_all(&reply).await?;
    write.flush().await
}

#[cfg(test)]
#[path = "socks_tests.rs"]
mod tests;
