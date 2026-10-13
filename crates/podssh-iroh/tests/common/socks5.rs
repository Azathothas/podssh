//! A stand-in SOCKS5 proxy (RFC 1928), as a sandbox's (T-280): a CONNECT to
//! the relay's name, [`super::RELAY_NAME`], opens a tunnel to the relay on
//! the loopback; a CONNECT to an address, or to another name, gets reply 2
//! (not allowed by its rules). Given a user and a password, it asks for them
//! (RFC 1929) and refuses others. It keeps the address type and the host of
//! each CONNECT.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One CONNECT that the stand-in got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The address type: 1 (IPv4), 3 (a name) or 4 (IPv6).
    pub address_type: u8,
    /// The name, or the address as text.
    pub host: String,
    pub port: u16,
}

/// The stand-in, for a relay on the loopback at `relay_port`; with
/// `credentials`, the user and the password that it takes. Each CONNECT that
/// it got, in order.
pub async fn proxy(
    relay_port: u16,
    credentials: Option<(&'static str, &'static str)>,
) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let kept = kept.clone();
            tokio::spawn(async move {
                let _ = tunnel(client, relay_port, credentials, &kept).await;
            });
        }
    });
    (addr, seen)
}

async fn tunnel(
    mut client: TcpStream,
    relay_port: u16,
    credentials: Option<(&str, &str)>,
    seen: &Mutex<Vec<Seen>>,
) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut methods).await?;
    // The method of its setting, when the client offers it.
    let wanted = if credentials.is_some() { 0x02 } else { 0x00 };
    if head[0] != 5 || !methods.contains(&wanted) {
        client.write_all(&[5, 0xff]).await?;
        return Ok(());
    }
    client.write_all(&[5, wanted]).await?;
    if let Some((user, password)) = credentials {
        let mut version_and_length = [0u8; 2];
        client.read_exact(&mut version_and_length).await?;
        let mut got_user = vec![0u8; usize::from(version_and_length[1])];
        client.read_exact(&mut got_user).await?;
        let mut length = [0u8; 1];
        client.read_exact(&mut length).await?;
        let mut got_password = vec![0u8; usize::from(length[0])];
        client.read_exact(&mut got_password).await?;
        let taken = got_user == user.as_bytes() && got_password == password.as_bytes();
        client.write_all(&[1, if taken { 0 } else { 1 }]).await?;
        if !taken {
            return Ok(());
        }
    }
    let mut request = [0u8; 4];
    client.read_exact(&mut request).await?;
    let host = match request[3] {
        1 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        4 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            let mut length = [0u8; 1];
            client.read_exact(&mut length).await?;
            let mut name = vec![0u8; usize::from(length[0])];
            client.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    seen.lock().unwrap().push(Seen { address_type: request[3], host: host.clone(), port });
    let bound = [1, 127, 0, 0, 1, 0, 0];
    if request[3] != 3 || host != super::RELAY_NAME || port != relay_port {
        client.write_all(&[&[5, 2, 0][..], &bound[..]].concat()).await?;
        return Ok(());
    }
    let mut relay = TcpStream::connect(("127.0.0.1", relay_port)).await?;
    client.write_all(&[&[5, 0, 0][..], &bound[..]].concat()).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
    Ok(())
}
