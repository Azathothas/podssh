//! Names inside the tunnel: DNS over TCP (RFC 7766, a length of two bytes
//! before each message) to Cloudflare's resolver, reached through WARP as
//! the target is, in the wire form of podssh-ws (`resolve::wire`). The host
//! of a cage resolves no name itself, and the proxy would be asked for each
//! name of the road, so the tunnel's own way out answers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use podssh_ws::resolve::wire;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::stack::Stack;

/// Cloudflare's resolvers, each family's first; the tunnel reaches them as
/// any address.
pub const RESOLVERS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];

/// The DNS port.
pub const PORT: u16 = 53;

/// The addresses of `name`, A then AAAA, from the first resolver of
/// `resolvers` that the stack can reach and that answers; NXDOMAIN ends the
/// lookup.
pub async fn lookup(stack: &Stack, resolvers: &[IpAddr], name: &str, limit: Duration) -> Result<Vec<IpAddr>, String> {
    let families: Vec<bool> = stack.addresses().iter().map(IpAddr::is_ipv4).collect();
    let mut reasons = Vec::new();
    for resolver in resolvers.iter().filter(|r| families.contains(&r.is_ipv4())) {
        let mut found = Vec::new();
        let mut answered = false;
        for kind in [wire::A, wire::AAAA] {
            match ask(stack, SocketAddr::new(*resolver, PORT), name, kind, limit).await {
                Ok(ips) => {
                    answered = true;
                    found.extend(ips);
                }
                Err(e) if e.ends_with(podssh_ws::resolve::NXDOMAIN) => return Err(format!("{resolver}: {e}")),
                Err(e) => reasons.push(format!("{resolver}: {e}")),
            }
        }
        if answered && !found.is_empty() {
            return Ok(found);
        }
        if answered {
            reasons.push(format!("{resolver}: no address"));
        }
    }
    Err(if reasons.is_empty() { "no resolver of this device's families".into() } else { reasons.join("; ") })
}

/// One question to `resolver`, on a connection of its own.
async fn ask(
    stack: &Stack,
    resolver: SocketAddr,
    name: &str,
    kind: u16,
    limit: Duration,
) -> Result<Vec<IpAddr>, String> {
    let query = wire::query(name, kind)?;
    let mut stream = stack.connect(resolver, limit).await?;
    let asked = async {
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        stream.write_all(&framed).await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut answer).await?;
        Ok::<_, std::io::Error>(answer)
    };
    let answer = tokio::time::timeout(limit, asked)
        .await
        .map_err(|_| format!("no answer within {} s", limit.as_secs()))?
        .map_err(|e| e.to_string())?;
    wire::addrs(&answer, name, kind)
}
