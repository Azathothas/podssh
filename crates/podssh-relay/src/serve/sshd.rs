//! The owner's sshd on the role's own port (T-644, GitHub #142): with
//! `podssh relay serve --sshd ADDR:PORT`, a connection of the listener whose
//! first four bytes are `SSH-`, the start of an SSH client's version line
//! (RFC 4253, section 4.2), goes to that sshd with its bytes untouched,
//! copied both ways; each other start goes on as before, to TLS or to the
//! cleartext road ([`super::listener`]). So an owner whose host lets one
//! port in serves the relay and a shell on it. The bytes are peeked, as the
//! node's check of a standard sshd peeks them (`crate::reverse::sshd`), so
//! the sshd reads the client's line whole.
//!
//! The sshd is the owner's own service: no token, no policy of targets (which
//! refuses the loopback) and no limit of the contract stands before it, only
//! its own authentication. It is dialed by the role's way out (T-457), so the
//! loopback, and what `NO_PROXY` names, go directly, as rule 2 of
//! `AGENTS.md` has each dial of the role go. A client that waits for the
//! server's line before it sends its own is never routed: the role speaks
//! for no sshd, and a port scanner's silence dials nothing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::egress::Plan;
use super::Config;

/// The start of each SSH client's version line, `SSH-2.0-...` (RFC 4253,
/// section 4.2): no method of HTTP and no record of TLS begins so.
pub const START: &[u8; 4] = b"SSH-";

/// How long a peek that saw part of the start waits before it looks again:
/// the bytes stay in the socket, so a peek at once would see the same.
const PEEK_AGAIN: Duration = Duration::from_millis(20);

/// The client's one line where the sshd does not answer: a line before any
/// version line, which RFC 4253 (section 4.2) lets a server send and which
/// an SSH client may show; it names no address of the role's host.
pub const NO_SSHD: &[u8] = b"podssh relay serve: the sshd of this port does not answer\r\n";
/// How long, and how many bytes, a client that no sshd answers is read
/// after that line, for a close that is no reset.
const DRAIN_WAIT: Duration = Duration::from_secs(5);
const DRAIN_MOST: usize = 64 * 1024;

/// Whether the first bytes of a connection open SSH: `Some(true)` once four
/// are `SSH-`, `Some(false)` once one differs, `None` for a part of `SSH-`
/// that waits for more.
pub fn judge(bytes: &[u8]) -> Option<bool> {
    let seen = &bytes[..bytes.len().min(START.len())];
    if !START.starts_with(seen) {
        return Some(false);
    }
    (seen.len() == START.len()).then_some(true)
}

/// Whether `tcp` opens SSH, by its first four bytes, peeked until
/// `deadline`: a start that stops short of four bytes, an end and an error
/// are no SSH. Each byte stays in the socket, for the sshd or for the road
/// that takes the connection instead.
pub async fn opens(tcp: &TcpStream, deadline: Instant) -> bool {
    // The four bytes of `START`, no more: what comes after is the sshd's.
    let mut buf = [0u8; 4];
    let look = async {
        loop {
            let n = match tcp.peek(&mut buf).await {
                Ok(n) => n,
                Err(_) => return false,
            };
            if n == 0 {
                return false;
            }
            match judge(&buf[..n]) {
                Some(verdict) => return verdict,
                None => tokio::time::sleep(PEEK_AGAIN).await,
            }
        }
    };
    tokio::time::timeout_at(deadline, look).await.unwrap_or(false)
}

/// Serve `client` with the sshd at `sshd`: dialed by the role's way out
/// within the dial's limit, then each byte copied both ways until each side
/// ended, its version line first. The owner's lines name the client's
/// address and the role's own end of the dial, which the sshd's log names
/// in the client's place.
pub async fn serve(mut client: TcpStream, sshd: SocketAddr, cfg: Arc<Config>) {
    let peer = client.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "a client".into());
    let host = sshd.ip().to_string();
    // The owner's own service: its address as named, never the policy of
    // targets, which refuses the loopback.
    let plan = Plan::Addresses(vec![sshd]);
    let mut far = match super::forward::dial(&host, &plan, &cfg).await {
        Ok(far) => far,
        Err(why) => {
            cfg.event(&format!("sshd from {peer}: the sshd at {sshd} did not answer: {why}"));
            return no_sshd(client).await;
        }
    };
    // Each keystroke goes on at once, as OpenSSH sends it on its own socket:
    // the role adds no wait of Nagle's to an interactive session.
    let _ = (client.set_nodelay(true), far.set_nodelay(true));
    let via = far.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| "an address of this host".into());
    cfg.event(&format!("sshd from {peer}, at the sshd as {via}"));
    let started = Instant::now();
    let ended = match tokio::io::copy_bidirectional(&mut client, &mut far).await {
        Ok((up, down)) => format!("{up} bytes up and {down} down"),
        Err(e) => format!("cut: {e}"),
    };
    cfg.event(&format!("sshd from {peer} ended after {} s, {ended}", started.elapsed().as_secs()));
}

/// Tell `client` that no sshd answers, in [`NO_SSHD`], then read what it
/// sent until its end, bounded: a byte of it left unread would make the
/// role's close a reset, which can lose the line.
async fn no_sshd(mut client: TcpStream) {
    let _ = client.write_all(NO_SSHD).await;
    let _ = client.shutdown().await;
    let mut sink = [0u8; 4096];
    let drain = async {
        let mut left = DRAIN_MOST;
        while left > 0 {
            match client.read(&mut sink).await {
                Ok(n) if n > 0 => left = left.saturating_sub(n),
                _ => break,
            }
        }
    };
    let _ = tokio::time::timeout(DRAIN_WAIT, drain).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_bytes_of_ssh_decide_and_another_start_decides_at_once() {
        for ssh in [&b"SSH-"[..], b"SSH-2.0-OpenSSH_9.6\r\n", b"SSH-1.99-old"] {
            assert_eq!(judge(ssh), Some(true), "{ssh:?}");
        }
        // TLS's record of a handshake, a method of HTTP, and a start that
        // leaves SSH's at its second, third or fourth byte.
        for other in [&[0x16u8, 0x03, 0x01][..], b"GET /health", b"POST", b"SEARCH", b"SSX", b"SSH_", b"ssh-"] {
            assert_eq!(judge(other), Some(false), "{other:?}");
        }
    }

    #[test]
    fn part_of_the_start_waits_for_more() {
        for part in [&b""[..], b"S", b"SS", b"SSH"] {
            assert_eq!(judge(part), None, "{part:?}");
        }
    }
}
