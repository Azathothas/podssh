//! A handler that offers a TCP service: each session of the relay is one
//! connection to TARGET.

use std::time::Duration;

use podssh_ws::ProxyChoice;
use tokio::net::TcpStream;

use super::framing::SessionId;
use super::node::{Handler, Opening};
use super::sshd;

/// Each session dials `host:port`, with `podssh_ws::dial::dial`, which keeps a
/// loopback target off any proxy of the environment.
#[derive(Debug, Clone)]
pub struct TcpHandler {
    pub host: String,
    pub port: u16,
    /// Bound on each dial, under the node's limit for opening a session.
    pub timeout: Duration,
    /// A roost (T-166): TARGET is a standard sshd, whose version line comes
    /// first on each connection, or the session is refused.
    pub sshd: bool,
}

impl Handler for TcpHandler {
    type Stream = TcpStream;

    fn open(&self, _id: SessionId) -> Opening<TcpStream> {
        let (host, port, timeout, sshd) = (self.host.clone(), self.port, self.timeout, self.sshd);
        Box::pin(async move { dial_target(&host, port, timeout, sshd).await })
    }
}

/// One connection to `host:port`; with `sshd`, a roost's, which must then
/// send an SSH version line first (T-166). The line stays in the stream for
/// the session's SSH client.
pub async fn dial_target(host: &str, port: u16, timeout: Duration, sshd: bool) -> Result<TcpStream, String> {
    let stream =
        podssh_ws::dial::dial(host, port, &ProxyChoice::FromEnvironment, timeout).await.map_err(|e| e.to_string())?;
    if sshd {
        let at = podssh_ws::dial::authority(host, port);
        sshd::check(&stream, sshd::BANNER_LIMIT).await.map_err(|why| format!("{at} is not an SSH server: it {why}"))?;
    }
    Ok(stream)
}
