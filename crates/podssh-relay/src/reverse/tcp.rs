//! A handler that offers a TCP service: each session of the relay is one
//! connection to TARGET.

use std::time::Duration;

use podssh_transport::SessionId;
use podssh_ws::ProxyChoice;
use tokio::net::TcpStream;

use super::node::{Handler, Opening};

/// Each session dials `host:port`, with `podssh_ws::dial::dial`, which keeps a
/// loopback target off any proxy of the environment.
#[derive(Debug, Clone)]
pub struct TcpHandler {
    pub host: String,
    pub port: u16,
    /// Bound on each dial, under the node's limit for opening a session.
    pub timeout: Duration,
}

impl Handler for TcpHandler {
    type Stream = TcpStream;

    fn open(&self, _id: SessionId) -> Opening<TcpStream> {
        let (host, port, timeout) = (self.host.clone(), self.port, self.timeout);
        Box::pin(async move {
            podssh_ws::dial::dial(&host, port, &ProxyChoice::FromEnvironment, timeout)
                .await
                .map_err(|e| e.to_string())
        })
    }
}
