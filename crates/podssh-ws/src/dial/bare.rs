//! The way out of the TLS roads: [`super::dialer`]'s connection handed to
//! rustls as the bare `TcpStream`, not inside `pod_proxy::Stream`.
//!
//! rustls writes its records with `write_vectored`. `pod_proxy::Stream`
//! (v0.3.0) does not pass vectored writes on, so each call sends one buffer,
//! and a write that the far end holds keeps a TLS session from reading: an
//! upload through a relay that ends each session after 1.5 MB then lost the
//! answers of the writes that the server took, on every try (the interop
//! check `resume.cut.up.sftp`). A connection through a proxy on a Unix
//! socket or at a command is no TCP and goes as it is.

use std::net::SocketAddr;

use pod_core::{BoxFuture, Connected, Dial, Failure, Target};
use pod_proxy::Dialer;
use tokio::time::Instant;

/// [`Dialer`], giving a TCP connection as the bare stream.
pub struct Bare(pub Dialer);

impl Dial for Bare {
    fn label(&self) -> String {
        self.0.label()
    }

    fn dial<'a>(&'a self, target: &'a Target, deadline: Instant) -> BoxFuture<'a, Result<Connected, Failure>> {
        Box::pin(async move {
            let budget = deadline.saturating_duration_since(Instant::now());
            let (stream, _) = self.0.stream(&target.host(), target.port(), budget).await?;
            let (peer, local) = (stream.peer_addr(), stream.local_addr());
            let io: pod_core::BoxedIo = match stream.into_tcp() {
                Ok(tcp) => Box::new(tcp),
                Err(other) => Box::new(other),
            };
            Ok(Connected { io, peer, local })
        })
    }

    fn dial_addrs<'a>(
        &'a self,
        host: &'a str,
        addrs: &'a [SocketAddr],
        deadline: Instant,
    ) -> BoxFuture<'a, Result<Connected, Failure>> {
        self.0.dial_addrs(host, addrs, deadline)
    }

    fn names_inside(&self) -> bool {
        self.0.names_inside()
    }
}
