//! One connection of the role's own listener, which `podssh relay serve`
//! owns (T-169): TLS, with the handshake alone for a CA's TLS-ALPN-01
//! (T-447); or, when its first byte begins no TLS handshake, the cleartext
//! road ([`super::cleartext`], T-326), unless the owner turned it off. The
//! byte is peeked, so TLS reads its ClientHello whole. One listener, the one
//! that the user asked for: the cleartext road adds none. A client whose TLS
//! chose `h2` gets HTTP/2 with extended CONNECT ([`super::http2`], T-321).
//! Where the owner named an sshd, a connection whose first four bytes are
//! `SSH-` goes to it, peeked too ([`super::sshd`], T-644).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::tls_server::{TlsAcceptor, ACME_TLS_1};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use super::Config;

/// How long a client has to begin, and to finish, TLS.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(30);

/// How the listener takes a connection: TLS with `acceptor`, the cleartext
/// road beside it when `cleartext`, and an SSH client to `sshd` when the
/// owner named one.
#[derive(Clone)]
pub struct Door {
    pub acceptor: TlsAcceptor,
    pub cleartext: bool,
    /// The owner's sshd, for a connection whose first bytes are `SSH-`
    /// (T-644); none unless named.
    pub sshd: Option<SocketAddr>,
}

/// Serve `tcp`, of a client at `peer`, as `door` says.
pub async fn connection(tcp: TcpStream, peer: IpAddr, door: Door, cfg: Arc<Config>) {
    if door.cleartext || door.sshd.is_some() {
        // One bound for the first byte and for the start of SSH after it.
        let deadline = tokio::time::Instant::now() + HANDSHAKE_WAIT;
        match super::cleartext::first_byte(&tcp, HANDSHAKE_WAIT).await {
            Some(first) if super::cleartext::is_tls(first) => {}
            Some(_) => {
                // An SSH client's version line goes to the owner's sshd; a
                // start that is no SSH goes on as before.
                if let Some(sshd) = door.sshd {
                    if super::sshd::opens(&tcp, deadline).await {
                        // Boxed: a session's future stays off the caller's.
                        return Box::pin(super::sshd::serve(tcp, sshd, cfg)).await;
                    }
                }
                if door.cleartext {
                    return super::cleartext::serve(tcp, cfg, Some(peer)).await;
                }
            }
            // Nothing came, or the client went: no TLS to wait for either.
            None => return,
        }
    }
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_WAIT, door.acceptor.accept(tcp)).await else { return };
    // A CA's validation of TLS-ALPN-01 wants the handshake alone (RFC 8737,
    // section 3).
    if tls.get_ref().1.alpn_protocol() == Some(ACME_TLS_1) {
        let _ = tls.shutdown().await;
        return;
    }
    // The name that the client asked for, which a key's signed mint must
    // name (T-448).
    let sni = tls.get_ref().1.server_name().map(str::to_string);
    // HTTP/2, where the client chose it by ALPN (T-321): each stream is a
    // request of its own to the routes below.
    if tls.get_ref().1.alpn_protocol() == Some(super::http2::H2) {
        return super::http2::serve(tls, cfg, sni, Some(peer)).await;
    }
    // The TCP peer, by whom the brake of mints and pairs counts (T-454): no
    // header of a client's.
    super::serve_from(tls, cfg, sni, Some(peer)).await;
}
