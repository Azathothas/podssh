//! The cleartext road at the role's own listener (T-326, the operator's
//! ruling Q45; `docs/relay.md`, "The cleartext road"): a connection whose
//! first byte begins no TLS handshake, from a client whose proxy tunnels
//! CONNECT but cuts TLS that it does not know. Each hop reads what crosses
//! it, so this serves what a session needs with a token of one session and
//! no more: `GET /health`, which the probe of `podssh doctor` reads; the
//! mint of such a token, `POST /v1/mint?once=1`, for whom `--mint` names and
//! under the same brake; and `/connect/` with such a token, which its
//! upgrade spends. A token of 72 h, the reverse road, the documents and the
//! probes are refused here (`403`): they go over TLS.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::{answer, brake, docs, forward, tokens, Config};

/// The first byte of TLS's record of a handshake, which a ClientHello
/// begins with (RFC 8446, section 5.1); an HTTP request begins with a letter
/// of its method.
pub const HANDSHAKE: u8 = 0x16;

/// The refusal of a token that is not of one session, in cleartext.
const NOT_ONCE: &str = "forward: in cleartext, a token of one session alone (POST /v1/mint?once=1); another \
     token goes over TLS";

/// Whether `first` begins TLS.
pub fn is_tls(first: u8) -> bool {
    first == HANDSHAKE
}

/// The first byte that `tcp` holds, left in it for TLS or HTTP to read;
/// none at its end, on an error, or after `wait`.
pub async fn first_byte(tcp: &TcpStream, wait: Duration) -> Option<u8> {
    let mut byte = [0u8; 1];
    match tokio::time::timeout(wait, tcp.peek(&mut byte)).await {
        Ok(Ok(1)) => Some(byte[0]),
        _ => None,
    }
}

/// Whether a request-target asks for a token of one session, `?once=1`, as
/// a pair asks for a connect token of one upgrade (T-226). The query holds
/// no credential, and the proof of a key (T-448) signs the path alone.
pub fn once_asked(target: &str) -> bool {
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    query.split('&').any(|p| p == "once=1" || p == "once=true")
}

/// Serve the one request of a connection in cleartext from `from`, by whom
/// the brake counts, as over TLS.
pub async fn serve<S>(mut stream: S, cfg: Arc<Config>, from: Option<IpAddr>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some((head, pending, path)) = super::head_of(&mut stream).await else { return };
    if brake::braked(&head.method, &path) {
        if let Err(braked) = cfg.brake.take(brake::Who::of(from)) {
            return super::slow_down(&mut stream, &head, pending, &path, braked, &cfg).await;
        }
    }
    match (head.method.as_str(), path.as_str()) {
        ("GET", "/health") => {
            cfg.event("cleartext GET /health");
            answer(&mut stream, docs::json(&docs::health(&cfg))).await
        }
        ("POST", "/v1/mint") if once_asked(&head.target) => {
            cfg.event("cleartext POST /v1/mint");
            // No TLS: no name that a key's signed mint must name.
            super::mint(&mut stream, &head, pending, &cfg, None).await
        }
        ("POST", "/v1/mint") => {
            cfg.event("cleartext refused POST /v1/mint");
            // The body first, as for each answer: a byte left unread makes
            // the end a reset, which can lose the answer.
            let _ = super::body(&mut stream, &head, pending, super::MINT_BODY, &path).await;
            let why = "/v1/mint: in cleartext, a token of one session alone: POST /v1/mint?once=1";
            answer(&mut stream, request::refusal(403, why, &[])).await
        }
        ("GET", p) if p.starts_with("/connect/") => {
            let once = head.header("x-relay-token").is_some_and(|t| cfg.tokens.is_once(t, tokens::now_ms()));
            if !once {
                cfg.event("cleartext refused GET /connect/");
                return answer(&mut stream, request::refusal(403, NOT_ONCE, &[])).await;
            }
            cfg.event("cleartext GET /connect/");
            // The upgrade spends the token (`Tokens::take`).
            forward::connect(stream, head, pending, cfg).await
        }
        (_, p) => {
            cfg.event("cleartext refused");
            let why = format!("{p}: not served in cleartext; ask over TLS");
            let _ = super::body(&mut stream, &head, pending, super::MINT_BODY, p).await;
            answer(&mut stream, request::refusal(403, &why, &[])).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_of_one_session_is_asked_by_its_query_alone() {
        assert!(once_asked("/v1/mint?once=1") && once_asked("/v1/mint?x=2&once=true"));
        for no in ["/v1/mint", "/v1/mint?once=0", "/v1/mint?nonce=1", "/v1/mint/once=1"] {
            assert!(!once_asked(no), "{no}");
        }
        assert!(is_tls(0x16) && !is_tls(b'G') && !is_tls(b'P'));
    }
}
