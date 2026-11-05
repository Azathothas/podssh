//! `podssh relay serve --quic yes` (T-667): QUIC on UDP at the listener's
//! own address and port, a second socket that the user asks for, as the
//! listener is (Q1): PODSSH_LISTEN=no refuses both before either is bound,
//! and a bind that fails stops the start, as the listener's does. The
//! socket is bound with the listener, before the capabilities of the start
//! go (T-629), as port 443 needs one; the role's endpoint is made on it once
//! the runtime runs, and `/relays.json` offers it as `forward.quic`.

use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;

use podssh_relay::serve::layer::Resumes;
use podssh_relay::serve::Config;
use podssh_ws::tls_server::Served;

use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::relay_settings::Refusal;

/// Whether `--quic WORD` asks for QUIC: no, unless asked.
pub(super) fn asked(word: Option<&str>) -> Result<bool, Refusal> {
    match word {
        None => Ok(false),
        Some(word) => crate::forwarder::fallback::word(word)
            .ok_or_else(|| Refusal::usage(format!("--quic {word:?}: yes or no"))),
    }
}

/// QUIC's socket where `asked`: UDP at the address and port that `tcp` is
/// bound to, a port that `--listen ADDR:0` chose too.
pub(super) fn bind(asked: bool, tcp: &TcpListener) -> Result<Option<UdpSocket>, Refusal> {
    if !asked {
        return Ok(None);
    }
    let at = tcp.local_addr().map_err(|e| Refusal::config(e.to_string()))?;
    UdpSocket::bind(at)
        .map(Some)
        .map_err(|e| Refusal { message: format!("cannot take UDP {at} for QUIC: {e}"), code: EX_UNAVAILABLE })
}

/// `sessions` with the port of `socket` in their offer.
pub(super) fn offered(sessions: Resumes, socket: &Option<UdpSocket>) -> Resumes {
    match socket.as_ref().and_then(|socket| socket.local_addr().ok()) {
        Some(at) => sessions.with_quic(at.port()),
        None => sessions,
    }
}

/// The words of the first line, after a comma: nothing without QUIC.
pub(super) fn shown(socket: &Option<UdpSocket>) -> String {
    match socket.as_ref().and_then(|socket| socket.local_addr().ok()) {
        Some(at) => format!(", QUIC on UDP {at}"),
        None => String::new(),
    }
}

/// Serve QUIC on `socket`, its TLS what `served` holds at each handshake;
/// called in the runtime, which drives the endpoint.
pub(super) fn spawn(socket: UdpSocket, served: Arc<Served>, cfg: Arc<Config>) -> Result<(), String> {
    let endpoint = podssh_relay::serve::quic::endpoint(socket, served)?;
    tokio::spawn(podssh_relay::serve::quic::serve(endpoint, cfg));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-667: QUIC only when asked, its words read strictly, and its socket
    // at the listener's own address and port.
    #[test]
    fn quic_is_asked_for_and_takes_the_listener_s_port() {
        assert_eq!(asked(None), Ok(false));
        assert_eq!(asked(Some("yes")), Ok(true));
        assert_eq!(asked(Some("no")), Ok(false));
        let wrong = asked(Some("udp")).unwrap_err();
        assert!(wrong.code == crate::exit_codes::EXIT_USAGE && wrong.message.contains("yes or no"), "{wrong:?}");
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(bind(false, &tcp).unwrap().is_none());
        // Another process may hold the same port of UDP: then the start
        // stops, as a listener's bind does.
        match bind(true, &tcp) {
            Ok(Some(udp)) => {
                assert_eq!(udp.local_addr().unwrap(), tcp.local_addr().unwrap());
                assert_eq!(shown(&Some(udp)), format!(", QUIC on UDP {}", tcp.local_addr().unwrap()));
            }
            Ok(None) => panic!("asked, and no socket"),
            Err(refused) => assert_eq!(refused.code, EX_UNAVAILABLE, "{refused:?}"),
        }
        assert_eq!(shown(&None), "");
    }
}
