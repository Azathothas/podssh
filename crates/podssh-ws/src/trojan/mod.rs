//! Trojan (T-491, the operator's ruling Q66): a server that the user runs,
//! trojan-gfw's, trojan-go's, Xray-core's or sing-box's, takes the target
//! from a short request after a real TLS handshake and dials it, so that it
//! is a road in place of the relay. The stream goes in TLS alone, or in a
//! WebSocket over TLS ([`ws`]), which passes through a CDN and where a front
//! end serves other paths. TLS is podssh's, checked for the link's name,
//! through `HTTPS_PROXY` when it is set, as each road dials.
//!
//! The link and its password come from a private file ([`link`]); the
//! request is [`request`]'s. Trojan has no answer, so the first bytes tell
//! the target from the server's fallback ([`answer`]): a session whose server
//! speaks first (SSH) waits for them, and one whose client may speak first
//! (a pipe) takes the stream after a short silence. The settings of a dial
//! are VLESS's ([`crate::vless::Dial`]), as both roads dial alike.

mod answer;
pub mod link;
mod request;
mod ws;

use std::time::Duration;

use crate::dial::DialError;
use crate::via::Duplex;

pub use crate::vless::Dial;
pub use link::{Password, Server, Transport};

/// How long a session whose server speaks first waits for its first bytes.
pub const ANSWER_WAIT: Duration = Duration::from_secs(10);
/// How long a pipe waits before it takes the stream: a fallback answers
/// the request's bytes at once.
pub const EARLY_WAIT: Duration = Duration::from_secs(3);

/// Why a Trojan server carried no session.
#[derive(Debug)]
pub enum TrojanError {
    /// The target cannot go in Trojan's request.
    Target(String),
    /// TCP, or the host's proxy.
    Dial(DialError),
    /// TLS or the upgrade failed: what failed.
    Carry(String),
    /// The WebSocket's upgrade was refused: its status, and what it refused.
    Refused { status: u16, why: String },
    /// The server's fallback answered: the password, or the request, was not
    /// the server's. The fallback's status line.
    Fallback(String),
    /// The server ended the session before any byte of the target.
    Ended,
    /// No byte within the wait.
    Silent(Duration),
}

impl TrojanError {
    /// The line that says it, for the server `shown` and the target. No line
    /// holds the password or its hash.
    pub fn line(&self, shown: &str, target: &str) -> String {
        match self {
            TrojanError::Target(why) => format!("{target} cannot go to the Trojan server {shown}: {why}"),
            TrojanError::Dial(e) => format!("the Trojan server {shown}: {e}"),
            TrojanError::Carry(why) => format!("the Trojan server {shown}: {why}"),
            TrojanError::Refused { status, why } => format!("the Trojan server {shown} refused {why}: HTTP {status}"),
            TrojanError::Fallback(line) => format!(
                "the Trojan server {shown} handed the session to its fallback, which answered {line:?}: the password \
                 of the link is not the server's, or the server reads no request of Trojan at this port or path"
            ),
            TrojanError::Ended => format!(
                "the Trojan server {shown}, for {target}: the server ended the session before the target said \
                 anything: a wrong password where the server has no fallback, or the server could not reach the \
                 target"
            ),
            TrojanError::Silent(after) => format!(
                "the Trojan server {shown} gave nothing for {target} within {} s: the target said nothing, a proxy \
                 or a front end between holds the bytes, or the server holds the session",
                after.as_secs()
            ),
        }
    }
}

/// A session to the target.
pub struct Opened {
    pub stream: Box<dyn Duplex>,
    /// What carried it: "TLS", "a WebSocket over TLS".
    pub how: &'static str,
    /// The target's first bytes came within the wait.
    pub answered: bool,
}

/// A session to `host:port` through `server`, on the link's transport.
pub async fn open(server: &Server, host: &str, port: u16, dial: &Dial<'_>) -> Result<Opened, TrojanError> {
    let request = request::request(&server.password, host, port).map_err(TrojanError::Target)?;
    let stream: Box<dyn Duplex> = match server.transport {
        Transport::Tls => Box::new(tls(server, request, dial).await?),
        Transport::Ws => Box::new(ws::open(server, request, dial).await?),
    };
    let mut stream = answer::Answered::new(stream);
    let answered = match tokio::time::timeout(dial.answer, stream.first()).await {
        Ok(Ok(())) => true,
        Ok(Err(answer::FirstError::Ended)) => return Err(TrojanError::Ended),
        Ok(Err(answer::FirstError::Fallback(line))) => return Err(TrojanError::Fallback(line)),
        Ok(Err(answer::FirstError::Io(e))) => {
            return Err(TrojanError::Carry(format!("before the target's bytes: {e}")))
        }
        Err(_) if dial.silence_is_ready => false,
        Err(_) => return Err(TrojanError::Silent(dial.answer)),
    };
    Ok(Opened { stream: Box::new(stream), how: server.transport.name(), answered })
}

/// TLS for the link's name, then the request as the first bytes of its
/// stream, in one write, as trojan-gfw reads it whole from its first read.
async fn tls(server: &Server, request: Vec<u8>, dial: &Dial<'_>) -> Result<impl Duplex + use<>, TrojanError> {
    use tokio::io::AsyncWriteExt;
    let mut tls = crate::client::open_tls(&server.host, server.port, &server.sni, dial.trust, dial.proxy, dial.timeout)
        .await
        .map_err(|e| ws::failed(e, "/"))?;
    let sent = async {
        tls.write_all(&request).await?;
        tls.flush().await
    };
    tokio::time::timeout(dial.timeout, sent)
        .await
        .map_err(|_| TrojanError::Carry(format!("Trojan's request not sent within {} s", dial.timeout.as_secs())))?
        .map_err(|e| TrojanError::Carry(format!("sending Trojan's request failed: {e}")))?;
    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_names_the_server_and_never_the_password() {
        let shown = "trojan://t.example:443";
        let fallback = TrojanError::Fallback("HTTP/1.1 400 Bad Request".into()).line(shown, "h.example:22");
        assert!(fallback.contains("fallback, which answered \"HTTP/1.1 400 Bad Request\""), "{fallback}");
        assert!(fallback.contains("password of the link is not the server's"), "{fallback}");
        assert!(TrojanError::Ended.line(shown, "h:22").contains("before the target said anything"));
        assert!(TrojanError::Silent(ANSWER_WAIT).line(shown, "h:22").contains("within 10 s"));
        let refused = TrojanError::Refused { status: 404, why: "the WebSocket upgrade at /tr".into() };
        assert_eq!(
            refused.line(shown, "h:22"),
            "the Trojan server trojan://t.example:443 refused the WebSocket upgrade at /tr: HTTP 404"
        );
    }
}
