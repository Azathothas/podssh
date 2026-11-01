//! A WebSocket forwarder that takes its target from the client (T-369): the
//! plumbing of another product, such as the Worker of Mudlet's web client or
//! the proxy of ssheasy's SSH client in a browser, which dials the host and
//! the port that a client names and carries the bytes in binary frames.
//! The target goes in the URL, by a [`Template`] with `{host}` and
//! `{port}`, or in a first text frame of JSON, which the forwarder answers
//! before the target's bytes. The dial is that of a WebSocket by its URL
//! ([`crate::url::dial`]): TLS checked for the forwarder's name, through the
//! proxy of the environment, and no token: a relay token goes only to the
//! deployment that minted it, and a forwarder is another product's.

// The public forwarders of other products that the binary names (T-370).
pub mod builtin;
mod carry;
mod template;

use std::sync::Arc;
use std::time::Duration;

use carry::First;

use crate::client::ConnectError;
use crate::dial::ProxyChoice;
use crate::tls::Trust;

pub use carry::{Carried, Ended, Status};
pub use template::{Form, Template, HOST, PORT};

/// Where each text frame of a forwarder goes, one safe line each.
pub type Note = Arc<dyn Fn(&str) + Send + Sync>;

/// How long the query form waits after the upgrade for the forwarder's
/// first frame. A Worker answers the upgrade before it dials the target,
/// so a target that it cannot reach is a Close that comes after the 101:
/// one that comes within this wait lets the next forwarder be tried. A
/// target whose client speaks first sends nothing, and its session starts
/// once the wait ends.
pub const EARLY_WAIT: Duration = Duration::from_secs(3);

/// The largest frame taken from a forwarder, which publishes no size: a
/// Worker sends what each read of its socket gave.
pub const RECEIVE_CAP: usize = 1024 * 1024;

/// What a forwarder's road needs, beside its template and its target.
pub struct Dial<'a> {
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// Bound on the dial, on the upgrade, and on the answer of the frame
    /// form.
    pub timeout: Duration,
    /// Whether the end of this side's bytes sends a Close at once (an SSH
    /// session's end), or the session waits for the forwarder's end, as the
    /// target may still answer (a pipe).
    pub close_at_end: bool,
    pub note: Note,
}

/// Why a forwarder carried no session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwarderError {
    /// The target cannot go in the template; no other forwarder takes it.
    Target(String),
    /// The dial or the upgrade, as [`crate::url::dial`] gives it.
    Connect(ConnectError),
    /// The forwarder's answer to the target, or none.
    Answer(String),
    /// The forwarder's Close before the target's first bytes: it could not
    /// reach the target, as a Worker says.
    Closed { code: Option<u16>, reason: String },
}

impl ForwarderError {
    /// The line that says it, the forwarder named as `shown`.
    pub fn line(&self, shown: &str) -> String {
        match self {
            ForwarderError::Target(why) | ForwarderError::Answer(why) => format!("the forwarder {shown}: {why}"),
            ForwarderError::Connect(ConnectError::Refused { status, body }) if body.is_empty() => {
                format!("the forwarder {shown} refused the upgrade: HTTP {status}")
            }
            ForwarderError::Connect(ConnectError::Refused { status, body }) => {
                format!("the forwarder {shown} refused the upgrade: HTTP {status}: {body}")
            }
            ForwarderError::Connect(ConnectError::Tls(why)) => format!("TLS with the forwarder {shown} failed: {why}"),
            ForwarderError::Connect(ConnectError::Upgrade(why)) => {
                format!("the WebSocket upgrade with the forwarder {shown} failed: {why}")
            }
            ForwarderError::Connect(other) => format!("the forwarder {shown}: {other}"),
            ForwarderError::Closed { code, reason } => {
                let code = code.map_or_else(|| "no code".to_string(), |c| c.to_string());
                let reason = crate::text::one_line(reason);
                let said = if reason.is_empty() { String::new() } else { format!(" {reason}") };
                format!("the forwarder {shown} closed the WebSocket before the target's bytes: {code}{said}")
            }
        }
    }
}

/// The answer of the frame form: `{"status":"ok"}`, as ssheasy sends it;
/// `{"status":"failed","error":E}` is its word that it could not reach the
/// target.
pub fn answer(payload: &[u8]) -> Result<(), String> {
    let doc: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|_| "its first answer is not JSON: it may not take a target in a first frame".to_string())?;
    match doc.get("status").and_then(|s| s.as_str()) {
        Some("ok") => Ok(()),
        Some(status) => {
            let error = doc.get("error").and_then(|e| e.as_str()).map(crate::text::one_line).unwrap_or_default();
            let status = crate::text::one_line(status);
            match error.is_empty() {
                true => Err(format!("it could not reach the target ({status})")),
                false => Err(format!("it could not reach the target ({status}): {error}")),
            }
        }
        None => Err("its first answer has no status".into()),
    }
}

/// A session to `host:port` through the forwarder of `template`: the dial
/// and the upgrade with no token, the first frame of the frame form and its
/// answer, and the forwarder's first word in the query form, within
/// [`EARLY_WAIT`].
pub async fn open(template: &Template, host: &str, port: u16, dial: &Dial<'_>) -> Result<Carried, ForwarderError> {
    let url = template.fill(host, port).map_err(ForwarderError::Target)?;
    let idle = Some(crate::client::DEFAULT_IDLE_TIMEOUT);
    let session = crate::url::dial(&url, dial.trust, dial.proxy, dial.timeout, idle)
        .await
        .map_err(ForwarderError::Connect)?
        .naming("the forwarder");
    session.set_receive_cap(RECEIVE_CAP);
    if let Some(first) = template.first_frame(host, port) {
        session
            .send_text(&first)
            .await
            .map_err(|e| ForwarderError::Answer(format!("sending the target failed: {e}")))?;
    }
    let form = template.form();
    let (carried, first) = carry::spawn(session, form, dial.close_at_end, dial.note.clone());
    let wait = if form == Form::Query { EARLY_WAIT } else { dial.timeout };
    let word = match tokio::time::timeout(wait, first).await {
        Ok(Ok(word)) => word,
        Ok(Err(_)) => First::Failed("the session ended before the forwarder said a word".into()),
        Err(_) if form == Form::Query => First::Ready,
        Err(_) => First::Failed(format!("no answer to the target within {} s", wait.as_secs())),
    };
    match word {
        First::Ready => Ok(carried),
        First::Closed { code, reason } => {
            carried.abort();
            Err(ForwarderError::Closed { code, reason })
        }
        First::Failed(why) => {
            carried.abort();
            Err(ForwarderError::Answer(why))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_of_the_frame_form_is_ok_or_says_why() {
        assert_eq!(answer(br#"{"status":"ok"}"#), Ok(()));
        let failed = answer(br#"{"status":"failed","error":"dial tcp 10.0.0.1:22: i/o timeout"}"#).unwrap_err();
        assert_eq!(failed, "it could not reach the target (failed): dial tcp 10.0.0.1:22: i/o timeout");
        assert!(answer(b"SSH-2.0-OpenSSH_9.9\r\n").unwrap_err().contains("not JSON"));
        assert!(answer(br#"{"type":"game.connected"}"#).unwrap_err().contains("no status"));
        let evil = answer(b"{\"status\":\"x\",\"error\":\"a\\u001b[2Jb\"}").unwrap_err();
        assert!(!evil.contains('\u{1b}'), "{evil:?}");
    }

    #[test]
    fn a_line_names_the_forwarder_and_its_close() {
        let shown = "wss://web-proxy.mudlet.org/";
        let closed =
            ForwarderError::Closed { code: Some(1011), reason: "Connections to port 25 are prohibited".into() };
        assert_eq!(
            closed.line(shown),
            "the forwarder wss://web-proxy.mudlet.org/ closed the WebSocket before the target's bytes: 1011 \
             Connections to port 25 are prohibited"
        );
        let refused = ForwarderError::Connect(ConnectError::Refused { status: 429, body: String::new() });
        assert_eq!(refused.line(shown), "the forwarder wss://web-proxy.mudlet.org/ refused the upgrade: HTTP 429");
        let tls = ForwarderError::Connect(ConnectError::Tls("unknown issuer".into()));
        assert!(tls.line(shown).starts_with("TLS with the forwarder wss://web-proxy.mudlet.org/ failed"));
    }
}
