//! VLESS (T-440, the operator's ruling Q66): a server that the user runs,
//! Xray-core's or another that speaks its protocol (shoes, sing-box), takes
//! the target from a short header and dials it, so that it is a road in place
//! of the relay. The stream goes over a WebSocket (`ws`), or over XHTTP's
//! plain HTTP requests on HTTP/2 (`xhttp`), which pass where a proxy or a
//! front end refuses the WebSocket upgrade. TLS is podssh's, checked for the
//! link's name, through `HTTPS_PROXY` when it is set, as each road dials.
//!
//! The link and its ID come from a private file ([`link`]); the request and
//! the answer are [`header`]'s. The server answers with the target's first
//! bytes, so a session whose server speaks first (SSH) waits for that answer,
//! and one whose client may speak first (a pipe) takes the stream after a
//! short silence, as `--shadowsocks` does.

mod extra;
mod header;
pub mod link;
mod packet;
mod split;
mod ws;
mod xhttp;

use std::time::Duration;

use crate::dial::{DialError, ProxyChoice};
use crate::tls::Trust;
use crate::via::Duplex;

pub use extra::Extra;
pub use header::{not_vless, ENDED};
pub use link::{Id, Mode, Server, Transport};

/// How long a session whose server speaks first waits for VLESS's answer,
/// which comes with the target's first bytes.
pub const ANSWER_WAIT: Duration = Duration::from_secs(10);
/// How long a pipe waits for an end before it takes the stream: a refused
/// ID ends the session at once.
pub const EARLY_WAIT: Duration = Duration::from_secs(3);

/// What a VLESS road needs beside its server and its target.
pub struct Dial<'a> {
    pub trust: &'a Trust,
    pub proxy: &'a ProxyChoice,
    /// The bound of each step: TCP, TLS, the upgrade, each HTTP answer.
    pub timeout: Duration,
    /// How long to wait for VLESS's answer.
    pub answer: Duration,
    /// Whether no answer within that wait is a stream to take (a pipe).
    pub silence_is_ready: bool,
    /// Whether the end of this side's bytes ends a WebSocket at once (an SSH
    /// session), or the session waits for the server's end (a pipe).
    pub close_at_end: bool,
}

/// Why a VLESS server carried no session.
#[derive(Debug)]
pub enum VlessError {
    /// The target cannot go in VLESS's header.
    Target(String),
    /// TCP, or the host's proxy.
    Dial(DialError),
    /// TLS, the upgrade or HTTP/2 failed: what failed.
    Carry(String),
    /// An HTTP answer refused it: the upgrade's or XHTTP's status, and what
    /// it refused.
    Refused { status: u16, why: String },
    /// HTTP/1.1, where XHTTP needs HTTP/2.
    Http1(String),
    /// The server ended the session before VLESS's answer.
    Ended,
    /// An answer of another protocol: its first byte.
    NotVless(u8),
    /// No answer within the wait.
    Silent(Duration),
}

impl VlessError {
    /// The line that says it, for the server `shown` and the target.
    pub fn line(&self, shown: &str, target: &str) -> String {
        match self {
            VlessError::Target(why) => format!("{target} cannot go to the VLESS server {shown}: {why}"),
            VlessError::Dial(e) => format!("the VLESS server {shown}: {e}"),
            VlessError::Carry(why) | VlessError::Http1(why) => format!("the VLESS server {shown}: {why}"),
            VlessError::Refused { status, why } => format!("the VLESS server {shown} refused {why}: HTTP {status}"),
            VlessError::Ended => format!("the VLESS server {shown}, for {target}: {ENDED}"),
            VlessError::NotVless(v) => format!("the VLESS server {shown}: {}", not_vless(*v)),
            VlessError::Silent(after) => format!(
                "the VLESS server {shown} gave no answer for {target} within {} s: the target said nothing, a \
                 proxy or a front end between holds the bytes, or the server holds the session with no target; \
                 Xray-core does so for a private address unless the finalRules of its freedom outbound allow it",
                after.as_secs()
            ),
        }
    }
}

impl From<header::AnswerError> for VlessError {
    fn from(e: header::AnswerError) -> VlessError {
        match e {
            header::AnswerError::Ended => VlessError::Ended,
            header::AnswerError::NotVless(v) => VlessError::NotVless(v),
            header::AnswerError::Io(e) => VlessError::Carry(format!("before VLESS's answer: {e}")),
        }
    }
}

/// A session to the target.
pub struct Opened {
    pub stream: Box<dyn Duplex>,
    /// What carried it: "a WebSocket", "XHTTP packet-up over HTTP/2".
    pub how: String,
    /// VLESS's answer came within the wait.
    pub answered: bool,
}

/// A session to `host:port` through `server`, on the link's transport.
pub async fn open(server: &Server, host: &str, port: u16, dial: &Dial<'_>) -> Result<Opened, VlessError> {
    open_as(server, server.transport, host, port, dial).await
}

/// [`open`] on `transport`, as `doctor` tries each mode of XHTTP.
pub async fn open_as(
    server: &Server,
    transport: Transport,
    host: &str,
    port: u16,
    dial: &Dial<'_>,
) -> Result<Opened, VlessError> {
    let request = header::request(&server.id, host, port).map_err(VlessError::Target)?;
    let (stream, how): (Box<dyn Duplex>, String) = match transport {
        Transport::Ws => (Box::new(ws::open(server, request, dial).await?) as Box<dyn Duplex>, transport.name()),
        Transport::Xhttp(mode) => xhttp::open(server, mode.chosen(), request, dial).await?,
    };
    let mut stream = header::Answered::new(stream);
    let answered = match tokio::time::timeout(dial.answer, stream.answer()).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) if dial.silence_is_ready => false,
        Err(_) => return Err(VlessError::Silent(dial.answer)),
    };
    Ok(Opened { stream: Box::new(stream), how, answered })
}

/// The modes that `doctor` tries for a link of XHTTP: the link's own, or
/// each where it says auto.
pub fn modes(transport: Transport) -> Vec<Transport> {
    match transport {
        Transport::Xhttp(Mode::Auto) => {
            [Mode::PacketUp, Mode::StreamUp, Mode::StreamOne].into_iter().map(Transport::Xhttp).collect()
        }
        other => vec![other],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_names_the_server_and_never_the_id() {
        let shown = "vless://v.example:443/ws";
        let ended = VlessError::Ended.line(shown, "h.example:22");
        let words = "the VLESS server vless://v.example:443/ws, for h.example:22: the server";
        assert!(ended.starts_with(words), "{ended}");
        assert!(ended.contains("refused the ID"), "{ended}");
        let refused = VlessError::Refused { status: 404, why: "the WebSocket upgrade at /ws".into() };
        assert_eq!(
            refused.line(shown, "h:22"),
            "the VLESS server vless://v.example:443/ws refused the WebSocket upgrade at /ws: HTTP 404"
        );
        assert!(VlessError::NotVless(72).line(shown, "h:22").contains("first byte is 72"));
        assert!(VlessError::Silent(ANSWER_WAIT).line(shown, "h:22").contains("within 10 s"));
        let auto = modes(Transport::Xhttp(Mode::Auto));
        assert_eq!(auto.len(), 3);
        assert_eq!(modes(Transport::Ws), vec![Transport::Ws]);
    }
}
