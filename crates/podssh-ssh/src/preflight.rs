//! The probes of `podssh health --preflight` (T-482, GitHub #92) on a
//! connection that is logged in: what the server does with the requests that
//! a long command makes later, each asked once and within a limit of its
//! own, so that a server that never answers fails its probe, not the run
//! (GitHub #86 waited 60 s for a channel that never opened). Each probe says
//! what came, in the terms of RFC 4254; podssh-cli says what each answer
//! stops.
//!
//! The remote forward asks the server to listen on its own loopback, on a
//! port that it chooses, and cancels at once: the user asked for the probe,
//! and this host binds nothing. The jump opens a channel to the server's own
//! loopback, port 22, as no port of the far side is known, and closes it.

use std::collections::BTreeMap;
use std::time::Duration;

use russh::client::Handle;
use russh::ChannelOpenFailure;

use crate::handler::Client;
use crate::sftp::{Limits, Sftp, SftpError};
use crate::unopened::{self, Unopened};

/// The far loopback that the probes name.
pub const LOOPBACK: &str = "127.0.0.1";
/// The target of the jump's channel: the one port that a host of SSH
/// likely has.
pub const JUMP_PORT: u32 = 22;
/// The global request of OpenSSH's keepalives (`ServerAliveInterval`).
pub const KEEPALIVE: &str = "keepalive@openssh.com";

/// What came of a request that wants an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer<T> {
    /// The server answered.
    Came(T),
    /// No answer within the limit.
    Silent(Duration),
    /// The connection ended first, or the request broke: the server's
    /// words of its DISCONNECT, else the cause.
    Lost(String),
}

/// The server's answer to `tcpip-forward`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forward {
    /// It listened on `port` (0: on a port that it did not name), and the
    /// answer to the cancel: whether it stopped.
    Listened { port: u32, cancel: Answer<bool> },
    /// It refused the request.
    Refused,
}

/// The server's answer to the open of a `direct-tcpip` channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Jump {
    /// The channel opened; it is closed again at once.
    Opened,
    /// It refused, with the reason of RFC 4254, section 5.1.
    Refused(ChannelOpenFailure),
}

/// What the server's SFTP subsystem said of itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SftpFacts {
    /// Each extension that its version reply named, with its version.
    pub extensions: BTreeMap<String, String>,
    /// The size of each read and of each write that `cp` asks for.
    pub read_len: u32,
    pub write_len: u32,
}

/// The words of a request that did not come back: the connection's end,
/// told from another error of russh.
async fn lost(e: &russh::Error, handle: &Handle<Client>) -> String {
    match unopened::read(e, handle).await {
        Unopened::Ended(Some(cause)) => format!("the connection ended: {cause}"),
        Unopened::Ended(None) => "the connection ended".to_string(),
        Unopened::Refused(reason) => reason,
        Unopened::Other(why) => why,
    }
}

/// `tcpip-forward` for the far loopback, port 0, then its cancel at once,
/// each within `limit`. A request that has no answer within the limit may
/// still be granted later: the server then listens until the connection
/// ends, which the caller ends after its probes.
pub async fn remote_forward(handle: &Handle<Client>, limit: Duration) -> Answer<Forward> {
    let port = match tokio::time::timeout(limit, handle.tcpip_forward(LOOPBACK, 0)).await {
        Err(_) => return Answer::Silent(limit),
        Ok(Ok(port)) => port,
        Ok(Err(russh::Error::RequestDenied)) => return Answer::Came(Forward::Refused),
        Ok(Err(e)) => return Answer::Lost(lost(&e, handle).await),
    };
    let cancel = match tokio::time::timeout(limit, handle.cancel_tcpip_forward(LOOPBACK, port)).await {
        Err(_) => Answer::Silent(limit),
        Ok(Ok(())) => Answer::Came(true),
        Ok(Err(russh::Error::RequestDenied)) => Answer::Came(false),
        Ok(Err(e)) => Answer::Lost(lost(&e, handle).await),
    };
    Answer::Came(Forward::Listened { port, cancel })
}

/// A `direct-tcpip` channel to the far loopback, [`JUMP_PORT`], within
/// `limit`, as `-J`, `-L`, `-D` and `-W` open one.
pub async fn jump(handle: &Handle<Client>, limit: Duration) -> Answer<Jump> {
    let open = handle.channel_open_direct_tcpip(LOOPBACK, JUMP_PORT, LOOPBACK, 0);
    match tokio::time::timeout(limit, open).await {
        Err(_) => Answer::Silent(limit),
        Ok(Ok(channel)) => {
            // The probe carries no byte: the far sshd sees a connection close.
            let _ = tokio::time::timeout(limit, channel.close()).await;
            Answer::Came(Jump::Opened)
        }
        Ok(Err(russh::Error::ChannelOpenFailure(reason))) => Answer::Came(Jump::Refused(reason)),
        Ok(Err(e)) => Answer::Lost(lost(&e, handle).await),
    }
}

/// One [`KEEPALIVE`] with a reply wanted, within `limit`: whether the
/// server's reply was a success. A reply that russh cannot read ends the
/// connection, as one ended each idle session of GitHub #83.
pub async fn keepalive(handle: &Handle<Client>, limit: Duration) -> Answer<bool> {
    match tokio::time::timeout(limit, handle.send_global_request(KEEPALIVE, &[], true)).await {
        Err(_) => Answer::Silent(limit),
        Ok(Ok(_)) => Answer::Came(true),
        Ok(Err(russh::Error::RequestDenied)) => Answer::Came(false),
        Ok(Err(e)) => Answer::Lost(lost(&e, handle).await),
    }
}

/// The `sftp` subsystem, its version exchange and its limits, within
/// `limit` in all; the session is ended again at once.
pub async fn sftp(handle: &Handle<Client>, limit: Duration) -> Result<SftpFacts, SftpError> {
    let limits = Limits { metadata: limit, data: limit };
    let opened = match tokio::time::timeout(limit, Sftp::open(handle, limits)).await {
        Err(_) => return Err(SftpError::Timeout { what: "the SFTP subsystem and its version".into(), limit }),
        Ok(opened) => opened?,
    };
    let facts = SftpFacts {
        extensions: opened.extensions().clone(),
        read_len: opened.read_len(),
        write_len: opened.write_len(),
    };
    let _ = opened.close_session();
    Ok(facts)
}
