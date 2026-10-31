//! The russh client handler: where the host key is checked, the server's
//! banner shown, its disconnect kept, and each channel that it opens unasked
//! refused. Everything else russh handles itself.

use std::sync::{Arc, Mutex};

use russh::client::{ChannelOpenHandle, DisconnectReason, Handler, Msg, Session};
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelOpenFailure};

use crate::agent_forward::Forward;
use crate::hostkey::{Offer, Policy, Verdict};
use crate::log::Log;
use crate::options::Agent;

/// The last SSH_MSG_DISCONNECT of a server in this process, made safe: a
/// run of `-N` says it once the connection ended (T-026). A process runs
/// one chain of connections, so one is enough.
static LAST_DISCONNECT: Mutex<Option<String>> = Mutex::new(None);

/// The last server's words of a disconnect, taken.
pub fn take_last_disconnect() -> Option<String> {
    LAST_DISCONNECT.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// Why the last connection of this process failed after its handshake, in
/// words: russh gives the error to the handler alone, and a lost session
/// names it (T-227: a write that made no progress, a reset).
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// The last connection's error, taken.
pub fn take_last_error() -> Option<String> {
    LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()).take()
}

pub struct Client {
    policy: Arc<Policy>,
    log: Arc<Log>,
    /// Why the host key was refused, for the error message: russh itself only
    /// reports "unknown server key".
    refusal: Arc<Mutex<Option<String>>>,
    /// The server's SSH_MSG_DISCONNECT, made safe for a terminal: russh keeps
    /// no reason, and the server's words name the cause of a drop.
    disconnect: Arc<Mutex<Option<String>>>,
    /// The forwards of `-R` that the server took: a `forwarded-tcpip`
    /// channel is accepted for these only.
    forwards: crate::remote::Table,
    /// The agent that this server may use (`-A`): an agent channel is
    /// accepted only when it is on, which it is for the destination alone.
    agent: Forward,
    /// The display that this server may use (`-X`, `-Y`): an `x11` channel
    /// is accepted only then, for the destination alone (T-037).
    x11: Option<crate::x11::Forward>,
}

impl Client {
    pub fn new(policy: Policy, log: Arc<Log>) -> Self {
        Client {
            policy: Arc::new(policy),
            log,
            refusal: Arc::new(Mutex::new(None)),
            disconnect: Arc::new(Mutex::new(None)),
            forwards: Arc::new(Mutex::new(Vec::new())),
            agent: Forward::new(Agent::Off),
            x11: None,
        }
    }

    /// Let this server use `agent` (T-036): the destination's, with `-A`.
    pub fn forwarding_agent(mut self, agent: Agent) -> Self {
        self.agent = Forward::new(agent);
        self
    }

    /// The agent's forward, whose clones share the binding that the
    /// handshake's end gives (T-279).
    pub fn agent_forward(&self) -> Forward {
        self.agent.clone()
    }

    /// Let this server open X11 channels to `x11` (T-037): the destination's,
    /// with `-X` or `-Y`.
    pub fn forwarding_x11(mut self, x11: Option<crate::x11::Forward>) -> Self {
        self.x11 = x11;
        self
    }

    /// A handle on the forwards that the server took, to fill after the login.
    pub fn forwards(&self) -> crate::remote::Table {
        self.forwards.clone()
    }

    /// A handle on the server's disconnect, to read after a drop.
    pub fn disconnect(&self) -> Arc<Mutex<Option<String>>> {
        self.disconnect.clone()
    }

    /// A handle on the refusal message, to read after the handshake fails.
    pub fn refusal(&self) -> Arc<Mutex<Option<String>>> {
        self.refusal.clone()
    }

    /// The one place that refuses a channel that the server opens and podssh
    /// did not ask for, as OpenSSH refuses it; russh would accept it, and read
    /// and drop its data with no end. -R, -A and -X (T-035, T-036, T-037)
    /// accept their own channels before this, only for their own requests.
    /// Each reads an accepted channel at once or closes it: a channel kept
    /// unread stops the whole session.
    async fn unasked(&self, kind: &str, reply: ChannelOpenHandle) {
        match kind {
            "auth-agent@openssh.com" => {
                self.log.info("Warning: the server tried agent forwarding, which podssh did not ask for; refused.")
            }
            "x11" => self.log.info("Warning: the server tried X11 forwarding, which podssh did not ask for; refused."),
            _ => self.log.verbose(&format!("refused a {kind} channel that the server opened unasked")),
        }
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
    }
}

impl Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        // A host certificate is checked against the `@cert-authority` lines,
        // and as its plain key when no line names its CA, as OpenSSH falls
        // back (T-027).
        let offer = match key {
            PublicKeyOrCertificate::Certificate(cert) => Offer::Certificate(Box::new(cert.clone())),
            plain => Offer::Key(plain.public_key()),
        };
        let policy = self.policy.clone();
        let log = self.log.clone();
        // The check may wait for the user; keep it off the runtime's thread so
        // the relay's keepalive frames are still read meanwhile.
        let verdict = tokio::task::spawn_blocking(move || policy.check_offer(&offer, &log))
            .await
            .unwrap_or_else(|e| Verdict::Reject(format!("the host key check failed: {e}")));
        match verdict {
            Verdict::Accept => Ok(true),
            Verdict::Reject(message) => {
                *self.refusal.lock().unwrap_or_else(|e| e.into_inner()) = Some(message);
                Ok(false)
            }
        }
    }

    async fn auth_banner(&mut self, banner: &str, _session: &mut Session) -> Result<(), Self::Error> {
        self.log.banner(&podssh_ws::text::multi_line(banner));
        Ok(())
    }

    async fn disconnected(&mut self, reason: DisconnectReason<Self::Error>) -> Result<(), Self::Error> {
        match reason {
            DisconnectReason::ReceivedDisconnect(info) => {
                let text = podssh_ws::text::one_line(&info.message);
                let said = if text.is_empty() {
                    format!("{:?}", info.reason_code)
                } else {
                    format!("{text} ({:?})", info.reason_code)
                };
                *LAST_DISCONNECT.lock().unwrap_or_else(|e| e.into_inner()) = Some(said.clone());
                *self.disconnect.lock().unwrap_or_else(|e| e.into_inner()) = Some(said);
                Ok(())
            }
            DisconnectReason::Error(e) => {
                *LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = Some(crate::run::describe(&e));
                Err(e)
            }
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match crate::remote::find(&self.forwards, connected_address, connected_port) {
            // Asked for: joined at once, as a channel kept unread stops the
            // whole session.
            Some(forward) => {
                reply.accept().await;
                tokio::spawn(crate::remote::join(channel, forward, self.log.clone()));
            }
            None => self.unasked("forwarded-tcpip", reply).await,
        }
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.unasked("forwarded-streamlocal@openssh.com", reply).await;
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.agent.is_on() {
            crate::agent_forward::join(self.agent.clone(), channel, reply, self.log.clone());
        } else {
            self.unasked("auth-agent@openssh.com", reply).await;
        }
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.unasked("session", reply).await;
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.unasked("direct-tcpip", reply).await;
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.unasked("direct-streamlocal@openssh.com", reply).await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match &self.x11 {
            Some(x11) => crate::x11::join(x11.clone(), channel, reply, self.log.clone()),
            None => self.unasked("x11", reply).await,
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
