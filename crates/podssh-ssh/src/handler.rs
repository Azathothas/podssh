//! The russh client handler: where the host key is checked and the server's
//! banner shown. Everything else russh handles itself.

use std::sync::{Arc, Mutex};

use russh::client::{DisconnectReason, Handler, Session};
use russh::keys::PublicKeyOrCertificate;

use crate::hostkey::{Policy, Verdict};
use crate::log::Log;

pub struct Client {
    policy: Arc<Policy>,
    log: Arc<Log>,
    /// Why the host key was refused, for the error message: russh itself only
    /// reports "unknown server key".
    refusal: Arc<Mutex<Option<String>>>,
    /// The server's SSH_MSG_DISCONNECT, made safe for a terminal: russh keeps
    /// no reason, and the server's words name the cause of a drop.
    disconnect: Arc<Mutex<Option<String>>>,
}

impl Client {
    pub fn new(policy: Policy, log: Arc<Log>) -> Self {
        Client {
            policy: Arc::new(policy),
            log,
            refusal: Arc::new(Mutex::new(None)),
            disconnect: Arc::new(Mutex::new(None)),
        }
    }

    /// A handle on the server's disconnect, to read after a drop.
    pub fn disconnect(&self) -> Arc<Mutex<Option<String>>> {
        self.disconnect.clone()
    }

    /// A handle on the refusal message, to read after the handshake fails.
    pub fn refusal(&self) -> Arc<Mutex<Option<String>>> {
        self.refusal.clone()
    }
}

impl Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        // A host certificate is checked as its plain key: podssh does not
        // trust certificate authorities (yet), and OpenSSH falls back the same
        // way when no `@cert-authority` line matches.
        let key = key.public_key();
        let policy = self.policy.clone();
        let log = self.log.clone();
        // The check may wait for the user; keep it off the runtime's thread so
        // the relay's keepalive frames are still read meanwhile.
        let verdict = tokio::task::spawn_blocking(move || policy.check(&key, &log))
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
                *self.disconnect.lock().unwrap_or_else(|e| e.into_inner()) = Some(said);
                Ok(())
            }
            DisconnectReason::Error(e) => Err(e),
        }
    }
}
