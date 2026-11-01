//! An RPC stream of the edge over QUIC (T-411), sans-IO. The edge opens a
//! stream, writes the six bytes of an RPC stream and no version, and speaks
//! Cap'n Proto's RPC on it as a client: it asks for the bootstrap capability,
//! cloudflared's `CloudflaredServer`, and calls one of its methods
//! (cloudflared 2026.10.6: `tunnelrpc/quic/cloudflared_client.go` and
//! `cloudflared_server.go`). So the edge pushes a configuration,
//! `ConfigurationManager.updateConfiguration`, and asks for the UDP sessions
//! of private networks, `SessionManager`'s two methods.
//!
//! podssh exports that one capability: a push gets the answer of a push that
//! cloudflared took, as over HTTP/2 (`configuration`), and nothing of it is
//! kept; each other call gets an exception, as podssh carries no UDP here.

use std::time::Duration;

use super::capnp::{self, Malformed, Message};
use super::configuration;
use super::control::Failure;
use super::rpc::{self, Call, Incoming, Target};

/// The id under which podssh exports its one capability.
pub const EXPORT: u32 = 0;
/// How long an RPC stream is served: cloudflared's own bound, its
/// `--rpc-timeout`.
pub const RPC_WAIT: Duration = Duration::from_secs(5);
/// The most bytes of the edge's that wait to be read: a push's, as over
/// HTTP/2, and room for the RPC's own.
const MAX_INBOX: usize = configuration::MAX_PUSH + 64 * 1024;
/// The most words read of one message: as many as such bytes hold.
const BUDGET: u64 = (MAX_INBOX / 8) as u64;
/// The most bootstraps of the edge whose answers a call may be on.
const MAX_BOOTSTRAPS: usize = 16;

/// One RPC stream of the edge, served.
#[derive(Default)]
pub struct RpcStream {
    inbox: Vec<u8>,
    /// The edge's questions that asked for the bootstrap, until it finishes
    /// them: a call on the promise of one is on the capability.
    bootstraps: Vec<u32>,
}

impl RpcStream {
    /// Bytes from the edge: the bytes to send back, the answers to each
    /// whole frame among them. A frame may come in pieces.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Failure> {
        if self.inbox.len() + bytes.len() > MAX_INBOX {
            return Err(Failure::Malformed(Malformed("a message larger than a push")));
        }
        self.inbox.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(len) = capnp::frame_len(&self.inbox)? {
            if self.inbox.len() < len {
                break;
            }
            let frame: Vec<u8> = self.inbox.drain(..len).collect();
            let message = Message::read_within(&frame, BUDGET)?;
            match rpc::read(&message)? {
                Incoming::Bootstrap(question) => {
                    if self.bootstraps.len() < MAX_BOOTSTRAPS && !self.bootstraps.contains(&question) {
                        self.bootstraps.push(question);
                    }
                    out.extend(rpc::capability(question, EXPORT));
                }
                Incoming::Call(call) => out.extend(self.answer(&call)),
                Incoming::Finish(question) => self.bootstraps.retain(|&q| q != question),
                Incoming::Abort(why) => return Err(Failure::Aborted(why)),
                // An answer to no question of this end's, a release of the
                // capability, or another kind: nothing to answer.
                Incoming::Return { .. } | Incoming::Other(_) => {}
            }
        }
        Ok(out)
    }

    /// The answer to `call`: a push's results, or an exception.
    fn answer(&self, call: &Call<'_>) -> Vec<u8> {
        let ours = match call.target {
            Target::Imported(id) => id == EXPORT,
            Target::Promised(question) => self.bootstraps.contains(&question),
            Target::Other => false,
        };
        if !ours {
            return rpc::unimplemented(call.question, "podssh exports one capability, at the bootstrap");
        }
        let push = (configuration::CONFIGURATION_MANAGER, configuration::UPDATE_CONFIGURATION);
        if (call.interface, call.method) != push {
            return rpc::unimplemented(call.question, "podssh serves a push of configuration here, and no UDP");
        }
        let params = call.params;
        rpc::results(call.question, configuration::RESULTS, |b, at| configuration::results(params, b, at))
    }
}

#[cfg(test)]
#[path = "rpc_stream_tests.rs"]
mod tests;
