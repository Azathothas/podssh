//! `-A` (T-036): the destination's server may use the local agent while the
//! session lasts. podssh asks for it on the session channel, and joins each
//! agent channel that the server then opens to a new connection to the
//! agent, as OpenSSH does. Off by default, and never for a jump hop: the
//! handler of every other connection refuses such a channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::client::{ChannelOpenHandle, Msg};
use russh::{Channel, ChannelMsg, ChannelOpenFailure};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::log::Log;
use crate::options::Agent;

/// How long a connection to the local agent may take: a named pipe whose
/// instances are all busy must not keep the server's channel unanswered.
const CONNECT_LIMIT: Duration = Duration::from_secs(10);

/// How long one side may still talk once the other has ended: an answer of
/// the agent on its way still reaches the server, and a named pipe, which
/// has no half-close, is closed after it.
const GRACE: Duration = Duration::from_secs(5);

/// The agent that one connection lets its server use: `Agent::Off` for each
/// jump hop, and for the destination without `-A`.
#[derive(Debug, Clone)]
pub struct Forward {
    agent: Agent,
    /// Whether a failure to reach the agent was said already: a program on
    /// the server may ask for the agent again and again.
    said: Arc<AtomicBool>,
}

impl Forward {
    pub fn new(agent: Agent) -> Self {
        Forward { agent, said: Arc::new(AtomicBool::new(false)) }
    }

    pub fn is_on(&self) -> bool {
        self.agent != Agent::Off
    }
}

/// Ask the server on `channel` for agent forwarding, before the shell or
/// the command: a refusal is said, and the session goes on without it.
pub async fn request(channel: &mut Channel<Msg>, early: &mut Vec<ChannelMsg>, log: &Log) -> Result<(), String> {
    log.verbose("requesting agent forwarding (auth-agent-req@openssh.com)");
    channel.agent_forward(true).await.map_err(|e| format!("could not request agent forwarding: {e}"))?;
    if !crate::session::wait_reply(channel, early).await? {
        log.info("the server refused agent forwarding; the session goes on without it");
    }
    Ok(())
}

/// Join an agent channel that the server opened to the local agent, in a
/// task of its own: accepted once the agent answers, refused when it cannot
/// be reached. The handler must not wait here, or the whole session would.
pub fn join(forward: Forward, channel: Channel<Msg>, reply: ChannelOpenHandle, log: Arc<Log>) {
    tokio::spawn(async move {
        let agent = match tokio::time::timeout(CONNECT_LIMIT, crate::keys::connect_agent(&forward.agent)).await {
            Ok(Ok(Some(agent))) => agent.into_inner(),
            failed => {
                let why = match failed {
                    Ok(Ok(_)) => "no agent runs here (SSH_AUTH_SOCK is not set)".to_string(),
                    Ok(Err(e)) => format!("the agent cannot be reached: {e}"),
                    Err(_) => format!("the agent did not answer within {} s", CONNECT_LIMIT.as_secs()),
                };
                let line = format!("agent forwarding: the server asked for the agent, but {why}; refused");
                if forward.said.swap(true, Ordering::SeqCst) {
                    log.verbose(&line);
                } else {
                    log.info(&line);
                }
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return;
            }
        };
        reply.accept().await;
        log.verbose("agent forwarding: the server uses the agent");
        splice(channel.into_stream(), agent, GRACE).await;
    });
}

/// Copy both ways between `a` and `b`. Once one side ends, the other gets an
/// end of its own, then `grace` to finish; then both are closed, so a
/// connection never outlives its channel.
pub(crate) async fn splice<A, B>(a: A, b: B, grace: Duration)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    let forth = async {
        let _ = tokio::io::copy(&mut a_read, &mut b_write).await;
        let _ = b_write.shutdown().await;
    };
    let back = async {
        let _ = tokio::io::copy(&mut b_read, &mut a_write).await;
        let _ = a_write.shutdown().await;
    };
    tokio::pin!(forth, back);
    tokio::select! {
        () = &mut forth => { let _ = tokio::time::timeout(grace, back).await; }
        () = &mut back => { let _ = tokio::time::timeout(grace, forth).await; }
    }
}

#[cfg(test)]
#[path = "agent_forward_tests.rs"]
mod tests;
