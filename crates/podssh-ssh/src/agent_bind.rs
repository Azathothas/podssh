//! `session-bind@openssh.com` (T-279): before a server may use the agent
//! through a channel of `-A`, podssh tells the agent which server that is,
//! as OpenSSH's client does: the server's host key, the session identifier
//! and the server's signature of it, from the first key exchange, and that
//! the agent is forwarded there. An OpenSSH agent checks the signature, then
//! hides and refuses each key that `ssh-add -h` keeps from that server; a
//! connection with no bind it takes as local use, where each key serves.

use std::time::Duration;

use russh::client::SessionBinding;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SSH_AGENTC_EXTENSION, and the name of the bind (OpenSSH's
/// PROTOCOL.agent).
const EXTENSION: u8 = 27;
const NAME: &str = "session-bind@openssh.com";

/// SSH_AGENT_SUCCESS (draft-miller-ssh-agent).
const SUCCESS: u8 = 6;

/// The longest answer read: OpenSSH's agent and client take no message over
/// 256 KiB, and an answer to a bind is a few bytes.
const MAX_ANSWER: usize = 256 * 1024;

/// What came of a bind.
#[derive(Debug, PartialEq, Eq)]
pub enum Bound {
    /// The agent took it (SSH_AGENT_SUCCESS).
    Yes,
    /// The agent answered with another message: an agent that knows no
    /// extension, or one whose check of the signature failed. Its answer is
    /// read whole, and the connection goes on, as OpenSSH's goes on.
    Refused(u8),
    /// No answer that could be read within the limit: the connection may
    /// still bring one, which must never reach the server.
    Lost(String),
}

/// The bind, framed as the agent reads it: its length, SSH_AGENTC_EXTENSION,
/// the extension's name, the host key, the session identifier, the signature,
/// and `is_forwarding`, true: the server uses the agent through this
/// connection, and podssh does not log in with it here.
pub fn request(binding: &SessionBinding) -> Vec<u8> {
    let mut body = vec![EXTENSION];
    let fields: [&[u8]; 4] = [NAME.as_bytes(), &binding.host_key, &binding.session_id, &binding.signature];
    for field in fields {
        body.extend_from_slice(&(field.len() as u32).to_be_bytes());
        body.extend_from_slice(field);
    }
    body.push(1);
    let mut framed = (body.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&body);
    framed
}

/// Send the bind on `agent`, before any byte of the server, and read its
/// answer within `limit`.
pub async fn bind_agent<S>(agent: &mut S, binding: &SessionBinding, limit: Duration) -> Bound
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(limit, exchange(agent, binding)).await {
        Ok(Ok(SUCCESS)) => Bound::Yes,
        Ok(Ok(other)) => Bound::Refused(other),
        Ok(Err(e)) => Bound::Lost(format!("the agent's connection failed at the bind: {e}")),
        Err(_) => Bound::Lost(format!("the agent did not answer the bind within {} s", limit.as_secs())),
    }
}

/// The bind out, and the type of the answer. The whole answer is read, so
/// that nothing of it reaches the server.
async fn exchange<S>(agent: &mut S, binding: &SessionBinding) -> std::io::Result<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    agent.write_all(&request(binding)).await?;
    agent.flush().await?;
    let mut len = [0u8; 4];
    agent.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_ANSWER {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("an answer of {len} bytes")));
    }
    let mut answer = vec![0u8; len];
    agent.read_exact(&mut answer).await?;
    Ok(answer[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> SessionBinding {
        SessionBinding { host_key: b"KEY".to_vec(), session_id: b"SID!".to_vec(), signature: b"SIGNED".to_vec() }
    }

    /// The bytes of OpenSSH's `ssh_agent_bind_hostkey`, framed: each field
    /// a string, and `is_forwarding` one byte.
    #[test]
    fn agent_channel_bind_is_framed_as_openssh_frames_it() {
        let mut want = vec![EXTENSION];
        want.extend_from_slice(&[0, 0, 0, 24]);
        want.extend_from_slice(b"session-bind@openssh.com");
        want.extend_from_slice(&[0, 0, 0, 3]);
        want.extend_from_slice(b"KEY");
        want.extend_from_slice(&[0, 0, 0, 4]);
        want.extend_from_slice(b"SID!");
        want.extend_from_slice(&[0, 0, 0, 6]);
        want.extend_from_slice(b"SIGNED");
        want.push(1);
        let mut framed = (want.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&want);
        assert_eq!(request(&binding()), framed);
    }

    /// The answer is read whole: a success binds, a failure is a refusal and
    /// leaves nothing unread, and an agent that hangs up or says nothing
    /// loses the connection.
    #[tokio::test]
    async fn agent_channel_bind_reads_the_whole_answer() {
        let limit = Duration::from_secs(5);
        let binding = binding();
        let took: &[u8] = &[0, 0, 0, 1, SUCCESS];
        let refused: &[u8] = &[0, 0, 0, 2, 5, 9];
        for (answer, want) in [(took, Bound::Yes), (refused, Bound::Refused(5))] {
            let (mut ours, mut agent) = tokio::io::duplex(1024);
            let sent = request(&binding);
            let agent_side = async {
                let mut got = vec![0u8; sent.len()];
                agent.read_exact(&mut got).await.expect("the bind");
                agent.write_all(answer).await.expect("the answer");
                agent.write_all(b"next").await.expect("what follows");
                got
            };
            let (bound, got) = tokio::join!(bind_agent(&mut ours, &binding, limit), agent_side);
            assert_eq!(got, sent);
            assert_eq!(bound, want);
            let mut next = [0u8; 4];
            ours.read_exact(&mut next).await.expect("the bytes after the answer");
            assert_eq!(&next, b"next", "the answer was not read whole");
        }
        let (mut ours, agent) = tokio::io::duplex(1024);
        drop(agent);
        assert!(matches!(bind_agent(&mut ours, &binding, limit).await, Bound::Lost(_)));
        let (mut ours, _agent) = tokio::io::duplex(1024);
        let bound = bind_agent(&mut ours, &binding, Duration::from_millis(100)).await;
        assert!(matches!(&bound, Bound::Lost(why) if why.contains("did not answer")), "{bound:?}");
    }
}
