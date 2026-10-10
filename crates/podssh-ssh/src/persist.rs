//! One connection of `podssh ssh --persist` (T-178): the login, a probe for
//! tmux, then the session `tmux new-session -A -s NAME` with a pty, and how
//! it ended, so that the caller connects again after a lost link, and only
//! then. tmux keeps the shell on the server while no client is attached.

use std::sync::Arc;
use std::time::Duration;

use russh::client::Handle;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::exec::{self, ExecError};
use crate::handler::Client;
use crate::io::{End, Input};
use crate::log::Log;
use crate::options::Options;
use crate::relay_stream::{RelayEnd, RelayStatus};
use crate::run::{connect_hops, disconnect_all, display, failure_lines, HopError, EXIT_FAILURE};
use crate::session;

/// How long a probe for tmux may take.
const PROBE_WAIT: Duration = Duration::from_secs(30);
/// What a probe may print that podssh reads.
const PROBE_CAP: usize = 4096;

/// How one connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// The session ended as the server or the user chose: the exit code.
    Ended(i32),
    /// The link was lost, and a new connection may attach the session
    /// again. `attached`: the session ran before the loss.
    Lost { attached: bool, why: String },
    /// A failure that a new connection would repeat; its lines are logged.
    Failed,
}

/// The session's command: attach NAME, or start it when it is not there.
pub fn command(name: &str) -> String {
    format!("tmux new-session -A -s {name}")
}

/// Whether a session that ended with no status lost its link, which a new
/// connection may repair: with no relay (`--direct`), a relay link that
/// failed (the ping watcher), or the relay's close for going away (1001),
/// no Close (1006), its limits (1009) or its link to the server (1011).
/// The server's own close (1000) and the other codes would come again.
pub fn link_lost(relay: Option<&RelayEnd>) -> bool {
    match relay {
        None | Some(RelayEnd::Failed(_)) => true,
        Some(RelayEnd::Closed { code, .. }) => matches!(code, None | Some(1001 | 1006 | 1009 | 1011)),
    }
}

/// One connection over `stream`: log in, look for tmux (`first`) or for the
/// session NAME (after a loss), then attach it with `input`.
pub async fn attempt<S>(
    stream: S,
    opts: &Options,
    relay: Option<&RelayStatus>,
    name: &str,
    first: bool,
    input: &mut Input,
    log: &Arc<Log>,
) -> Attempt
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handles = match connect_hops(stream, opts, log).await {
        Ok(handles) => handles,
        Err(HopError::Unreachable(why)) => return Attempt::Lost { attached: false, why },
        Err(refused) => {
            log.error(&refused.to_string());
            return Attempt::Failed;
        }
    };
    let handle = handles.last().expect("the destination");
    let attempt = attach(handle, opts, relay, name, first, input, log).await;
    disconnect_all(&handles).await;
    attempt
}

async fn attach(
    handle: &Handle<Client>,
    opts: &Options,
    relay: Option<&RelayStatus>,
    name: &str,
    first: bool,
    input: &mut Input,
    log: &Arc<Log>,
) -> Attempt {
    if let Err(attempt) = probe(handle, name, first, log).await {
        return attempt;
    }
    if !first {
        log.info(&format!("attaching the tmux session {name} again"));
    }
    let host = display(&opts.destination);
    match session::attach(handle, opts, &host, log, input).await {
        Ok(End::Lost) => {
            let end = relay.and_then(RelayStatus::get);
            let lost = format!("the connection to {host} was lost");
            if link_lost(end.as_ref()) {
                let why = end.as_ref().and_then(RelayEnd::explain).unwrap_or(lost);
                return Attempt::Lost { attached: true, why };
            }
            let hop = opts.jump.first().unwrap_or(&opts.destination);
            let target = podssh_ws::dial::authority(&hop.host, hop.port);
            for line in failure_lines(&lost, end.as_ref(), &target) {
                log.error(&line);
            }
            Attempt::Failed
        }
        Ok(end) => Attempt::Ended(session::code(end, &host).unwrap_or(EXIT_FAILURE)),
        // A link that broke while the session was asked for.
        Err(why) if handle.is_closed() => Attempt::Lost { attached: false, why },
        Err(why) => {
            log.error(&why);
            Attempt::Failed
        }
    }
}

/// Before the attach: tmux on PATH (`first`), or after a loss the session
/// NAME, which must not come back as a new shell that looks like the old.
async fn probe(handle: &Handle<Client>, name: &str, first: bool, log: &Log) -> Result<(), Attempt> {
    let (command, missing) = if first {
        ("command -v tmux".to_string(), "the server has no tmux on PATH; --persist needs it".to_string())
    } else {
        (
            format!("tmux has-session -t ={name}"),
            format!("the tmux session {name} is gone from the server; podssh starts no new one after a lost link"),
        )
    };
    match exec::capture(handle, &command, PROBE_WAIT, PROBE_CAP).await {
        Ok(found) if found.status == Some(0) => Ok(()),
        Ok(_) => {
            log.error(&missing);
            Err(Attempt::Failed)
        }
        Err(ExecError::Lost(why)) => Err(Attempt::Lost { attached: false, why }),
        Err(e) => {
            log.error(&format!("{command}: {e}"));
            Err(Attempt::Failed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed(code: u16) -> RelayEnd {
        RelayEnd::Closed { code: Some(code), reason: String::new() }
    }

    #[test]
    fn a_lost_link_is_one_that_a_new_connection_may_repair() {
        assert!(link_lost(None), "--direct");
        let watcher = RelayEnd::Failed(podssh_ws::SessionError::Idle("the relay sent nothing for 40 s".into()));
        assert!(link_lost(Some(&watcher)));
        assert!(link_lost(Some(&RelayEnd::Closed { code: None, reason: String::new() })));
        for code in [1001, 1006, 1009, 1011] {
            assert!(link_lost(Some(&closed(code))), "{code}");
        }
        for code in [1000, 1008, 1013] {
            assert!(!link_lost(Some(&closed(code))), "{code}");
        }
    }

    #[test]
    fn the_session_attaches_the_name_or_starts_it() {
        assert_eq!(command("podssh"), "tmux new-session -A -s podssh");
    }
}
