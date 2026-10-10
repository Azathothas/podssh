//! The SSH server's end of a pipe (T-175):
//! `ssh:[USER@]HOP[,HOP...],HOST:PORT`, TCP to HOST:PORT that the last hop
//! opens, as `-W` asks. Each hop logs in as `podssh ssh` logs in, through
//! the relay or with `--direct`, with the flags `-i`, `-o` and the relay's;
//! each connection stays until the pipe ends. An SSH channel has a
//! half-close, so each direction ends by itself.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use podssh_ssh::run::HopError;
use podssh_ssh::{Connection, Log};

use super::pump::{End, Ending, Verdict};
use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env};

/// The keywords of a session: a pipe opens no session, so a hop's `-o`
/// with one of them would change nothing that the user meant.
const SESSION_KEYWORDS: &[&str] = &[
    "RequestTTY",
    "RemoteCommand",
    "SessionType",
    "StdinNull",
    "EscapeChar",
    "LocalCommand",
    "PermitLocalCommand",
    "ForwardX11",
    "ForwardAgent",
    "LocalForward",
    "RemoteForward",
    "DynamicForward",
    "ForkAfterAuthentication",
];

/// Refuse an `-o` that names a keyword of a session (64).
pub fn check_options(options: &[String]) -> Result<(), Refusal> {
    for option in options {
        let name = option.split(['=', ' ', '\t']).next().unwrap_or("").trim();
        if let Some(keyword) = SESSION_KEYWORDS.iter().find(|k| k.eq_ignore_ascii_case(name)) {
            return Err(Refusal::usage(format!("-o {option}: {keyword} is for a session, and ssh: opens none")));
        }
    }
    Ok(())
}

/// Log in through `hops` and open `host:port` from the last: the end, or the
/// exit code once `say` has the lines.
pub async fn open(
    hops: &[String],
    host: &str,
    port: u16,
    base: &SshArgs,
    say: &mut dyn FnMut(&str),
) -> Result<End, i32> {
    let (last, before) = hops.split_last().expect("ssh: names one hop at least");
    let mut args = base.clone();
    args.destination = Some(last.clone());
    args.jump = (!before.is_empty()).then(|| before.join(","));
    let resolved = resolve::resolve_or_refuse(&args, &Env::from_process()).map_err(|refusal| {
        say(&refusal.message);
        refusal.code
    })?;
    let log = Arc::new(Log::new(resolved.options.log_level));
    let reached = crate::ssh::transport::reach(&resolved, &log).await.map_err(|not| {
        for line in &not.lines {
            say(line);
        }
        not.code
    })?;
    let handles = podssh_ssh::run::connect_hops(reached.stream, &resolved.options, &log).await.map_err(|e| {
        say(&e.to_string());
        hop_code(&e)
    })?;
    let last_hop = handles.last().expect("the last hop's connection");
    match podssh_ssh::forward::open(last_hop, host, port).await {
        Ok(stream) => {
            let (read, write) = tokio::io::split(stream);
            Ok(End {
                read: Box::new(read),
                write: Box::new(write),
                child: None,
                last_word: false,
                ending: Some(Box::new(Hops(handles))),
            })
        }
        Err(why) => {
            podssh_ssh::run::disconnect_all(&handles).await;
            say(&why);
            Err(EX_UNAVAILABLE)
        }
    }
}

/// The sysexits code of a hop that failed: 77 for a host key or a login
/// that was refused, as `podssh proxy` gives 77 for a refusal.
fn hop_code(e: &HopError) -> i32 {
    match e {
        HopError::Unreachable(_) => EX_UNAVAILABLE,
        HopError::HostKey(_) | HopError::Auth(_) => EX_NOPERM,
    }
}

/// Each hop's connection, kept until the pipe ends, then closed.
struct Hops(Vec<Connection>);

impl Ending for Hops {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        Box::pin(async move {
            podssh_ssh::run::disconnect_all(&self.0).await;
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_keyword_of_a_session_is_refused_and_one_of_a_connection_is_not() {
        for option in ["RequestTTY=yes", "remotecommand=ls", "SessionType none", "ForwardAgent=yes"] {
            assert_eq!(check_options(&[option.to_string()]).unwrap_err().code, 64, "{option}");
        }
        let fine = ["StrictHostKeyChecking=accept-new".to_string(), "Port=2222".into(), "User=me".into()];
        assert!(check_options(&fine).is_ok());
    }
}
