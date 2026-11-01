//! `podssh proxy --forwarder TEMPLATES` (T-369): the pipe of stdin and
//! stdout to the target through the first forwarder that carries it, as
//! OpenSSH's `ProxyCommand`. The end of stdin sends no Close, as on the
//! relay's road: a Close is no half-close, and data may not follow it, so
//! the target's bytes come until it closes.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;

use podssh_ws::forwarder::{Carried, Dial, Status};
use podssh_ws::{ProxyChoice, Trust};

use super::Forwarder;
use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::exitmap::sysexits::{EX_UNAVAILABLE, EX_USAGE};
use crate::pipe::pump::{End, Ending, Verdict};
use crate::proxy::ProxyArgs;
use crate::relay_settings::Refusal;

/// The schemes of a destination whose road is its own.
const OWN_ROADS: &[&str] = &["cf://", "iap://", "eice://"];

/// `--forwarder` beside a destination whose road is its own: a usage error.
pub fn beside(args: &ProxyArgs) -> Result<(), Refusal> {
    let own = args.target.as_deref().is_some_and(|t| OWN_ROADS.iter().any(|s| t.starts_with(s)));
    if args.forwarder.is_some() && own {
        return Err(Refusal::usage(
            "--forwarder cannot go with cf://, iap:// or eice://, which is a road of its own; a run has one road",
        ));
    }
    Ok(())
}

/// The forwarders of `podssh proxy`, chosen as `podssh ssh` chooses them;
/// none when the relay is the road, whose fallback's word is then checked
/// (T-370).
pub fn chosen(args: &ProxyArgs) -> Result<Option<Vec<Forwarder>>, Refusal> {
    let named = super::other_road(args.relay_host.is_some(), args.relay_failover.is_some(), args.shadowsocks.is_some());
    let relay_env = std::env::var(podssh_relay::relay::RELAY_ENV).ok().is_some_and(|v| !v.trim().is_empty());
    let file = crate::settings::here();
    let chosen = super::choose(args.forwarder.as_deref(), named, super::env_value(), relay_env, file)?;
    if chosen.is_none() {
        super::fallback::on_from(super::fallback::env_value(), file)?;
    }
    Ok(chosen)
}

/// The pipe to `host:port` through `forwarders`: its exit code.
pub fn run(forwarders: &[Forwarder], host: &str, port: u16, ca_file: Option<&str>, err: &mut dyn Write) -> i32 {
    crate::session_log::target(host, Some(port), "forwarder");
    let trust = crate::settings::ca_file(ca_file).map_or(Trust::Default, |file| Trust::File(file.into()));
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh proxy: could not start the async runtime: {e}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    let code = runtime.block_on(session(forwarders, host, port, &trust, err));
    // A read on stdin may still be blocked in a helper thread.
    runtime.shutdown_background();
    code
}

async fn session(forwarders: &[Forwarder], host: &str, port: u16, trust: &Trust, err: &mut dyn Write) -> i32 {
    let opened = open(forwarders, host, port, trust, &mut |line: &str| {
        let _ = writeln!(err, "podssh: {line}");
    })
    .await;
    match opened {
        Ok((end, _)) => carry(end, err).await,
        Err(code) => code,
    }
}

/// The pump of stdin and stdout with `end`, and its report.
pub async fn carry(end: End, err: &mut dyn Write) -> i32 {
    crate::session_log::opened(None);
    let pumped = crate::pipe::pump::pump(crate::pipe::local::stdio(), end).await;
    crate::session_log::carried(pumped.carried.0, pumped.carried.1);
    crate::pipe::report(pumped, "podssh", err).await
}

/// The pipe's end at the first of `forwarders` that carries `host:port`,
/// with that forwarder's name, or the exit code once `say` has the line of
/// each failure.
pub async fn open(
    forwarders: &[Forwarder],
    host: &str,
    port: u16,
    trust: &Trust,
    say: &mut dyn FnMut(&str),
) -> Result<(End, String), i32> {
    if podssh_relay::open::offline() {
        say(&format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV));
        return Err(EX_UNAVAILABLE);
    }
    let mut code = EX_UNAVAILABLE;
    for forwarder in forwarders {
        let dial = Dial {
            trust,
            proxy: &ProxyChoice::FromEnvironment,
            timeout: podssh_relay::open::CONNECT_TIMEOUT,
            close_at_end: false,
            // A pipe has no -v; a forwarder's notes are not the target's.
            note: Arc::new(|_: &str| {}),
        };
        match podssh_ws::forwarder::open(&forwarder.template, host, port, &dial).await {
            Ok(carried) => return Ok((end(carried, forwarder.name.clone()), forwarder.name.clone())),
            Err(e) => {
                say(&e.line(&forwarder.name));
                code = super::reach::exit_code(&e);
                if code == EX_USAGE {
                    break;
                }
            }
        }
    }
    Err(code)
}

/// The pipe's end of a forwarder's session: its end ends the pipe, as
/// nothing more can come.
pub fn end(carried: Carried, name: String) -> End {
    let status = carried.status.clone();
    let (read, write) = tokio::io::split(carried.stream);
    let ending = Finished { status, name };
    End { read: Box::new(read), write: Box::new(write), child: None, last_word: true, ending: Some(Box::new(ending)) }
}

struct Finished {
    status: Status,
    name: String,
}

impl Ending for Finished {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        Box::pin(async move {
            let line = self.status.get().and_then(|end| super::reach::ended(&self.name, &end))?;
            Some((EX_UNAVAILABLE, vec![line]))
        })
    }
}
