//! `podssh proxy iap://...` and `podssh proxy eice://...` (T-351): the pipe
//! of stdin and stdout to a port of a VM through its cloud's own tunnel,
//! made to be OpenSSH's `ProxyCommand`:
//!
//! ```text
//! ssh -o ProxyCommand='podssh proxy iap://my-project/us-central1-a/%h:%p' user@my-vm
//! ```
//!
//! The port is in the destination, and the relay's flags do not apply. On
//! IAP the end of stdin ends the session after its bytes, as gcloud ends
//! it, as IAP carries no half-close; on EICE receiving goes on, as on the
//! relay. The end of the road is said in the cloud's own words.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::iap::carry::{self, Carried, Ended, Line, Say};
use podssh_ws::Trust;
use tokio::io::DuplexStream;

use super::google::Tokens;
use super::{eice, iap, Road, DURATION_ENV};
use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::pipe::pump::{End, Ending, Verdict};
use crate::proxy::ProxyArgs;

/// How long the end of a pipe waits for IAP's task to say how it ended.
const SAID_WAIT: Duration = Duration::from_secs(5);

/// Run `podssh proxy` when its target is a road of a cloud's tunnel; `None`
/// for another target.
pub fn run(args: &ProxyArgs, err: &mut dyn Write) -> Option<i32> {
    let text = args.target.as_deref()?;
    let (user, road) = match super::destination(text) {
        Ok(Some(found)) => found,
        Ok(None) => return None,
        Err(why) => {
            let _ = writeln!(err, "podssh proxy: {why}");
            return Some(EXIT_USAGE);
        }
    };
    let relay_flag = args.relay_host.is_some() || args.relay_failover.is_some() || args.relay_addr.is_some();
    let why = if user.is_some() {
        Some(format!("{text}: the SSH client logs in, so the destination takes no user here"))
    } else if args.port.is_some() {
        Some(format!("{text}: the port goes in the destination, as {}:PORT", road.shown()))
    } else if relay_flag {
        Some(format!("{text}: the relay's flags do not apply, as the road is the cloud's own tunnel"))
    } else {
        None
    };
    if let Some(why) = why {
        let _ = writeln!(err, "podssh proxy: {why}");
        return Some(EXIT_USAGE);
    }
    let road = match road {
        Road::Eice { endpoint, mut target } => {
            match eice::max_duration(std::env::var(DURATION_ENV).ok().as_deref()) {
                Ok(duration) => target.max_duration = duration,
                Err(why) => {
                    let _ = writeln!(err, "podssh proxy: {DURATION_ENV}: {why}");
                    return Some(EX_CONFIG);
                }
            }
            Road::Eice { endpoint, target }
        }
        other => other,
    };
    crate::session_log::target(&road.host(), Some(road.port()), road.word());
    if podssh_relay::open::offline() {
        let _ =
            writeln!(err, "podssh: {} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Some(EX_UNAVAILABLE);
    }
    let trust = crate::settings::ca_file(args.ca_file.as_deref()).map_or(Trust::Default, |f| Trust::File(f.into()));
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh proxy: could not start the async runtime: {e}");
            return Some(EXIT_NOT_IMPLEMENTED);
        }
    };
    let code = runtime.block_on(pipe(&road, &trust, err));
    // A read on stdin may still be blocked in a helper thread.
    runtime.shutdown_background();
    Some(code)
}

/// The road opened, then the pump of stdin and stdout over it; its code.
async fn pipe(road: &Road, trust: &Trust, err: &mut dyn Write) -> i32 {
    let shown = road.shown();
    let end = match road {
        Road::Iap(target) => {
            let tokens = match Tokens::from_env(trust.clone()) {
                Ok(tokens) => tokens,
                Err(fault) => {
                    let (why, code) = iap::token_words(&fault);
                    let _ = writeln!(err, "podssh: {shown}: the token: {why}");
                    return code;
                }
            };
            let said = shown.clone();
            // A lost link and its new one, as on podssh ssh; the rest is -v's.
            let say: Say = Arc::new(move |line: Line| {
                if let Line::Info(text) = line {
                    eprintln!("podssh: {said}: {text}");
                }
            });
            match carry::open(iap::dial(target, Arc::new(tokens), trust), say).await {
                Ok((stream, carried)) => {
                    let (target, said, watched) = (target.clone(), shown.clone(), carried.clone());
                    let why = move || {
                        let end = watched.get()?;
                        let code = match end {
                            Ended::Closed { code: Some(podssh_ws::iap::close::NOT_AUTHORIZED), .. } => EX_NOPERM,
                            _ => EX_UNAVAILABLE,
                        };
                        iap::ended(&said, &target, &end).map(|line| (code, line))
                    };
                    end_of(stream, why, Some(carried))
                }
                Err(not) => {
                    let (line, code) = iap::not_open(&shown, target, &not);
                    let _ = writeln!(err, "podssh: {line}");
                    return code;
                }
            }
        }
        Road::Eice { endpoint, target } => {
            let credentials = match super::aws::credentials() {
                Ok(credentials) => credentials,
                Err(why) => {
                    let _ = writeln!(err, "podssh: {shown}: the credential: {why}");
                    return EX_CONFIG;
                }
            };
            match eice::open(endpoint, target, &credentials, trust).await {
                Ok(session) => {
                    let (stream, status) = podssh_ssh::relay_stream::spawn(session);
                    let said = shown.clone();
                    let why = move || {
                        let end = status.get()?;
                        eice::ended(&said, &end).map(|line| (EX_UNAVAILABLE, line))
                    };
                    end_of(stream, why, None)
                }
                Err(e) => {
                    let (line, code) = eice::refusal(&shown, endpoint, &e);
                    let _ = writeln!(err, "podssh: {line}");
                    return code;
                }
            }
        }
        // WARP's tunnel (T-352): the stream's end is the end of the pipe,
        // and a lost tunnel ends its read with the tunnel's words.
        Road::Warp(target) => {
            let say = |line: &str| eprintln!("podssh: {line}");
            let quiet = |_: &str| {};
            match super::warp::open(target, trust, &say, &quiet).await {
                Ok(stream) => {
                    let (read, write) = tokio::io::split(stream);
                    End { read: Box::new(read), write: Box::new(write), child: None, last_word: true, ending: None }
                }
                Err((line, code)) => {
                    let _ = writeln!(err, "podssh: {line}");
                    return code;
                }
            }
        }
        // Tor (T-353): the stream's end is the end of the pipe.
        Road::Tor(target) => {
            let say = |line: &str| eprintln!("podssh: {line}");
            let quiet = |_: &str| {};
            match super::tor::open(target, &say, &quiet).await {
                Ok(stream) => {
                    let (read, write) = tokio::io::split(stream);
                    End { read: Box::new(read), write: Box::new(write), child: None, last_word: true, ending: None }
                }
                Err((line, code)) => {
                    let _ = writeln!(err, "podssh: {line}");
                    return code;
                }
            }
        }
    };
    crate::session_log::opened(None);
    let pumped = crate::pipe::pump::pump(crate::pipe::local::stdio(), end).await;
    crate::session_log::carried(pumped.carried.0, pumped.carried.1);
    crate::pipe::report(pumped, "podssh", err).await
}

/// The pipe's end of a road: its stream, and what its end says.
fn end_of(
    stream: DuplexStream,
    why: impl Fn() -> Option<(i32, String)> + Send + 'static,
    wait: Option<Carried>,
) -> End {
    let (read, write) = tokio::io::split(stream);
    let ending = Said { why: Box::new(why), wait };
    End { read: Box::new(read), write: Box::new(write), child: None, last_word: true, ending: Some(Box::new(ending)) }
}

/// What a road says once the pump is done: its end, after IAP's task has
/// said it, for [`SAID_WAIT`] at most.
struct Said {
    why: Box<dyn Fn() -> Option<(i32, String)> + Send>,
    wait: Option<Carried>,
}

impl Ending for Said {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        let Said { why, wait } = *self;
        Box::pin(async move {
            if let Some(mut carried) = wait {
                let _ = tokio::time::timeout(SAID_WAIT, carried.ended()).await;
            }
            why().map(|(code, line)| (code, vec![line]))
        })
    }
}
