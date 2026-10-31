//! What `~C` does in a session (T-291). Its line is read from the session's
//! own keys, with the question of ZMODEM (`zmodem::ask`): the input task
//! reads the terminal, and a second reader would take keys from it. The
//! keys after the line go back to the session, and no key of the line
//! reaches the server. A command acts on the session's connection: `-R`
//! and `-KR` ask the server, as `-R` does; `-L` and `-D` get listeners from
//! the caller and serve beside the session until `-KL` or `-KD` closes them
//! or the session ends; the connections that a closed listener took go on,
//! as in OpenSSH.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use russh::client::Handle;

use crate::escape_command::{self, Commands, Kind, Order, Place};
use crate::handler::Client;
use crate::io::Input;
use crate::local::LocalForward;
use crate::log::Log;
use crate::remote::Table;
use crate::zmodem::ask::{Answer, Question};

/// OpenSSH's prompt of the command line.
const PROMPT: &str = "ssh> ";

/// How long the server may take to answer `-R` or `-KR`: the session's keys
/// wait for the answer, as each other escape's keys wait for it to end.
const ANSWER_LIMIT: Duration = Duration::from_secs(20);

// Polled by the session's own task alone, which needs no `Send`.
type Serving<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;

/// The forwards of `-L` and `-D` that `~C` added to a session, each served
/// on the session's connection until its listeners are closed.
#[derive(Default)]
pub struct Added<'a> {
    serving: FuturesUnordered<Serving<'a>>,
}

impl<'a> Added<'a> {
    fn serve(&mut self, handle: &'a Handle<Client>, forward: LocalForward, log: &'a Arc<Log>) {
        self.serving.push(Box::pin(async move {
            crate::local::serve(handle, std::slice::from_ref(&forward), log).await;
        }));
    }

    /// Until one of them ends, which drops its listeners; never, with none.
    pub async fn next(&mut self) {
        if self.serving.next().await.is_none() {
            std::future::pending::<()>().await;
        }
    }
}

/// `~C`: its line, from `first` (the keys after `~C` in their read) and then
/// the session's keys, and the command on it.
pub async fn command_line<'a>(
    handle: &'a Handle<Client>,
    input: &mut Input,
    first: Vec<u8>,
    commands: Option<Commands>,
    added: &mut Added<'a>,
    log: &'a Arc<Log>,
) {
    let Some(line) = read_line(input, first).await else { return };
    // The destination's forwards of -R: a process runs one chain of
    // connections, as a control master's `-O forward` finds them too.
    let table = crate::remote::destination();
    match escape_command::parse(&line) {
        Ok(order) => run(order, handle, table.as_ref(), commands.as_ref(), added, log).await,
        Err(why) => log.info(&why),
    }
}

/// The line typed after `~C`, shown as it is typed when the terminal is raw
/// (the terminal shows it else); `None` for Ctrl-C, Ctrl-D or the end of
/// the input. The keys after the line are read next by the session.
async fn read_line(input: &mut Input, first: Vec<u8>) -> Option<String> {
    let (mut question, shown) = Question::new(PROMPT);
    let raw = crate::terminal::raw_active();
    show(b"\r\n");
    show(&shown);
    let mut keys = first;
    loop {
        let (echo, answer) = question.keys_and_rest(&keys);
        if raw {
            show(&echo);
        }
        if let Some((answer, took)) = answer {
            input.unread(keys.split_off(took));
            return match answer {
                Answer::Line(line) => Some(line),
                Answer::Refused => None,
            };
        }
        keys = input.next().await?;
    }
}

/// Bytes for the terminal, on stderr, where podssh's lines go.
fn show(bytes: &[u8]) {
    use std::io::Write;
    let mut err = std::io::stderr();
    let _ = err.write_all(bytes);
    let _ = err.flush();
}

/// Do `order` on the session's connection, whose forwards of `-R` are
/// `table`, and say how it went, in OpenSSH's words where it has them.
pub(crate) async fn run<'a>(
    order: Order,
    handle: &'a Handle<Client>,
    table: Option<&Table>,
    commands: Option<&Commands>,
    added: &mut Added<'a>,
    log: &'a Arc<Log>,
) {
    match order {
        Order::Nothing => {}
        Order::Help => log.banner(escape_command::HELP),
        Order::Add(kind, spec) => {
            let Some(commands) = commands else {
                log.info("Port forwarding failed: this session adds no forward");
                return;
            };
            if kind == Kind::Remote {
                add_remote(&spec, handle, table, commands, log).await;
                return;
            }
            match commands.0.local(&spec, kind == Kind::Dynamic).await {
                Ok(forward) => {
                    log.info("Forwarding port.");
                    added.serve(handle, forward, log);
                }
                Err(why) => log.info(&format!("Port forwarding failed: {why}")),
            }
        }
        Order::Cancel(Kind::Remote, Place::Port { bind, port }) => {
            cancel_remote(bind.as_deref(), port, handle, table, log).await;
        }
        // A forward of the server to a socket is not carried (T-035).
        Order::Cancel(Kind::Remote, Place::Path(path)) => cancel_remote_path(&path, handle, table, log).await,
        Order::Cancel(kind, at) => {
            let closed = crate::local::close(kind == Kind::Dynamic, |listening| at.holds(listening));
            if closed.is_empty() {
                log.info("Unknown port forwarding.");
            }
            for (name, whole) in closed {
                // `~#` says closed once no listener of it is left.
                if whole {
                    crate::tally::closed(&name);
                }
                log.info(&format!("Canceled forwarding: {name}"));
            }
        }
    }
}

/// `-R SPEC`: the server is asked, as for `-R`, and the answer awaited for
/// [`ANSWER_LIMIT`] at most. OpenSSH says "Forwarding port." before the
/// answer; podssh says it once the server took the forward.
async fn add_remote(spec: &str, handle: &Handle<Client>, table: Option<&Table>, commands: &Commands, log: &Log) {
    let forward = match commands.0.remote(spec) {
        Ok(forward) => forward,
        Err(why) => {
            log.info(&format!("Bad remote forwarding specification: {why}"));
            return;
        }
    };
    let Some(table) = table else {
        log.info("Port forwarding failed: no connection to forward on");
        return;
    };
    match tokio::time::timeout(ANSWER_LIMIT, crate::remote::ask(handle, table, &forward, log)).await {
        Ok(true) => log.info("Forwarding port."),
        Ok(false) => log.info(&crate::remote::failed("Warning", &forward)),
        Err(_) => log.info(&format!(
            "{}: no answer of the server within {} s",
            crate::remote::failed("Warning", &forward),
            ANSWER_LIMIT.as_secs()
        )),
    }
}

/// `-KR [BIND:]PORT`: the server lets the forward go, which it answers
/// within [`ANSWER_LIMIT`]; a channel for that port is refused from then on.
async fn cancel_remote(bind: Option<&str>, port: u16, handle: &Handle<Client>, table: Option<&Table>, log: &Log) {
    let Some(table) = table else {
        log.info("Unknown port forwarding.");
        return;
    };
    let cancelled = crate::remote::cancel(handle, table, bind, u32::from(port));
    match tokio::time::timeout(ANSWER_LIMIT, cancelled).await {
        Ok(Ok(Some(name))) => log.info(&format!("Canceled forwarding: {name}")),
        Ok(Ok(None)) => log.info("Unknown port forwarding."),
        Ok(Err(why)) => log.info(&format!("Port forwarding was not canceled: {why}")),
        Err(_) => log.info(&format!(
            "Port forwarding was not canceled: no answer of the server within {} s",
            ANSWER_LIMIT.as_secs()
        )),
    }
}

/// `-KR PATH`: as `-KR [BIND:]PORT`, for a socket path on the server (T-365).
async fn cancel_remote_path(path: &str, handle: &Handle<Client>, table: Option<&Table>, log: &Log) {
    let Some(table) = table else {
        log.info("Unknown port forwarding.");
        return;
    };
    match tokio::time::timeout(ANSWER_LIMIT, crate::remote::cancel_path(handle, table, path)).await {
        Ok(Ok(Some(name))) => log.info(&format!("Canceled forwarding: {name}")),
        Ok(Ok(None)) => log.info("Unknown port forwarding."),
        Ok(Err(why)) => log.info(&format!("Port forwarding was not canceled: {why}")),
        Err(_) => log.info(&format!(
            "Port forwarding was not canceled: no answer of the server within {} s",
            ANSWER_LIMIT.as_secs()
        )),
    }
}

#[cfg(test)]
#[path = "escape_run_tests.rs"]
mod tests;
