//! `podssh each --interactive HOSTS` (T-185): a shell with no pty on each
//! host, and each line typed here goes to the hosts of the selection. The
//! local terminal keeps its normal mode, so that its own line discipline
//! edits the line; podssh reads whole lines, and a line that starts with
//! `:` is for podssh ([`hub`]). Each host's output comes as `HOST: LINE`,
//! as `podssh each` gives it, through the same writer ([`super::out`]).
//!
//! **The emergency stop** is a key that the terminal turns into a signal,
//! so that it acts at once, also while a line is half typed ([`keys`]): it
//! clears the selection and each byte that waits for a host. A broadcast
//! mistake costs once for each host, so the stop is armed before the first
//! host connects, and no broadcast starts without it (78).
//!
//! **Each host has a queue of 64 KiB** ([`hub::QUEUE`]): the bytes that its
//! session has not taken yet, as a session takes a line only when it can
//! send it. A host whose queue is full leaves the selection, with a word.
//!
//! No panes and no full screen: podssh is a CLI (the operator's ruling of
//! 2026-10-08), and line mode is the whole feature.

pub mod hub;
mod keys;

use std::io::Write;

use futures_util::stream::{FuturesUnordered, StreamExt};
use podssh_ssh::io::Feed;
use podssh_ssh::terminal::interrupt::INTERRUPTED;
use podssh_ssh::LogLevel;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use super::fan::{self, Ended};
use super::host::{self, Plan};
use super::out::{self, Line, Place};
use super::{EachArgs, MOST_AT_ONCE};
use crate::exitmap::Fault;
use crate::relay_settings::Refusal;
use crate::ssh::resolve::Env;
use hub::Hub;
use keys::{Key, Keys};

/// Run `podssh each --interactive`, or refuse a `--confirm` without it;
/// the process exit code.
pub fn run(args: &EachArgs, err: &mut dyn Write) -> i32 {
    let usage = |err: &mut dyn Write, why: String| Refusal::usage(why).report("each", err);
    if !args.interactive {
        return usage(err, "--confirm holds the lines of --interactive for a second Enter".into());
    }
    let Some(word) = args.hosts.as_deref() else {
        return usage(err, "give the hosts: podssh each --interactive HOSTS".into());
    };
    if !args.ssh.command.is_empty() {
        return usage(err, "--interactive takes no COMMAND: each line typed is one, for the shell of each host".into());
    }
    let for_a_command = [
        ("--parallel", args.parallel.is_some()),
        ("--fail-fast", args.fail_fast),
        ("--output-dir", args.output_dir.is_some()),
    ];
    if let Some((flag, _)) = for_a_command.iter().find(|(_, given)| *given) {
        return usage(err, format!("{flag} is for a command; --interactive keeps each host open, at once"));
    }
    if let Err(refusal) = crate::pins::apply(args.ssh.relay_addr.as_deref()) {
        return refusal.report("each", err);
    }
    // The hosts, each resolved before anything connects, as `each` does.
    let env = Env::from_process();
    let labels = match crate::hosts::expand(word, &env.settings.groups) {
        Ok(labels) => labels,
        Err(refusal) => return refusal.report("each", err),
    };
    if labels.len() > MOST_AT_ONCE {
        let n = labels.len();
        return usage(err, format!("{word} gives {n} hosts; --interactive keeps {MOST_AT_ONCE} open at most"));
    }
    let mut plans = Vec::with_capacity(labels.len());
    for label in &labels {
        match host::shell_plan(label, &args.ssh, &env) {
            Ok(plan) => plans.push(plan),
            Err(refusal) => return refusal.report("each", err),
        }
    }
    super::say_once(&plans);
    let mut feeds = Vec::with_capacity(plans.len());
    for plan in &mut plans {
        let feed = Feed::new();
        plan.resolved.options.feed = Some(feed.clone());
        feeds.push(feed);
    }
    let quiet = plans.iter().all(|p| p.resolved.options.log_level == LogLevel::Quiet);
    let hub = Hub::new(labels.clone(), feeds, env.settings.groups.clone(), args.confirm);
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh each: could not start the async runtime: {e}");
            return podssh_ssh::EXIT_FAILURE;
        }
    };
    // On the heap: the future of each host is large, and Windows gives the
    // main thread 1 MiB of stack.
    let ran = runtime.block_on(Box::pin(broadcast(&plans, hub, quiet)));
    // The read of stdin may still wait; the run is over.
    runtime.shutdown_background();
    let ends = match ran {
        Ok(ends) => ends,
        Err(why) => {
            let _ = writeln!(err, "podssh each: {why}");
            return Fault::Capability.code();
        }
    };
    if !quiet {
        for line in fan::summary(&labels, &ends) {
            let _ = writeln!(err, "podssh each: {line}");
        }
    }
    fan::exit_status(&ends)
}

/// The broadcast, from the keys to the end of the last host: the end of
/// each host, or why the broadcast could not start. A host that still ran
/// when Ctrl-C came after the end of the input is cut, with 130.
async fn broadcast(plans: &[Plan], mut hub: Hub, quiet: bool) -> Result<Vec<Ended>, String> {
    // Before anything connects: no broadcast without a stop that works.
    let mut keys = Keys::arm().map_err(|why| format!("the emergency stop cannot be armed ({why}); no broadcast"))?;
    if let Some(first) = plans.first() {
        host::first_token(&first.resolved, &first.log).await;
    }
    let (to, lines) = mpsc::channel(64);
    let writer = tokio::spawn(out::writer(lines));
    let mut running = FuturesUnordered::new();
    for (i, plan) in plans.iter().enumerate() {
        let place = Place::Lines { label: plan.label.clone(), to: to.clone() };
        running.push(async move { (i, host::run(plan, place).await) });
    }
    if !quiet {
        say(&to, &hub.banner()).await;
    }
    let mut typed = read_stdin();
    let mut reading = true;
    let mut ends: Vec<Option<Ended>> = vec![None; plans.len()];
    while !running.is_empty() {
        tokio::select! {
            chunk = typed.recv(), if reading => match chunk {
                Some(bytes) => say(&to, &hub.typed(&bytes)).await,
                None => {
                    reading = false;
                    say(&to, &hub.end()).await;
                    if !quiet {
                        say(&to, &[hub::ENDED.to_string()]).await;
                    }
                }
            },
            key = keys.next() => match key {
                Key::Stop => {
                    // What was read before the key and not yet acted on goes too.
                    let mut unread = 0;
                    while let Ok(bytes) = typed.try_recv() {
                        unread += bytes.len();
                    }
                    say(&to, &hub.stop(unread)).await;
                }
                Key::Interrupt if reading => say(&to, &hub.ctrl_c()).await,
                Key::Interrupt => {
                    let still = running.len();
                    let cut = format!("Ctrl-C after the end of the input: the {still} hosts that still run are cut");
                    say(&to, &[cut]).await;
                    break;
                }
            },
            Some((i, end)) = running.next() => {
                say(&to, &hub.ended(i, &end)).await;
                ends[i] = Some(end);
            }
        }
    }
    // Each host that still runs is cut here, as its future goes.
    drop(running);
    say(&to, &hub.missed()).await;
    drop(to);
    let _ = writer.await;
    Ok(ends.into_iter().map(|end| end.unwrap_or(Ended::Status(INTERRUPTED))).collect())
}

/// podssh's words, each a line on stderr, through the one writer of the
/// hosts' lines, so that no host's line cuts one of them.
async fn say(to: &mpsc::Sender<Line>, lines: &[String]) {
    for line in lines {
        let _ = to.send((format!("podssh: {line}\n").into_bytes(), true)).await;
    }
}

/// Read stdin on a task of its own, as it comes: a terminal in its normal
/// mode gives whole lines. `None` at its end.
fn read_stdin() -> mpsc::Receiver<Vec<u8>> {
    // Asked before the task reads: on Windows the question would wait for
    // the pending read, and each host's session asks it.
    let _ = podssh_ssh::terminal::stdin_is_terminal();
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                // A key that the terminal turned into a signal can cut a read short.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    });
    rx
}
