//! `podssh proxy --shadowsocks FILE HOST PORT` (T-373): the pipe of stdin
//! and stdout to the target through the first server of the file that
//! carries it, as OpenSSH's `ProxyCommand`. A pipe's client may speak first,
//! so a server that stays silent through a short wait is taken; one that
//! closes, resets or answers with a chunk that does not open gives way to
//! the next. The end of stdin is TCP's half-close, which the server passes
//! on: the target's bytes come until it closes.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::time::Duration;

use podssh_ws::shadowsocks::{self, Carried, Dial, Node, Status};
use podssh_ws::{ProxyChoice, Trust};

use super::order::Order;
use super::Servers;
use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::pipe::pump::{End, Ending, Verdict};
use crate::proxy::ProxyArgs;
use crate::relay_settings::Refusal;

/// How long a pipe waits for a server's first word before it takes the
/// server: a close or a reset comes within it, a target whose client
/// speaks first sends nothing.
pub const EARLY_WAIT: Duration = Duration::from_secs(3);

/// The schemes of a destination whose road is its own.
const OWN_ROADS: &[&str] = &["cf://", "iap://", "eice://", "warp://", "tor://"];

/// `--shadowsocks` beside another road: a usage error.
pub fn beside(args: &ProxyArgs) -> Result<(), Refusal> {
    if args.shadowsocks.is_none() {
        return Ok(());
    }
    let own = args.target.as_deref().is_some_and(|t| OWN_ROADS.iter().any(|s| t.starts_with(s)));
    let other = if own {
        Some("a cf://, iap://, eice://, warp:// or tor:// target, which is a road of its own")
    } else if args.forwarder.is_some() {
        Some("--forwarder")
    } else if args.relay_host.is_some() {
        Some("--relay-host")
    } else if args.relay_failover.is_some() {
        Some("--relay-failover")
    } else {
        None
    };
    match other {
        Some(other) => Err(Refusal::usage(format!("--shadowsocks cannot go with {other}; a run has one road"))),
        None => Ok(()),
    }
}

/// The pipe to `host:port` through the servers of the file at `path`: its
/// exit code.
pub fn run(path: &str, host: &str, port: u16, ca_file: Option<&str>, err: &mut dyn Write) -> i32 {
    let servers = match super::read(path) {
        Ok(servers) => servers,
        Err(refusal) => return refusal.report("proxy", err),
    };
    crate::session_log::target(host, Some(port), "shadowsocks");
    let trust = super::trust(ca_file);
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh proxy: could not start the async runtime: {e}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    let code = runtime.block_on(session(&servers, host, port, &trust, err));
    // A read on stdin may still be blocked in a helper thread.
    runtime.shutdown_background();
    code
}

async fn session(servers: &Servers, host: &str, port: u16, trust: &Trust, err: &mut dyn Write) -> i32 {
    let mut lines: Vec<String> = Vec::new();
    let opened = open(servers, host, port, trust, &mut |line: &str| lines.push(line.to_string())).await;
    for line in &lines {
        let _ = writeln!(err, "podssh: {line}");
    }
    match opened {
        Ok(end) => crate::forwarder::pipe::carry(end, err).await,
        Err(code) => code,
    }
}

/// The pipe's end at the first server that carries `host:port`, or the
/// exit code once `say` has the line of each failure.
pub async fn open(
    servers: &Servers,
    host: &str,
    port: u16,
    trust: &Trust,
    say: &mut (dyn FnMut(&str) + Send),
) -> Result<End, i32> {
    if podssh_relay::open::offline() {
        say(&format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV));
        return Err(EX_UNAVAILABLE);
    }
    let target = podssh_ws::dial::authority(host, port);
    let dial = Dial {
        proxy: &ProxyChoice::FromEnvironment,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        answer: Some(EARLY_WAIT),
        silence_is_ready: true,
    };
    let mut order = Order::new(servers, trust);
    let mut code = EX_UNAVAILABLE;
    while let Some(node) = order.next(say).await {
        match shadowsocks::open(&node, host, port, &dial).await {
            Ok(opened) => return Ok(end(opened.carried, &node)),
            Err(e) => {
                say(&e.line(&node.shown(), &target));
                code = super::reach::exit_code(&e);
                // A target that no server takes: the next would refuse it too.
                if code == crate::exitmap::sysexits::EX_USAGE {
                    break;
                }
            }
        }
    }
    Err(code)
}

/// The pipe's end of a server's stream: its end ends the pipe, as nothing
/// more can come.
fn end(carried: Carried, node: &Node) -> End {
    let status = carried.status.clone();
    let (read, write) = tokio::io::split(carried.stream);
    let ending = Finished { status, shown: node.shown() };
    End { read: Box::new(read), write: Box::new(write), child: None, last_word: true, ending: Some(Box::new(ending)) }
}

struct Finished {
    status: Status,
    shown: String,
}

impl Ending for Finished {
    fn finish(self: Box<Self>) -> Pin<Box<dyn Future<Output = Verdict> + Send>> {
        Box::pin(async move {
            let end = self.status.get()?;
            Some((EX_UNAVAILABLE, vec![super::reach::ended(&self.shown, &end)]))
        })
    }
}
