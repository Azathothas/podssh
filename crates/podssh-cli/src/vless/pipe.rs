//! `podssh proxy --vless FILE HOST PORT` (T-440): the pipe of stdin and
//! stdout to the target through the first server of the file that carries
//! it, as OpenSSH's `ProxyCommand` takes it. A pipe's client may speak first,
//! so a server that says nothing through a short wait is taken; one that
//! ends the session within it, or whose answer is not VLESS's, gives way to
//! the next. A WebSocket and packet-up have no half-close: the end of stdin
//! ends nothing, and the target's bytes come until the server ends.

use std::io::Write;

use podssh_ws::vless::{self, Dial};
use podssh_ws::{ProxyChoice, Trust};

use super::Servers;
use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::exitmap::sysexits::{EX_UNAVAILABLE, EX_USAGE};
use crate::pipe::pump::End;
use crate::proxy::ProxyArgs;
use crate::relay_settings::Refusal;

/// The schemes of a target whose road is its own.
const OWN_ROADS: &[&str] = &["cf://", "iap://", "eice://", "warp://", "tor://"];

/// `--vless` beside another road of `proxy`: a usage error.
pub fn beside(args: &ProxyArgs) -> Result<(), Refusal> {
    if args.vless.is_none() {
        return Ok(());
    }
    let own = args.target.as_deref().is_some_and(|t| OWN_ROADS.iter().any(|s| t.starts_with(s)));
    let flags = [
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
        ("--via", args.via.url.is_some()),
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
        ("--wstunnel", args.wstunnel.url.is_some()),
    ];
    let other = match own {
        true => Some("a cf://, iap://, eice://, warp:// or tor:// target, which is a road of its own"),
        false => flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag),
    };
    match other {
        Some(other) => Err(Refusal::usage(format!("--vless cannot go with {other}; a run has one road"))),
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
    crate::session_log::target(host, Some(port), "vless");
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
        trust,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        answer: vless::EARLY_WAIT,
        silence_is_ready: true,
        close_at_end: false,
    };
    let mut code = EX_UNAVAILABLE;
    for server in &servers.servers {
        match vless::open(server, host, port, &dial).await {
            Ok(opened) => {
                let (read, write) = tokio::io::split(opened.stream);
                return Ok(End::plain(Box::new(read), Box::new(write)));
            }
            Err(e) => {
                say(&e.line(&server.shown(), &target));
                code = super::reach::exit_code(&e);
                if code == EX_USAGE {
                    break;
                }
            }
        }
    }
    Err(code)
}
