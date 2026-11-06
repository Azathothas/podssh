//! `podssh proxy --chisel URL HOST PORT` (T-490): the pipe to the target
//! through a chisel server's channel, as OpenSSH's `ProxyCommand` takes it,
//! and as `chisel client URL stdio:HOST:PORT` serves it. The end of stdin
//! sends the channel's EOF, a half-close: the target's bytes come until it
//! closes, and the server's close of the channel ends the pipe.

use std::io::Write;

use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::pipe::pump::End;
use crate::proxy::ProxyArgs;
use crate::relay_settings::Refusal;

use super::Road;

/// The schemes of a target whose road is its own.
const OWN_ROADS: &[&str] = &["cf://", "iap://", "eice://", "warp://", "tor://", "upterm://", "upterm+ws://"];

/// `--chisel` beside another road of `proxy`: a usage error.
pub fn beside(args: &ProxyArgs) -> Result<(), Refusal> {
    if args.chisel.url.is_none() {
        return Ok(());
    }
    let own = args.target.as_deref().is_some_and(|t| OWN_ROADS.iter().any(|s| t.starts_with(s)));
    let flags = [
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
        ("--via", args.via.url.is_some()),
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
        ("--vless", args.vless.is_some()),
        ("--wstunnel", args.wstunnel.url.is_some()),
    ];
    let other = match own {
        true => Some("a cf://, iap://, eice://, warp:// or tor:// target, which is a road of its own"),
        false => flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag),
    };
    match other {
        Some(other) => Err(Refusal::usage(format!("--chisel cannot go with {other}; a run has one road"))),
        None => Ok(()),
    }
}

/// The chisel server of `proxy`: the flag, else `PODSSH_CHISEL` where the
/// command line names no other road and no other road's variable is set.
pub fn chosen(args: &ProxyArgs) -> Result<Option<Road>, Refusal> {
    let others = args.forwarder.is_some()
        || args.shadowsocks.is_some()
        || args.via.url.is_some()
        || args.relay_host.is_some()
        || args.relay_failover.is_some()
        || args.vless.is_some()
        || args.wstunnel.url.is_some();
    if args.chisel.url.is_none() && args.chisel.auth_file.is_none() && others {
        return Ok(None);
    }
    // The variable beside another road's variable: neither wins.
    if args.chisel.url.is_none() && super::var(super::CHISEL_ENV).is_some() {
        let other = [
            podssh_relay::relay::RELAY_ENV,
            crate::forwarder::FORWARDER_ENV,
            crate::via::VIA_ENV,
            crate::wstunnel::WSTUNNEL_ENV,
        ];
        if let Some(other) = other.into_iter().find(|name| super::var(name).is_some()) {
            let why = format!("{} and {other} name two roads; a run has one", super::CHISEL_ENV);
            return Err(Refusal::config(why));
        }
    }
    super::chosen(&args.chisel, super::trust(args.ca_file.as_deref()))
}

/// The pipe of stdin and stdout to `host:port` through `road`: its exit
/// code.
pub fn run(road: &Road, host: &str, port: u16, err: &mut dyn Write) -> i32 {
    crate::session_log::target(host, Some(port), "chisel");
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh proxy: could not start the async runtime: {e}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    let code = runtime.block_on(session(road, host, port, err));
    // A read on stdin may still be blocked in a helper thread.
    runtime.shutdown_background();
    code
}

async fn session(road: &Road, host: &str, port: u16, err: &mut dyn Write) -> i32 {
    let mut lines: Vec<String> = Vec::new();
    let opened = open(road, host, port, &mut |line: &str| lines.push(line.to_string())).await;
    for line in &lines {
        let _ = writeln!(err, "podssh: {line}");
    }
    match opened {
        Ok(end) => crate::forwarder::pipe::carry(end, err).await,
        Err(code) => code,
    }
}

/// The end of a channel to `host:port` through `road`, or the exit code
/// once `say` has the line of the failure.
pub async fn open(road: &Road, host: &str, port: u16, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    if podssh_relay::open::offline() {
        say(&format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV));
        return Err(EX_UNAVAILABLE);
    }
    let target = podssh_ws::dial::authority(host, port);
    match super::link::open(road, host, port, podssh_relay::open::CONNECT_TIMEOUT).await {
        Ok(stream) => {
            let (read, write) = tokio::io::split(stream);
            Ok(End { read: Box::new(read), write: Box::new(write), child: None, last_word: true, ending: None })
        }
        Err(failed) => {
            say(&format!("could not connect to {target}: {}", failed.line));
            Err(failed.code)
        }
    }
}
