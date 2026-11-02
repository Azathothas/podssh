//! `podssh proxy --via URL HOST PORT` and `podssh pipe tcp:HOST:PORT --via
//! URL` (T-439): the pipe to the target through the second proxy's tunnel,
//! as OpenSSH's `ProxyCommand` takes it. The tunnel has TCP's half-close
//! (END_STREAM on HTTP/2, TLS's close on HTTP/1.1), so the end of stdin
//! stops what goes, and the target's bytes come until it closes.

use std::io::Write;

use super::Road;
use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::pipe::pump::End;
use crate::proxy::ProxyArgs;
use crate::relay_settings::Refusal;

/// The schemes of a target whose road is its own.
const OWN_ROADS: &[&str] = &["cf://", "iap://", "eice://", "warp://", "tor://"];

/// `--via` beside another road of `proxy`: a usage error.
pub fn beside(args: &ProxyArgs) -> Result<(), Refusal> {
    if args.via.url.is_none() {
        return Ok(());
    }
    let own = args.target.as_deref().is_some_and(|t| OWN_ROADS.iter().any(|s| t.starts_with(s)));
    let flags = [
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
    ];
    let other = match own {
        true => Some("a cf://, iap://, eice://, warp:// or tor:// target, which is a road of its own"),
        false => flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag),
    };
    match other {
        Some(other) => Err(Refusal::usage(format!("--via cannot go with {other}; a run has one road"))),
        None => Ok(()),
    }
}

/// The second proxy of `proxy`: the flag, else `PODSSH_VIA` where the
/// command line names no other road and `PODSSH_RELAY` is not set.
pub fn chosen(args: &ProxyArgs) -> Result<Option<Road>, Refusal> {
    let others = args.forwarder.is_some()
        || args.shadowsocks.is_some()
        || args.relay_host.is_some()
        || args.relay_failover.is_some();
    if args.via.url.is_none() && args.via.auth_file.is_none() && others {
        return Ok(None);
    }
    // The variable beside another road's variable: neither wins.
    if args.via.url.is_none() && super::var(super::VIA_ENV).is_some() {
        let other = [podssh_relay::relay::RELAY_ENV, crate::forwarder::FORWARDER_ENV];
        if let Some(other) = other.into_iter().find(|name| super::var(name).is_some()) {
            return Err(Refusal::config(format!("{} and {other} name two roads; a run has one", super::VIA_ENV)));
        }
    }
    super::chosen(&args.via, super::trust(args.ca_file.as_deref()))
}

/// The pipe of stdin and stdout to `host:port` through `road`: its exit
/// code.
pub fn run(road: &Road, host: &str, port: u16, err: &mut dyn Write) -> i32 {
    crate::session_log::target(host, Some(port), "via");
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

/// The end of a tunnel to `host:port` through `road`, or the exit code once
/// `say` has the line of the failure.
pub async fn open(road: &Road, host: &str, port: u16, say: &mut dyn FnMut(&str)) -> Result<End, i32> {
    if podssh_relay::open::offline() {
        say(&format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV));
        return Err(EX_UNAVAILABLE);
    }
    let target = podssh_ws::dial::authority(host, port);
    match super::client(road).open(host, port).await {
        Ok(opened) => {
            let (read, write) = tokio::io::split(opened.stream);
            Ok(End::plain(Box::new(read), Box::new(write)))
        }
        Err(e) => {
            say(&format!("could not connect to {target}: {e}"));
            Err(super::reach::exit_code(&e))
        }
    }
}
