//! `podssh proxy HOST PORT`: a byte pipe between stdin/stdout and HOST:PORT,
//! through the relay. It is made to be OpenSSH's `ProxyCommand`:
//!
//! ```text
//! ssh -o ProxyCommand='podssh proxy %h %p' -o ServerAliveInterval=60 user@host
//! ```
//!
//! stdout carries the target's bytes and nothing else; diagnostics go to
//! stderr. End of stdin stops sending but keeps receiving (as `nc` does without
//! `-N`): a WebSocket Close is not a TCP half-close, and sending one would cut
//! off a reply that is still on its way. Since T-175 it is the pipe of
//! `stdio` and `relay:HOST:PORT`: one pump, and the relay's end of
//! `crate::pipe::relay`. `node://NAME` is the pipe of `podssh operator NAME`
//! (`crate::proxy_node`, T-587). With `PODSSH_RELAY_LAYER=yes`, a relay
//! host that offers it carries the session in the resumable layer, which
//! outlives a drop of this host's link (`crate::relay_layer`, T-173).

use std::io::Write;

use podssh_ws::Trust;

use podssh_relay::failover::Mode;
use podssh_relay::open::{OpenError, Request};
use podssh_relay::relay::{self, RelayList};
use podssh_relay::token::TokenError;
use podssh_ws::dial::DialError;
use podssh_ws::ConnectError;

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};

/// What `podssh proxy` was asked to do.
#[derive(Debug, Clone, Default)]
pub struct ProxyArgs {
    /// `HOST`, or `HOST:PORT` when no separate port is given.
    pub target: Option<String>,
    pub port: Option<String>,
    /// `--relay-host`.
    pub relay_host: Option<String>,
    /// `--relay-failover`.
    pub relay_failover: Option<String>,
    /// `--relay-addr`.
    pub relay_addr: Option<String>,
    /// `--ca-file`.
    pub ca_file: Option<String>,
    /// `--forwarder`: the forwarders in place of the relay (T-369).
    pub forwarder: Option<String>,
    /// `--shadowsocks`: the file of Shadowsocks servers in place of the
    /// relay (T-373).
    pub shadowsocks: Option<String>,
    /// `--via` and `--via-auth-file`: a forward proxy over TLS in place of
    /// the relay (T-439).
    pub via: crate::via::Flags,
    /// `--vless`: the file of VLESS servers in place of the relay (T-440).
    pub vless: Option<String>,
    /// `--wstunnel` and `--wstunnel-secret-file`: a wstunnel server in place
    /// of the relay (T-441).
    pub wstunnel: crate::wstunnel::Flags,
    /// `--chisel` and `--chisel-auth-file`: a chisel server in place of the
    /// relay (T-490).
    pub chisel: crate::chisel::Flags,
    /// `--exit NAME` and `--client-key FILE`: the pipe starts at this exit
    /// of the net, in place of the relay (T-431).
    pub exit: crate::exit::Flags,
    /// `--idle-warn SECONDS`: the lead of the warning before the relay's
    /// idle cut (T-463), unparsed.
    pub idle_warn: Option<String>,
    /// The flags of a pair and of its channel, for `node://NAME` (T-587).
    pub node: crate::proxy_node::Flags,
    /// `--ConnectTimeout SECONDS`: the bound on the open of each road
    /// (T-589), unparsed.
    pub connect_timeout: Option<String>,
    /// `--timeout DURATION`, another name of the bound (T-613), unparsed.
    pub timeout: Option<String>,
}

/// Run the verb; returns the process exit code. A run that named its
/// destination adds its line to the session log, when it is on (T-056).
pub fn run_proxy(args: &ProxyArgs, err: &mut dyn Write) -> i32 {
    let (started, start_ms) = (std::time::Instant::now(), crate::pairs::now_ms());
    let log = match crate::session_log::place() {
        Ok(place) => place,
        Err(refusal) => return refusal.report("proxy", err),
    };
    let code = proxy(args, err);
    let line = crate::session_log::proxy_line(start_ms, started.elapsed().as_millis() as u64, code);
    if let Some(line) = line.filter(|_| log != crate::session_log::Place::Off) {
        if let Err(why) = crate::session_log::append(&log, &line) {
            let _ = writeln!(err, "podssh proxy: the session log: {why}");
        }
    }
    code
}

fn proxy(args: &ProxyArgs, err: &mut dyn Write) -> i32 {
    // node://NAME, the pipe of `operator NAME`, first: each other road's
    // flag is its refusal there, and the flags of a node go with it alone.
    if let Some(code) = crate::proxy_node::run(args, err) {
        return code;
    }
    // A road of its own takes no forwarder (T-369), no Shadowsocks server
    // (T-373), no second proxy (T-439), no VLESS server (T-440), no
    // wstunnel server (T-441) and no chisel server (T-490).
    let beside = crate::forwarder::pipe::beside(args)
        .and_then(|()| crate::shadowsocks::pipe::beside(args))
        .and_then(|()| crate::via::pipe::beside(args))
        .and_then(|()| crate::vless::pipe::beside(args))
        .and_then(|()| crate::wstunnel::pipe::beside(args))
        .and_then(|()| crate::chisel::pipe::beside(args));
    if let Err(refusal) = beside.and_then(|()| key_alone(args)) {
        return refusal.report("proxy", err);
    }
    // The lead of the warning before the relay's idle cut (T-463).
    let idle = match crate::ssh::idle_warn::lead_of(args.idle_warn.as_deref()) {
        Ok(lead) => lead,
        Err(why) => return crate::relay_settings::Refusal::usage(why).report("proxy", err),
    };
    // --ConnectTimeout (T-589), or --timeout or PODSSH_TIMEOUT (T-613): one
    // bound on the open of the road, whose step each road below names; a
    // node's run keeps its own, in `operator`.
    let var = |name: &str| std::env::var(name).ok();
    let bound = match crate::connect_bound::chosen(args.connect_timeout.as_deref(), args.timeout.as_deref(), var) {
        Ok(bound) => bound,
        Err(refusal) => return refusal.report("proxy", err),
    };
    let first = format!("{} did not answer", args.target.as_deref().unwrap_or("the road"));
    let _bound = crate::connect_bound::watch(bound, "proxy", &first);
    // iap:// and eice://, a cloud's own tunnel (T-351).
    if let Some(code) = crate::ssh::cloud::proxy::run(args, err) {
        return code;
    }
    match args.target.as_deref().map(crate::ssh::cloudflare::destination) {
        Some(Ok(Some((None, host)))) => return run_cloudflare(&host, args, err),
        Some(Ok(Some((Some(_), _)))) => {
            let _ = writeln!(err, "podssh proxy: a cf://HOST has no user here: the SSH client logs in");
            return EXIT_USAGE;
        }
        Some(Err(why)) => {
            let _ = writeln!(err, "podssh proxy: {why}");
            return EXIT_USAGE;
        }
        _ => {}
    }
    let (host, port) = match parse_target(args.target.as_deref(), args.port.as_deref()) {
        Ok(t) => t,
        Err(why) => {
            let _ = writeln!(err, "podssh proxy: {why}");
            // `--relay-host=-x 22` takes the HOST for its value: say how a
            // HOST that starts with - gets through.
            let flags = args.relay_host.is_some()
                || args.relay_failover.is_some()
                || args.relay_addr.is_some()
                || args.ca_file.is_some()
                || args.forwarder.is_some()
                || args.shadowsocks.is_some()
                || args.vless.is_some()
                || args.via != crate::via::Flags::default()
                || args.wstunnel != crate::wstunnel::Flags::default()
                || args.chisel != crate::chisel::Flags::default();
            if flags && (args.target.is_none() || args.port.is_none()) {
                let _ = writeln!(err, "podssh proxy: a HOST that starts with - is read as a flag; put -- before it");
            }
            let _ = writeln!(
                err,
                "usage: podssh proxy [OPTIONS] [--] HOST PORT | node://NAME   (as an OpenSSH ProxyCommand: podssh \
                 proxy %h %p)"
            );
            return EXIT_USAGE;
        }
    };
    if let Err(refusal) = crate::pins::apply(args.relay_addr.as_deref()) {
        return refusal.report("proxy", err);
    }
    // The exit of the net (T-431): the pipe starts at the node, alone, or at
    // the node at the other end of the stream of --carrier (T-614).
    if let Some(name) = args.exit.name.as_deref() {
        crate::connect_bound::step(match args.node.carrier {
            Some(_) => format!("the exit {name} did not read the carrier's stream"),
            None => format!("the exit {name} did not answer"),
        });
        return match exit_alone(args) {
            Ok(()) => crate::exit::open::run_proxy(&exit_to(name, args), &host, port, err),
            Err(refusal) => refusal.report("proxy", err),
        };
    }
    crate::session_log::target(&host, Some(port), "relay");
    // A chisel server (T-490), the VLESS servers of a file (T-440), a
    // wstunnel server (T-441), a forward proxy over TLS (T-439), the
    // Shadowsocks servers of a file (T-373), then the forwarders, when the
    // command line or the environment names them (T-369): then the relay is
    // not asked.
    match crate::chisel::pipe::chosen(args) {
        Ok(Some(road)) => {
            crate::connect_bound::step("the chisel server did not answer");
            return crate::chisel::pipe::run(&road, &host, port, err);
        }
        Ok(None) => {}
        Err(refusal) => return refusal.report("proxy", err),
    }
    if let Some(path) = args.vless.as_deref() {
        crate::connect_bound::step("no VLESS server answered");
        return crate::vless::pipe::run(path, &host, port, args.ca_file.as_deref(), err);
    }
    match crate::wstunnel::pipe::chosen(args) {
        Ok(Some(road)) => {
            crate::connect_bound::step("the wstunnel server did not answer");
            return crate::wstunnel::pipe::run(&road, &host, port, err);
        }
        Ok(None) => {}
        Err(refusal) => return refusal.report("proxy", err),
    }
    match crate::via::pipe::chosen(args) {
        Ok(Some(road)) => {
            crate::connect_bound::step("the proxy of --via did not answer");
            return crate::via::pipe::run(&road, &host, port, err);
        }
        Ok(None) => {}
        Err(refusal) => return refusal.report("proxy", err),
    }
    if let Some(path) = args.shadowsocks.as_deref() {
        crate::connect_bound::step("no Shadowsocks server answered");
        return crate::shadowsocks::pipe::run(path, &host, port, args.ca_file.as_deref(), err);
    }
    match crate::forwarder::pipe::chosen(args) {
        Ok(Some(forwarders)) => {
            crate::connect_bound::step("no forwarder answered");
            return crate::forwarder::pipe::run(&forwarders, &host, port, args.ca_file.as_deref(), err);
        }
        Ok(None) => {}
        Err(refusal) => return refusal.report("proxy", err),
    }
    crate::connect_bound::step("no relay host answered");
    let relays = match crate::relay_settings::relays(args.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok()) {
        Ok(r) => r,
        Err(refusal) => return refusal.report("proxy", err),
    };
    let failover = match crate::relay_settings::failover(
        args.relay_failover.as_deref(),
        std::env::var(podssh_relay::failover::MODE_ENV).ok(),
    ) {
        Ok(mode) => mode,
        Err(refusal) => return refusal.report("proxy", err),
    };
    let path = match relay::forward_path(&host, port) {
        Ok(p) => p,
        Err(why) => {
            let _ = writeln!(err, "podssh proxy: {why}");
            return EXIT_USAGE;
        }
    };
    let ca_file = crate::settings::ca_file(args.ca_file.as_deref());
    let trust = match ca_file {
        Some(file) => Trust::File(file.into()),
        None => Trust::Default,
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh proxy: could not start the async runtime: {e}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    let v6 = relay::is_ipv6_literal(&host);
    let road = Road { relays: &relays, trust: &trust, failover };
    let code = runtime.block_on(session(&road, &path, (&host, port), v6, idle, err));
    // A read on stdin may still be blocked in a helper thread; do not wait
    // for it, or podssh would hang after the session has ended.
    runtime.shutdown_background();
    code
}

/// `podssh proxy cf://HOST` (T-264): the pipe to the service that
/// `cloudflared` publishes under HOST, over its WebSocket, with no relay.
fn run_cloudflare(host: &str, args: &ProxyArgs, err: &mut dyn Write) -> i32 {
    let relay_flag = args.relay_host.is_some() || args.relay_failover.is_some() || args.relay_addr.is_some();
    let why = if args.port.is_some() {
        Some("cf://HOST takes no PORT: the tunnel's rule names the service")
    } else if relay_flag {
        Some("the relay's flags do not apply to cf://HOST: its road is the tunnel's WebSocket")
    } else {
        None
    };
    if let Some(why) = why {
        let _ = writeln!(err, "podssh proxy: {why}");
        return EXIT_USAGE;
    }
    crate::session_log::target(host, None, "cloudflare");
    if podssh_relay::open::offline() {
        let _ =
            writeln!(err, "podssh: {} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return EX_UNAVAILABLE;
    }
    let access = match crate::ssh::cloudflare::access_from(&|name| std::env::var(name).ok()) {
        Ok(access) => access,
        Err(why) => {
            let _ = writeln!(err, "podssh proxy: {why}");
            return EX_CONFIG;
        }
    };
    let ca_file = crate::settings::ca_file(args.ca_file.as_deref());
    let trust = ca_file.map_or(Trust::Default, |file| Trust::File(file.into()));
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh proxy: could not start the async runtime: {e}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    let code = runtime.block_on(async {
        let timeout = podssh_relay::open::CONNECT_TIMEOUT;
        let idle = Some(podssh_ws::client::DEFAULT_IDLE_TIMEOUT);
        let proxy = podssh_ws::ProxyChoice::FromEnvironment;
        match podssh_ws::cloudflare::connect(host, &access, &trust, &proxy, timeout, idle).await {
            Ok(session) => {
                crate::session_log::opened(None);
                let shown = format!("{}{host}", crate::ssh::cloudflare::SCHEME);
                let carried = crate::pipe::relay::carry(session, shown, false, true);
                let pumped = crate::pipe::pump::pump(crate::pipe::local::stdio(), carried).await;
                crate::session_log::carried(pumped.carried.0, pumped.carried.1);
                crate::pipe::report(pumped, "podssh", err).await
            }
            Err(e) => {
                let (line, code) = crate::ssh::cloudflare::refusal(host, &e);
                let _ = writeln!(err, "podssh: {line}");
                code
            }
        }
    });
    runtime.shutdown_background();
    code
}

/// `--exit` takes the relay's place: no relay host, no server of another
/// road, and no cf://HOST, iap:// or eice://, which have roads of their own.
/// Over a carrier (T-614), no flag of the pair's relay either, and no stdio,
/// which carries the pipe's bytes.
fn exit_alone(args: &ProxyArgs) -> Result<(), crate::relay_settings::Refusal> {
    let other = args.relay_host.is_some()
        || args.relay_failover.is_some()
        || args.forwarder.is_some()
        || args.shadowsocks.is_some()
        || args.vless.is_some()
        || args.via != crate::via::Flags::default()
        || args.wstunnel != crate::wstunnel::Flags::default()
        || args.chisel != crate::chisel::Flags::default();
    if other {
        let why = "--exit takes the relay's place: it goes with no relay host and no server of another road";
        return Err(crate::relay_settings::Refusal::usage(why));
    }
    let Some(text) = args.node.carrier.as_deref() else { return Ok(()) };
    crate::exit::no_relay(&[(args.relay_addr.is_some(), "--relay-addr"), (args.ca_file.is_some(), "--ca-file")])?;
    crate::carrier::for_a_client(text, "stdin and stdout carry the pipe's bytes here").map(|_| ())
}

/// `--client-key` is the channel's of the exit, or of a node, which takes
/// it before this.
fn key_alone(args: &ProxyArgs) -> Result<(), crate::relay_settings::Refusal> {
    match (&args.exit.name, &args.exit.client_key) {
        (None, Some(_)) => {
            let why = "--client-key is this client's key for --exit NAME or node://NAME: give one of them";
            Err(crate::relay_settings::Refusal::usage(why))
        }
        _ => Ok(()),
    }
}

/// The exit of `--exit NAME`, with the trust of `--ca-file` for its pair's
/// relay, or the stream of `--carrier` in place of its pair (T-614).
fn exit_to(name: &str, args: &ProxyArgs) -> crate::exit::open::To {
    let (name, client_key, ca_file) = (name.to_string(), args.exit.client_key.clone(), args.ca_file.clone());
    let carrier = args.node.carrier.clone();
    crate::exit::open::To { name, client_key, ca_file, carrier, ..Default::default() }
}

/// `HOST PORT`, or one word: `HOST:PORT` or `[IPV6]:PORT`. HOST may be a
/// bare IPv6 address (OpenSSH gives `%h` so) or one in brackets.
pub fn parse_target(target: Option<&str>, port: Option<&str>) -> Result<(String, u16), String> {
    let target = target.ok_or("missing HOST and PORT")?;
    let (host, port_text) = match port {
        Some(p) => (unbracket(target)?, p.to_string()),
        None => one_word(target)?,
    };
    let port =
        port_text.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{port_text:?} is not a port"))?;
    relay::check_target(&host)?;
    Ok((host, port))
}

/// `[IPV6]` to the address; a name or a bare address as it is.
fn unbracket(host: &str) -> Result<String, String> {
    let Some(rest) = host.strip_prefix('[') else { return Ok(host.to_string()) };
    match rest.strip_suffix(']') {
        Some(inner) if relay::is_ipv6_literal(inner) => Ok(inner.to_string()),
        Some(_) => Err(format!("{host:?}: brackets hold an IPv6 address, as in [2001:db8::1]")),
        None => Err(format!("{host:?}: '[' is not closed")),
    }
}

/// One word, by the rule of `podssh_ws::dial`'s proxy URLs: `[IPV6]:PORT`,
/// or `HOST:PORT` with one `:`. More than one `:` with no brackets is
/// refused: in `2001:db8::1:22`, the `:22` is a part of the address.
fn one_word(target: &str) -> Result<(String, String), String> {
    if let Some(rest) = target.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or_else(|| format!("{target:?}: '[' is not closed"))?;
        let port = after.strip_prefix(':').ok_or_else(|| format!("missing PORT: {target:?} needs :PORT after ']'"))?;
        return Ok((unbracket(&format!("[{inner}]"))?, port.to_string()));
    }
    if target.matches(':').count() > 1 {
        return Err(format!(
            "{target:?}: an IPv6 address with a port needs brackets, as in [2001:db8::1]:22; or give the port as a second word"
        ));
    }
    let (host, port) = target.rsplit_once(':').ok_or("missing PORT")?;
    Ok((host.to_string(), port.to_string()))
}

/// The relay hosts, the trust of their TLS, and how the hosts are tried.
struct Road<'a> {
    relays: &'a RelayList,
    trust: &'a Trust,
    failover: Mode,
}

/// The session through the relay; `idle`, the lead of `--idle-warn`.
async fn session(
    road: &Road<'_>,
    path: &str,
    (host, port): (&str, u16),
    v6: bool,
    idle: Option<std::time::Duration>,
    err: &mut dyn Write,
) -> i32 {
    // The resumable layer at podssh's relay role, where PODSSH_RELAY_LAYER
    // asks for it and the first host offers it (T-173); else the contract's.
    if let Some(code) = crate::relay_layer::run(road.relays, road.trust, (host, port), err).await {
        return code;
    }
    let target = &podssh_ws::dial::authority(host, port);
    let request = Request { relays: road.relays, path, trust: road.trust, target, rounds: 1, failover: road.failover };
    let opened = podssh_relay::open(&request, &mut |note: &str| {
        let _ = writeln!(err, "podssh: {note}");
    })
    .await;
    match opened {
        Ok(opened) => {
            crate::session_log::opened(Some(&opened.relay.host));
            let (relayed, crossed) = crate::pipe::relay::carry_watched(opened, target.to_string(), v6);
            let watch = crate::ssh::idle_warn::spawn_proxy(crossed, idle);
            let pumped = crate::pipe::pump::pump(crate::pipe::local::stdio(), relayed).await;
            if let Some(watch) = watch {
                watch.abort();
            }
            crate::session_log::carried(pumped.carried.0, pumped.carried.1);
            crate::pipe::report(pumped, "podssh", err).await
        }
        Err(failure) => {
            for line in failure.lines(target) {
                let _ = writeln!(err, "podssh: {line}");
            }
            // The HTTP road at a host whose upgrade the way refused (T-319).
            let to = (host, port);
            if let Some(code) = crate::http_road::after_relay_pipe(&failure, road.relays, road.trust, to, err).await {
                return code;
            }
            // Each relay host failed: the forwarders that the binary names,
            // where the relay was podssh's choice (T-370) and no relay host
            // answered about the target (T-509).
            let code = sysexit(failure.last());
            let answered = crate::forwarder::fallback::answered(&failure);
            crate::connect_bound::step("no forwarder answered after the relay");
            let to = (host, port);
            crate::forwarder::fallback::after_relay_pipe(code, answered, road.relays, to, road.trust, err).await
        }
    }
}

/// The sysexits code `podssh proxy` exits with when no session opened.
pub fn sysexit(e: &OpenError) -> i32 {
    match e {
        OpenError::Token(TokenError::BadEnvironment) => EX_CONFIG,
        OpenError::Token(TokenError::Connect(c)) | OpenError::Connect { error: c, .. } => match c {
            ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_)) => EX_CONFIG,
            ConnectError::Refused { status: 401 | 403, .. } => EX_NOPERM,
            // The relay answers 400 for a target in a blocked address range.
            ConnectError::Refused { status: 400, body } if podssh_relay::open::is_policy_refusal(body) => EX_NOPERM,
            ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
            _ => EX_UNAVAILABLE,
        },
        _ => EX_UNAVAILABLE,
    }
}
