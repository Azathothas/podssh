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
//! `crate::pipe::relay`.

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
    /// `--exit NAME` and `--client-key FILE`: the pipe starts at this exit
    /// of the net, in place of the relay (T-431).
    pub exit: crate::exit::Flags,
    /// `--idle-warn SECONDS`: the lead of the warning before the relay's
    /// idle cut (T-463), unparsed.
    pub idle_warn: Option<String>,
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
    // A road of its own takes no forwarder (T-369), no Shadowsocks server
    // (T-373), no second proxy (T-439), no VLESS server (T-440) and no
    // wstunnel server (T-441).
    let beside = crate::forwarder::pipe::beside(args)
        .and_then(|()| crate::shadowsocks::pipe::beside(args))
        .and_then(|()| crate::via::pipe::beside(args))
        .and_then(|()| crate::vless::pipe::beside(args))
        .and_then(|()| crate::wstunnel::pipe::beside(args));
    if let Err(refusal) = beside.and_then(|()| key_alone(args)) {
        return refusal.report("proxy", err);
    }
    // The lead of the warning before the relay's idle cut (T-463).
    let idle = match crate::ssh::idle_warn::lead_of(args.idle_warn.as_deref()) {
        Ok(lead) => lead,
        Err(why) => return crate::relay_settings::Refusal::usage(why).report("proxy", err),
    };
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
                || args.wstunnel != crate::wstunnel::Flags::default();
            if flags && (args.target.is_none() || args.port.is_none()) {
                let _ = writeln!(err, "podssh proxy: a HOST that starts with - is read as a flag; put -- before it");
            }
            let _ = writeln!(
                err,
                "usage: podssh proxy [OPTIONS] [--] HOST PORT   (as an OpenSSH ProxyCommand: podssh proxy %h %p)"
            );
            return EXIT_USAGE;
        }
    };
    if let Err(refusal) = crate::pins::apply(args.relay_addr.as_deref()) {
        return refusal.report("proxy", err);
    }
    // The exit of the net (T-431): the pipe starts at the node, alone.
    if let Some(name) = args.exit.name.as_deref() {
        return match exit_alone(args) {
            Ok(()) => crate::exit::open::run_proxy(&exit_to(name, args), &host, port, err),
            Err(why) => crate::relay_settings::Refusal::usage(why).report("proxy", err),
        };
    }
    crate::session_log::target(&host, Some(port), "relay");
    // The VLESS servers of a file (T-440), a wstunnel server (T-441), a forward
    // proxy over TLS (T-439), the Shadowsocks servers of a file (T-373), then
    // the forwarders, when the command line or the environment names them
    // (T-369): then the relay is not asked.
    if let Some(path) = args.vless.as_deref() {
        return crate::vless::pipe::run(path, &host, port, args.ca_file.as_deref(), err);
    }
    match crate::wstunnel::pipe::chosen(args) {
        Ok(Some(road)) => return crate::wstunnel::pipe::run(&road, &host, port, err),
        Ok(None) => {}
        Err(refusal) => return refusal.report("proxy", err),
    }
    match crate::via::pipe::chosen(args) {
        Ok(Some(road)) => return crate::via::pipe::run(&road, &host, port, err),
        Ok(None) => {}
        Err(refusal) => return refusal.report("proxy", err),
    }
    if let Some(path) = args.shadowsocks.as_deref() {
        return crate::shadowsocks::pipe::run(path, &host, port, args.ca_file.as_deref(), err);
    }
    match crate::forwarder::pipe::chosen(args) {
        Ok(Some(forwarders)) => {
            return crate::forwarder::pipe::run(&forwarders, &host, port, args.ca_file.as_deref(), err)
        }
        Ok(None) => {}
        Err(refusal) => return refusal.report("proxy", err),
    }
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
fn exit_alone(args: &ProxyArgs) -> Result<(), &'static str> {
    let other = args.relay_host.is_some()
        || args.relay_failover.is_some()
        || args.forwarder.is_some()
        || args.shadowsocks.is_some()
        || args.vless.is_some()
        || args.via != crate::via::Flags::default()
        || args.wstunnel != crate::wstunnel::Flags::default();
    match other {
        true => Err("--exit takes the relay's place: it goes with no relay host and no server of another road"),
        false => Ok(()),
    }
}

/// `--client-key` is the exit's channel's alone.
fn key_alone(args: &ProxyArgs) -> Result<(), crate::relay_settings::Refusal> {
    match (&args.exit.name, &args.exit.client_key) {
        (None, Some(_)) => {
            let why = "--client-key is this client's key for --exit NAME: give --exit too";
            Err(crate::relay_settings::Refusal::usage(why))
        }
        _ => Ok(()),
    }
}

/// The exit of `--exit NAME`, with the trust of `--ca-file` for its pair's
/// relay.
fn exit_to(name: &str, args: &ProxyArgs) -> crate::exit::open::To {
    let (name, client_key, ca_file) = (name.to_string(), args.exit.client_key.clone(), args.ca_file.clone());
    crate::exit::open::To { name, client_key, ca_file, ..Default::default() }
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
            // Each relay host failed: the forwarders that the binary names,
            // where the relay was podssh's choice (T-370) and no relay host
            // answered about the target (T-509).
            let code = sysexit(failure.last());
            let answered = crate::forwarder::fallback::answered(&failure);
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
