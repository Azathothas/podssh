//! From the command line to a connection: destination, user, files, request,
//! transport. Everything is decided here, before anything connects, so a bad
//! command line fails at once with a usage error.

use std::path::PathBuf;
use std::time::Duration;

use podssh_ssh::{Hop, LogLevel, Options, Request, RequestTty};
use podssh_ws::Trust;

use podssh_relay::failover::Mode;
use podssh_relay::relay::{self, RelayList};

use super::args::SshArgs;
use super::hop::{host_rule, request};
use super::options::{parse_port, Settings};
use super::tokens::{jump_token, lower_host, Tokens, USER_REFUSES};
use crate::relay_settings::Refusal;

// Its old home, for the callers that name it here.
pub use super::hop::parse_hop;

/// How the first hop is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Through the relay hosts, in order; `family` is 4 or 6 when one was
    /// asked for.
    Relay { relays: RelayList, trust: Trust, family: Option<u8>, failover: Mode },
    /// A TCP connection, through `HTTPS_PROXY` when one is set (`--direct`).
    Direct,
    /// The node of a pair, through the operator's leg of the reverse road
    /// (`node://NAME`, T-084); raced with its iroh road when `race` names
    /// one (T-164).
    Node {
        label: String,
        pair_file: Option<String>,
        trust: Trust,
        race: Option<super::iroh::Race>,
        channel: crate::channel::Ask,
    },
    /// A node over the iroh road (`iroh:TICKET`, T-163), with this client's
    /// key file when `--iroh-key` names one, and the relays to try after the
    /// ticket's (T-165).
    Iroh { ticket: String, key: Option<String>, relays: Vec<String>, trust: Trust, channel: crate::channel::Ask },
    /// The service that `cloudflared` publishes under `host`, over its
    /// WebSocket (`cf://HOST`, T-264).
    Cloudflare { host: String, trust: Trust },
}

/// A command line, resolved.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub options: Options,
    pub transport: Transport,
    pub log_file: Option<PathBuf>,
    /// Rounds over the relay hosts, or dials with `--direct`
    /// (`ConnectionAttempts`, 1 by default as in OpenSSH).
    pub connection_attempts: u32,
    /// Notes for the log once it exists (ignored options and the like),
    /// shown with -v.
    pub notes: Vec<String>,
    /// Warnings the user should see without -v.
    pub warnings: Vec<String>,
    /// `--persist`: what a new connection after a loss keeps (T-178, T-042).
    pub persist: Option<super::persist::Kept>,
    /// What `-G` prints as it was given.
    pub shown: super::dump::Shown,
    /// `-L` and `-D` (T-038), bound before anything connects, and whether
    /// one with no address listens on each address (`-g`, `GatewayPorts`).
    pub local: Vec<super::local_spec::LocalSpec>,
    pub gateway_ports: bool,
    /// `-M`, `-S`, `-O` and the control keywords (T-039).
    pub control: super::control::Plan,
    /// `--record FILE` (T-033), made as the run starts.
    pub record: Option<PathBuf>,
    /// `-X` and `-Y` (T-037), probed as the run starts.
    pub x11: Option<super::x11::Plan>,
    /// `--upgrade` (T-167): what the move to a temporary node needs.
    pub upgrade: Option<super::upgrade::Upgrade>,
}

/// What the process environment contributes, gathered once so it can be
/// replaced in tests.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub home: Option<PathBuf>,
    pub user: Option<String>,
    pub relay: Option<String>,
    /// `PODSSH_RELAY_FAILOVER` (T-220).
    pub relay_failover: Option<String>,
    pub ssl_cert_file: Option<String>,
    /// The local host name and user id, for the `%` tokens.
    pub local_host: Option<String>,
    pub uid: Option<u32>,
    /// `PODSSH_SSH_CONFIG`: the file of `-F`, when `-F` is not given.
    pub ssh_config: Option<String>,
    /// The system's `ssh_config`, read after `~/.ssh/config`; `None` reads
    /// none, as in the tests.
    pub system_config: Option<PathBuf>,
    /// podssh's own settings file (T-048); none in the tests.
    pub settings: crate::settings::Defaults,
}

impl Env {
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let home = var("HOME").or_else(|| if cfg!(windows) { var("USERPROFILE") } else { None }).map(PathBuf::from);
        let user = var("USER").or_else(|| var("LOGNAME")).or_else(|| var("USERNAME")).or_else(uid_zero_is_root);
        Env {
            home,
            user,
            relay: var(relay::RELAY_ENV),
            relay_failover: var(podssh_relay::failover::MODE_ENV),
            ssl_cert_file: var("SSL_CERT_FILE"),
            local_host: super::tokens::local_host_name(),
            uid: super::tokens::local_uid(),
            ssh_config: var("PODSSH_SSH_CONFIG"),
            system_config: Some(super::config::system_file()),
            settings: crate::settings::here().clone(),
        }
    }
}

/// The CA file: `--ca-file`, else `SSL_CERT_FILE`, else the settings
/// file's `CaFile` (T-048).
pub(super) fn ca_file(args: &SshArgs, env: &Env) -> Option<String> {
    crate::settings::ca_file_from(args.ca_file.as_deref(), env.ssl_cert_file.clone(), &env.settings)
}

/// With no user name in the environment, uid 0 is `root` by convention; any
/// other uid has no name podssh may assume (never `getpwuid`: hosts without a
/// passwd entry make OpenSSH fail exactly there).
#[cfg(unix)]
fn uid_zero_is_root() -> Option<String> {
    // SAFETY: getuid has no preconditions.
    (unsafe { libc::getuid() } == 0).then(|| "root".to_string())
}

#[cfg(not(unix))]
fn uid_zero_is_root() -> Option<String> {
    None
}

/// Resolve `args`; `Err` is the message of a refusal.
pub fn resolve(args: &SshArgs, env: &Env) -> Result<Resolved, String> {
    resolve_or_refuse(args, env).map_err(|refusal| refusal.message)
}

/// Resolve `args`; `Err` is a refusal with its exit code: 64 for the command
/// line, 78 for a bad `PODSSH_RELAY`.
pub fn resolve_or_refuse(args: &SshArgs, env: &Env) -> Result<Resolved, Refusal> {
    let mut settings = Settings::default();
    for raw in args.options.iter().chain(&args.long_options) {
        settings.apply(raw)?;
    }
    let destination = args.destination.as_deref().ok_or("missing destination: podssh ssh [user@]host [command]")?;
    let node = super::node::destination(destination)?;
    let iroh = super::iroh::destination(destination)?;
    let tunnel = super::cloudflare::destination(destination)?;
    let target = match (&node, &iroh, &tunnel) {
        (Some((user, label, _)), ..) => Hop { user: user.clone(), host: label.clone(), port: 22 },
        (None, Some(dest), _) => Hop { user: dest.user.clone(), host: dest.shown.clone(), port: 22 },
        (None, None, Some((user, host))) => Hop { user: user.clone(), host: host.clone(), port: 22 },
        (None, None, None) => parse_hop(destination)?,
    };
    if args.iroh_ticket.is_some() && node.is_none() {
        return Err("--iroh-ticket is for a node://NAME destination, whose pair it races with".into());
    }
    let iroh_road = iroh.is_some() || args.iroh_ticket.is_some();
    if args.iroh_relay.is_some() && !iroh_road {
        return Err("--iroh-relay is for an iroh:TICKET destination, or --iroh-ticket".into());
    }
    // The channel's flags are for a destination of two podssh ends (T-087);
    // --upgrade takes this client's key for its temporary node (T-167).
    let channel = [
        ("--client-key", args.client_key.is_some() && !args.upgrade),
        ("--iroh-key", args.iroh_key.is_some() && !args.upgrade),
        ("--node-key", args.node_key.is_some()),
        ("--no-e2e", args.no_e2e),
    ];
    if let Some((flag, _)) = channel.iter().find(|(_, given)| *given).filter(|_| node.is_none() && iroh.is_none()) {
        return Err(format!("{flag} is for a node://NAME or iroh:TICKET destination").into());
    }
    let fingerprints = args
        .host_key_fingerprint
        .as_deref()
        .map(podssh_ssh::hostkey::parse_fingerprints)
        .transpose()?
        .unwrap_or_default();
    // The file's blocks for the host as typed (T-043): under the command
    // line, but for `User` and `Port`, which `user@host` and `host:PORT`
    // also beat.
    let source = super::config::file(args.config.as_deref(), env.ssh_config.as_deref(), env.home.as_deref());
    let so_far = |file: &Settings| super::tokens::include_tokens(args, &settings, &target, env, file);
    let ctx = super::config::Context {
        host: &target.host,
        home: env.home.as_deref(),
        system: env.system_config.as_deref(),
        tokens: &so_far,
        given: super::config::Given {
            host_name: settings.host_name.as_deref(),
            user: args.login.as_deref().or(settings.user.as_deref()).or(target.user.as_deref()),
            local_user: env.user.as_deref(),
            tag: args.tag.as_deref().or(settings.tag.as_deref()),
            command: args.command.join(" "),
            session: match (args.no_command || args.stdio_forward.is_some(), args.subsystem) {
                (true, _) => Some("none"),
                (false, true) => Some("subsystem"),
                (false, false) => settings.session_type.as_deref(),
            },
        },
    };
    let filed = super::config::read(&source, &ctx, settings.ignore_unknown.clone()).map_err(Refusal::config)?;
    let (file_user, file_port) = (filed.user.clone(), filed.port);
    // Each hop of -J reads its own blocks, under these (T-290).
    let cli = settings.clone();
    let settings = settings.then_file(filed);
    let host = match settings.host_name.as_deref() {
        Some(name) => {
            let name = super::tokens::host_name(name, &target.host)?;
            host_rule(&format!("HostName={name}"), &name)?;
            name
        }
        None => target.host.clone(),
    };
    let port = match &args.port {
        Some(p) => parse_port(p).ok_or_else(|| format!("-p {p}: not a port"))?,
        None => settings.port.or(Some(target.port).filter(|p| *p != 22)).or(file_port).unwrap_or(22),
    };
    let proxy_jump = args.jump.as_deref().or(settings.proxy_jump.as_deref());
    let (jump, jump_options) = match proxy_jump {
        None | Some("none") => (Vec::new(), Vec::new()),
        Some(list) => super::jump::hops(list, args, &cli, env)?,
    };

    // The `%` tokens, with OpenSSH's values for this connection; `%r` once
    // the user is known.
    let mut tokens = Tokens {
        home: env.home.clone(),
        host: lower_host(&host),
        original: target.host.clone(),
        port,
        remote_user: String::new(),
        local_user: env.user.clone(),
        local_host: env.local_host.clone(),
        uid: env.uid,
        alias: settings.host_key_alias.as_deref().map(str::to_ascii_lowercase).unwrap_or_else(|| target.host.clone()),
        jump: jump_token(proxy_jump),
    };
    // OpenSSH expands a `User` of `-o` or of a file, and takes `-l` and
    // `user@host` as they are.
    let user = match (&args.login, &settings.user, &target.user, &file_user) {
        (Some(login), ..) => login.clone(),
        (None, Some(user), ..) => tokens.text("-o User=", user, USER_REFUSES)?,
        (None, None, Some(user), _) => user.clone(),
        (None, None, None, Some(user)) => tokens.text("User ", user, USER_REFUSES)?,
        (None, None, None, None) => env.user.clone().ok_or("no user name: give one with user@host or -l USER")?,
    };
    tokens.remote_user = user.clone();
    let remote_command =
        settings.remote_command.as_deref().map(|c| tokens.text("RemoteCommand ", c, &[])).transpose()?;
    let expand = |setting: &str, p: &str| tokens.expand(setting, p);
    let login = super::login::login(&args.identity_files, &settings, &tokens, env)?;

    let request = request(args, &settings, remote_command.as_deref())?;
    let request_tty = if matches!(request, Request::StdioForward(_) | Request::Nothing) || args.no_tty {
        RequestTty::No
    } else {
        match args.tty {
            0 => settings.request_tty.unwrap_or(RequestTty::Auto),
            1 => RequestTty::Yes,
            _ => RequestTty::Force,
        }
    };
    let escape_char = match &args.escape_char {
        Some(e) => podssh_ssh::escape::parse_escape_char(e)
            .ok_or_else(|| format!("-e {e}: expected none, a character or ^X"))?,
        None => settings.escape_char.unwrap_or(Some(b'~')),
    };
    let agents = super::agents::choose(args.forward_agent, &settings, &expand)?;
    let control = super::control::plan(args, &settings, &expand)?;
    let mut log_level = settings.log_level.unwrap_or(LogLevel::Info);
    if args.quiet > 0 {
        log_level = LogLevel::Quiet;
    } else if args.verbose > 0 {
        log_level = log_level.max(LogLevel::from_flags(args.verbose, 0));
    }

    let family = match (args.ipv4, args.ipv6, settings.address_family) {
        (true, true, _) => return Err("-4 and -6 cannot be used together".into()),
        (true, _, _) => Some(4),
        (_, true, _) => Some(6),
        (_, _, Some(4)) => Some(4),
        (_, _, Some(6)) => Some(6),
        _ => None,
    };
    let first = jump.first().map(|h| h.host.clone()).unwrap_or_else(|| host.clone());
    let ask = |label, route| super::node::Ask {
        label,
        route,
        args,
        host_name: settings.host_name.is_some(),
        port: args.port.is_some() || settings.port.is_some(),
        jumps: jump.len(),
        family,
        forward: matches!(request, Request::StdioForward(_)),
    };
    let transport = if let Some((_, label, route)) = &node {
        let race = super::iroh::race(args)?;
        super::node::transport(&ask(label, route.as_deref()), env, race)?
    } else if let Some(dest) = &iroh {
        let trust = match ca_file(args, env) {
            Some(file) => Trust::File(file.into()),
            None => Trust::Default,
        };
        super::iroh::transport(dest, &ask(&dest.shown, None), trust)?
    } else if let Some((_, host)) = &tunnel {
        super::cloudflare::transport(&ask(host, None), env)?
    } else if args.direct {
        if family.is_some() {
            return Err(
                "-4/-6 select the address family the relay dials; with --direct they are not supported yet".into()
            );
        }
        Transport::Direct
    } else {
        let relays = crate::relay_settings::relays_from(args.relay_host.as_deref(), env.relay.clone(), &env.settings)?;
        let failover = crate::relay_settings::failover_from(
            args.relay_failover.as_deref(),
            env.relay_failover.clone(),
            &env.settings,
        )?;
        relay::check_target(&first).map_err(|why| format!("cannot reach {first} through the relay: {why}"))?;
        // The relay dials a literal as it is; a family of the other kind
        // cannot apply to it.
        match family {
            Some(4) if relay::is_ipv6_literal(&first) => {
                return Err(format!("-4 asks the relay for IPv4, but {first} is an IPv6 address").into())
            }
            Some(6) if first.parse::<std::net::Ipv4Addr>().is_ok() => {
                return Err(format!("-6 asks the relay for IPv6, but {first} is an IPv4 address").into())
            }
            _ => {}
        }
        let trust = match ca_file(args, env) {
            Some(file) => Trust::File(file.into()),
            None => Trust::Default,
        };
        Transport::Relay { relays, trust, family, failover }
    };

    // A node runs the resumable layer, whose heartbeat finds a dead link and
    // keeps the relay's idle cut away; SSH's own keepalives would end a
    // session that the layer carries onto a new link (T-154).
    let resumable = matches!(transport, Transport::Node { .. } | Transport::Iroh { .. });
    let keepalive_interval = match settings.alive_interval {
        Some(0) => None,
        Some(s) => Some(Duration::from_secs(s)),
        None if resumable => None,
        None => Some(Duration::from_secs(60)),
    };
    let notes: Vec<String> = settings.ignored.iter().map(|k| format!("-o {k} has no effect in podssh")).collect();
    let mut warnings: Vec<String> = agents.warning.clone().into_iter().collect();
    let idle = relay::RELAY_IDLE_SECS;
    if resumable {
        if keepalive_interval.is_some() {
            warnings.push(
                "ServerAliveInterval ends the session after ServerAliveCountMax keepalives with no answer, also \
                 while the resumable layer would carry it onto a new link"
                    .to_string(),
            );
        }
    } else if matches!(transport, Transport::Relay { .. }) && keepalive_interval.is_none_or(|d| d.as_secs() >= idle) {
        warnings.push(format!(
            "ServerAliveInterval is off or at least {idle} s: the relay closes a connection after {idle} s without traffic"
        ));
    }

    // OpenSSH opens -E FILE with the name as typed.
    let log_file = args.log_file.as_deref().map(PathBuf::from);
    // A node is named `node://NAME` in the messages and the known hosts; a
    // node of the iroh road, `iroh:` and its key.
    let shown = match (&node, &iroh) {
        (Some((_, label, route)), _) => super::node::shown(label, route.as_deref()),
        (None, Some(dest)) => dest.shown.clone(),
        (None, None) => host.clone(),
    };
    let mut options = Options::new(Hop { user: None, host: shown, port }, user.clone());
    // OpenSSH looks a host key up, and records it, under the alias in lowercase.
    options.host_key_alias = settings.host_key_alias.as_deref().map(str::to_ascii_lowercase);
    options.jump = jump;
    options.jump_options = jump_options;
    for hop in &mut options.jump_options {
        hop.log_level = log_level;
    }
    login.apply(&mut options, &settings);
    options.agent = agents.identity.clone();
    options.forward_agent = agents.forward.clone();
    options.host_key_fingerprints = fingerprints;
    options.keepalive_interval = keepalive_interval;
    options.request = request;
    options.request_tty = request_tty;
    options.escape_char = escape_char;
    options.set_env = settings.set_env.clone();
    options.send_env = settings.send_env.clone();
    options.compression = args.compression || settings.compression.unwrap_or(false);
    options.log_level = log_level;
    options.stdin_null = args.stdin_null || settings.stdin_null.unwrap_or(false);
    let forwards = super::local_spec::forwards(args, &settings, matches!(options.request, Request::StdioForward(_)))?;
    options.remote_forwards = forwards.remote;
    options.exit_on_forward_failure = settings.exit_on_forward_failure.unwrap_or(false);
    let shown = super::dump::Shown {
        host: target.host.clone(),
        hostname: lower_host(&host),
        family,
        pubkey: settings.pubkey.unwrap_or(true),
        password: settings.password.unwrap_or(true),
        kbd_interactive: settings.kbd_interactive.unwrap_or(true),
        preferred: settings.preferred_auth.as_ref().map(|m| m.iter().map(|m| m.name()).collect::<Vec<_>>().join(",")),
        remote_command,
        proxy_jump: proxy_jump.filter(|j| *j != "none").map(str::to_string),
        home: env.home.clone(),
        identity_agent: agents.shown_identity,
        forward_agent: agents.shown_forward,
        clear_all_forwardings: forwards.cleared,
        tag: args.tag.clone().or_else(|| settings.tag.clone()),
    };
    let mut resolved = Resolved {
        options,
        transport,
        log_file,
        connection_attempts: settings.connection_attempts.unwrap_or(1),
        notes,
        warnings,
        persist: None,
        shown,
        local: forwards.local,
        gateway_ports: args.gateway_ports || settings.gateway_ports.unwrap_or(false),
        control,
        record: None,
        x11: None,
        upgrade: None,
    };
    super::persist::check(args, &mut resolved)?;
    super::upgrade::check(args, env, &mut resolved)?;
    super::elevate::check(args, &mut resolved)?;
    super::recording::check(args, &mut resolved)?;
    super::attach::check(args, &mut resolved)?;
    // X11 goes on a session alone, as OpenSSH asks for it; a run with it
    // makes a connection of its own, as a master's session would not ask.
    if !matches!(resolved.options.request, Request::StdioForward(_) | Request::Nothing) {
        resolved.x11 = super::x11::plan(args, &settings);
    }
    if resolved.x11.is_some() && resolved.control.path.take().is_some() {
        resolved.notes.push("X11 forwarding makes a connection of its own: ControlPath has no effect".into());
    }
    Ok(resolved)
}
