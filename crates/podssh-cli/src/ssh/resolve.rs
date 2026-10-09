//! From the command line to a connection: destination, user, files, request,
//! transport. Everything is decided here, before anything connects, so a bad
//! command line fails at once with a usage error.

use std::path::PathBuf;
use std::time::Duration;

use podssh_ssh::options::{default_global_known_hosts, default_identity_files, default_user_known_hosts};
use podssh_ssh::{Agent, Hop, LogLevel, Method, Options, Request, RequestTty, StrictHostKeyChecking};
use podssh_ws::Trust;

use podssh_relay::relay::{self, RelayList};

use super::args::SshArgs;
use super::options::{parse_port, Settings};
use super::tokens::{lower_host, Tokens};
use crate::relay_settings::Refusal;

/// How the first hop is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Through the relay hosts, in order; `family` is 4 or 6 when one was
    /// asked for.
    Relay { relays: RelayList, trust: Trust, family: Option<u8> },
    /// A TCP connection, through `HTTPS_PROXY` when one is set (`--direct`).
    Direct,
    /// The node of a pair, through the operator's leg of the reverse road
    /// (`node://NAME`, T-084).
    Node { label: String, pair_file: Option<String>, trust: Trust },
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
}

/// What the process environment contributes, gathered once so it can be
/// replaced in tests.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub home: Option<PathBuf>,
    pub user: Option<String>,
    pub relay: Option<String>,
    pub ssl_cert_file: Option<String>,
    /// The local host name and user id, for the `%` tokens.
    pub local_host: Option<String>,
    pub uid: Option<u32>,
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
            ssl_cert_file: var("SSL_CERT_FILE"),
            local_host: super::tokens::local_host_name(),
            uid: super::tokens::local_uid(),
        }
    }
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
    match args.config.as_deref() {
        None | Some("none") | Some("/dev/null") | Some("NUL") => {}
        Some(file) => {
            return Err(Refusal::usage(format!(
                "-F {file}: reading ssh_config files is not implemented yet; pass the settings with -o NAME=VALUE (-F none is accepted)"
            )))
        }
    }
    let mut settings = Settings::default();
    for raw in args.options.iter().chain(&args.long_options) {
        settings.apply(raw)?;
    }
    let destination = args.destination.as_deref().ok_or("missing destination: podssh ssh [user@]host [command]")?;
    let node = super::node::destination(destination)?;
    let target = match &node {
        Some((user, label)) => Hop { user: user.clone(), host: label.clone(), port: 22 },
        None => parse_hop(destination)?,
    };
    let host = match settings.host_name.clone() {
        Some(name) => {
            host_rule(&format!("HostName={name}"), &name)?;
            name
        }
        None => target.host.clone(),
    };
    let port = match &args.port {
        Some(p) => parse_port(p).ok_or_else(|| format!("-p {p}: not a port"))?,
        None => settings.port.or(Some(target.port).filter(|p| *p != 22)).unwrap_or(22),
    };
    let user = args
        .login
        .clone()
        .or_else(|| settings.user.clone())
        .or_else(|| target.user.clone())
        .or_else(|| env.user.clone())
        .ok_or("no user name: give one with user@host or -l USER")?;
    let proxy_jump = args.jump.as_deref().or(settings.proxy_jump.as_deref());
    let jump: Vec<Hop> = match proxy_jump {
        None | Some("none") => Vec::new(),
        Some(list) => list.split(',').map(|h| jump_hop(h.trim())).collect::<Result<_, _>>()?,
    };

    // The `%` tokens, with OpenSSH's values for this connection.
    let tokens = Tokens {
        home: env.home.clone(),
        host: lower_host(&host),
        original: target.host.clone(),
        port,
        remote_user: user.clone(),
        local_user: env.user.clone(),
        local_host: env.local_host.clone(),
        uid: env.uid,
        alias: settings.host_key_alias.as_deref().map(str::to_ascii_lowercase).unwrap_or_else(|| target.host.clone()),
        jump: match proxy_jump {
            Some("none") => "none".into(),
            _ => jump.last().map(|h| h.host.clone()).unwrap_or_default(),
        },
    };
    let expand = |setting: &str, p: &str| tokens.expand(setting, p);
    let mut identity_files: Vec<PathBuf> = args
        .identity_files
        .iter()
        .map(|p| expand("-i ", p))
        .chain(settings.identity_files.iter().map(|p| expand("-o IdentityFile=", p)))
        .collect::<Result<_, _>>()?;
    if identity_files.is_empty() {
        identity_files = env.home.as_deref().map(default_identity_files).unwrap_or_default();
    }
    let known = |setting: &str, list: &Option<Vec<String>>, default: Vec<PathBuf>| -> Result<Vec<PathBuf>, String> {
        Ok(match list {
            Some(files) if files.iter().any(|f| f.eq_ignore_ascii_case("none")) => Vec::new(),
            Some(files) => files.iter().map(|f| expand(setting, f)).collect::<Result<_, _>>()?,
            None => default,
        })
    };
    let user_known_hosts = known(
        "-o UserKnownHostsFile=",
        &settings.user_known_hosts,
        env.home.as_deref().map(default_user_known_hosts).unwrap_or_default(),
    )?;
    let global_known_hosts =
        known("-o GlobalKnownHostsFile=", &settings.global_known_hosts, default_global_known_hosts())?;

    let mut methods = settings
        .preferred_auth
        .clone()
        .unwrap_or_else(|| vec![Method::PublicKey, Method::KeyboardInteractive, Method::Password]);
    methods.retain(|m| match m {
        Method::PublicKey => settings.pubkey != Some(false),
        Method::Password => settings.password != Some(false),
        Method::KeyboardInteractive => settings.kbd_interactive != Some(false),
    });
    let publickey_off = match (methods.contains(&Method::PublicKey), settings.pubkey) {
        (true, _) => None,
        (false, Some(false)) => Some("-o PubkeyAuthentication=no".to_string()),
        (false, _) => Some("PreferredAuthentications does not list publickey".to_string()),
    };

    let request = request(args, &settings)?;
    let request_tty = if matches!(request, Request::StdioForward { .. } | Request::Nothing) || args.no_tty {
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
    let agent = match settings.identity_agent.as_deref() {
        None | Some("SSH_AUTH_SOCK") => Agent::FromEnvironment,
        Some(v) if v.eq_ignore_ascii_case("none") => Agent::Off,
        Some(path) => Agent::Path(expand("-o IdentityAgent=", path)?),
    };
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
    let transport = if let Some((_, label)) = &node {
        let ask = super::node::Ask {
            label,
            args,
            host_name: settings.host_name.is_some(),
            port: args.port.is_some() || settings.port.is_some(),
            jumps: jump.len(),
            family,
            forward: matches!(request, Request::StdioForward { .. }),
        };
        super::node::transport(&ask, env)?
    } else if args.direct {
        if family.is_some() {
            return Err(
                "-4/-6 select the address family the relay dials; with --direct they are not supported yet".into()
            );
        }
        Transport::Direct
    } else {
        let relays = crate::relay_settings::relays(args.relay_host.as_deref(), env.relay.clone())?;
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
        let trust = match args.ca_file.clone().or_else(|| env.ssl_cert_file.clone()) {
            Some(file) => Trust::File(file.into()),
            None => Trust::Default,
        };
        Transport::Relay { relays, trust, family }
    };

    let keepalive_interval = match settings.alive_interval {
        Some(0) => None,
        Some(s) => Some(Duration::from_secs(s)),
        None => Some(Duration::from_secs(60)),
    };
    let notes: Vec<String> = settings.ignored.iter().map(|k| format!("-o {k} has no effect in podssh")).collect();
    let mut warnings = Vec::new();
    let idle = relay::RELAY_IDLE_SECS;
    if matches!(transport, Transport::Relay { .. } | Transport::Node { .. })
        && keepalive_interval.is_none_or(|d| d.as_secs() >= idle)
    {
        warnings.push(format!(
            "ServerAliveInterval is off or at least {idle} s: the relay closes a connection after {idle} s without traffic"
        ));
    }

    // OpenSSH opens -E FILE with the name as typed.
    let log_file = args.log_file.as_deref().map(PathBuf::from);
    // A node is named `node://NAME` in the messages and the known hosts.
    let shown = match &node {
        Some((_, label)) => format!("{}{label}", super::node::SCHEME),
        None => host.clone(),
    };
    let mut options = Options::new(Hop { user: None, host: shown, port }, user.clone());
    options.host_key_alias = settings.host_key_alias.clone();
    options.jump = jump;
    options.identity_files = identity_files;
    options.identities_only = settings.identities_only.unwrap_or(false);
    options.agent = agent;
    options.strict_host_key_checking = settings.strict.unwrap_or(StrictHostKeyChecking::Ask);
    options.user_known_hosts = user_known_hosts;
    options.global_known_hosts = global_known_hosts;
    options.batch_mode = settings.batch_mode.unwrap_or(false);
    options.methods = methods;
    options.publickey_off = publickey_off;
    options.password_prompts = settings.password_prompts.unwrap_or(3);
    options.keepalive_interval = keepalive_interval;
    options.keepalive_max = settings.alive_count.unwrap_or(3);
    options.connect_timeout = Duration::from_secs(settings.connect_timeout.unwrap_or(60));
    options.request = request;
    options.request_tty = request_tty;
    options.escape_char = escape_char;
    options.set_env = settings.set_env.clone();
    options.send_env = settings.send_env.clone();
    options.compression = args.compression || settings.compression.unwrap_or(false);
    options.log_level = log_level;
    options.stdin_null = args.stdin_null || settings.stdin_null.unwrap_or(false);
    Ok(Resolved {
        options,
        transport,
        log_file,
        connection_attempts: settings.connection_attempts.unwrap_or(1),
        notes,
        warnings,
    })
}

/// `-W` takes `HOST:PORT` or `[ADDR]:PORT`. OpenSSH reads a value with a `/`
/// as a Unix socket on the server, and refuses a value with no port: a host
/// on port 22 would change the meaning of its command line. A `-J` hop is
/// read elsewhere, where a host alone is port 22, as in OpenSSH.
fn stdio_forward_form(target: &str) -> Result<(), String> {
    if target.contains('/') {
        return Err(format!("-W {target}: a Unix socket on the server is not supported yet"));
    }
    let port = match target.strip_prefix('[') {
        Some(rest) => rest.split_once("]:").map(|(_, port)| port),
        None if target.matches(':').count() > 1 => {
            return Err(format!("-W {target}: expected HOST:PORT; an IPv6 address needs brackets: [ADDR]:PORT"))
        }
        None => target.split_once(':').map(|(_, port)| port),
    };
    match port {
        Some(port) if !port.is_empty() => Ok(()),
        _ => Err(format!("-W {target}: expected HOST:PORT")),
    }
}

fn request(args: &SshArgs, settings: &Settings) -> Result<Request, String> {
    if let Some(target) = &args.stdio_forward {
        if !args.command.is_empty() {
            return Err("-W cannot be combined with a remote command".into());
        }
        stdio_forward_form(target)?;
        let hop = parse_hop(target)?;
        if hop.user.is_some() {
            return Err(format!("-W {target}: expected HOST:PORT"));
        }
        return Ok(Request::StdioForward { host: hop.host, port: hop.port });
    }
    let command = if args.command.is_empty() {
        settings.remote_command.clone().unwrap_or_default()
    } else {
        args.command.join(" ")
    };
    if args.no_command || settings.session_type.as_deref() == Some("none") {
        return Ok(Request::Nothing);
    }
    if args.subsystem || settings.session_type.as_deref() == Some("subsystem") {
        if command.trim().is_empty() {
            return Err("-s needs the subsystem name as the command, for example: podssh ssh -s host sftp".into());
        }
        return Ok(Request::Subsystem(command.trim().to_string()));
    }
    Ok(if command.is_empty() { Request::Shell } else { Request::Exec(command) })
}

/// `[user@]host[:port]`, `[user@][v6]:port` or `ssh://[user@]host[:port]`.
/// The `host:port` form is podssh's own (OpenSSH would read it as a host
/// name), because the "did you mean" message suggests it.
pub fn parse_hop(text: &str) -> Result<Hop, String> {
    let original = text;
    let text = text.strip_prefix("ssh://").map(|t| t.trim_end_matches('/')).unwrap_or(text);
    let (user, rest) = match text.rsplit_once('@') {
        Some((u, r)) if !u.is_empty() => (Some(u.to_string()), r),
        Some(_) => return Err(format!("{original:?}: empty user name")),
        None => (None, text),
    };
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (h, after) = inner.split_once(']').ok_or_else(|| format!("{original:?}: unclosed '['"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => parse_port(p).ok_or_else(|| format!("{original:?}: {p:?} is not a port"))?,
            None if after.is_empty() => 22,
            None => return Err(format!("{original:?}: unexpected text after ']'")),
        };
        (h.to_string(), port)
    } else if rest.matches(':').count() == 1 {
        let (h, p) = rest.split_once(':').unwrap_or((rest, "22"));
        (h.to_string(), parse_port(p).ok_or_else(|| format!("{original:?}: {p:?} is not a port"))?)
    } else {
        (rest.to_string(), 22)
    };
    host_rule(original, &host)?;
    Ok(Hop { user, host, port })
}

/// A `-J` hop, which a node cannot be yet.
fn jump_hop(text: &str) -> Result<Hop, String> {
    if text.starts_with(super::node::SCHEME) {
        return Err(format!("-J {text}: a node cannot be a -J hop yet"));
    }
    parse_hop(text)
}

/// A host that a word names: not empty, and not starting with `-`, which a
/// program would read as a flag (OpenSSH refuses it too). The same rule for a
/// destination, a `-J` hop, a `-W` target and `-o HostName`.
fn host_rule(original: &str, host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err(format!("{original:?}: no host"));
    }
    if host.starts_with('-') {
        return Err(format!("{original:?}: a host name cannot start with '-'"));
    }
    Ok(())
}
