//! `podssh ssh -G` (T-046): the settings in effect, one `keyword value` line
//! each, as OpenSSH's `ssh -G` prints them, so that a script can compare the
//! two line by line. Only the keywords of OpenSSH that podssh applies are
//! printed, defaults included, in OpenSSH's order; podssh's own settings
//! (relay hosts, `--ca-file`) are not, as OpenSSH knows no such keyword and
//! a line of `-G` must be one that a file of OpenSSH's takes. Nothing
//! connects.

use std::path::{Path, PathBuf};

use podssh_ssh::{Agent, LogLevel, Request, RequestTty, StrictHostKeyChecking};

use super::resolve::Resolved;

/// What `-G` prints that `Options` does not keep as it was given: OpenSSH
/// prints these settings, not what podssh made of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shown {
    /// The destination's host as typed.
    pub host: String,
    /// The host to connect to, lowercased unless it is an address.
    pub hostname: String,
    /// `-4` or `-6`.
    pub family: Option<u8>,
    pub pubkey: bool,
    pub password: bool,
    pub kbd_interactive: bool,
    /// `PreferredAuthentications`, as given.
    pub preferred: Option<String>,
    /// `RemoteCommand`, its tokens expanded as OpenSSH prints it; a command
    /// on the command line is not one.
    pub remote_command: Option<String>,
    /// `-J` or `ProxyJump`, as given.
    pub proxy_jump: Option<String>,
    /// HOME: a path under it is printed with `~`, as OpenSSH prints its
    /// default identity files.
    pub home: Option<PathBuf>,
}

/// The lines of `ssh -G`.
pub fn lines(resolved: &Resolved) -> Vec<String> {
    let (o, s) = (&resolved.options, &resolved.shown);
    let yes = |b: bool| if b { "yes" } else { "no" };
    let mut out = vec![
        format!("host {}", s.host),
        format!("user {}", o.user),
        format!("hostname {}", s.hostname),
        format!("port {}", o.destination.port),
        format!("addressfamily {}", family(s.family)),
        format!("batchmode {}", yes(o.batch_mode)),
        format!("compression {}", yes(o.compression)),
        format!("exitonforwardfailure {}", yes(o.exit_on_forward_failure)),
        format!("identitiesonly {}", yes(o.identities_only)),
        format!("kbdinteractiveauthentication {}", yes(s.kbd_interactive)),
        format!("passwordauthentication {}", yes(s.password)),
        format!("pubkeyauthentication {}", s.pubkey),
        format!("requesttty {}", request_tty(o.request_tty)),
        format!("sessiontype {}", session_type(&o.request)),
        format!("stdinnull {}", yes(o.stdin_null)),
        format!("stricthostkeychecking {}", strict(o.strict_host_key_checking)),
        format!("connectionattempts {}", resolved.connection_attempts),
        format!("numberofpasswordprompts {}", o.password_prompts),
        format!("serveralivecountmax {}", o.keepalive_max),
        format!("serveraliveinterval {}", o.keepalive_interval.map_or(0, |d| d.as_secs())),
    ];
    if let Some(alias) = &o.host_key_alias {
        out.push(format!("hostkeyalias {alias}"));
    }
    match &o.agent {
        Agent::FromEnvironment => {}
        Agent::Off => out.push("identityagent none".into()),
        Agent::Path(path) => out.push(format!("identityagent {}", path.display())),
    }
    if let Some(command) = &s.remote_command {
        out.push(format!("remotecommand {command}"));
    }
    out.push(format!("loglevel {}", log_level(o.log_level)));
    if let Some(list) = &s.preferred {
        out.push(format!("preferredauthentications {list}"));
    }
    // OpenSSH writes a port alone when no address was given, and each host
    // in brackets.
    for f in &o.remote_forwards {
        let listen = match &f.bind {
            None => f.port.to_string(),
            Some(bind) => format!("[{bind}]:{}", f.port),
        };
        out.push(format!("remoteforward {listen} [{}]:{}", f.host, f.host_port));
    }
    for file in &o.identity_files {
        out.push(format!("identityfile {}", shown_path(file, s.home.as_deref())));
    }
    out.push(format!("globalknownhostsfile {}", files(&o.global_known_hosts)));
    out.push(format!("userknownhostsfile {}", files(&o.user_known_hosts)));
    out.extend(o.send_env.iter().map(|pattern| format!("sendenv {pattern}")));
    out.extend(o.set_env.iter().map(|(name, value)| format!("setenv {name}={value}")));
    out.push(format!("connecttimeout {}", o.connect_timeout.as_secs()));
    out.push(format!("escapechar {}", escape_char(o.escape_char)));
    if let Some(jump) = &s.proxy_jump {
        out.push(format!("proxyjump {jump}"));
    }
    out
}

fn family(family: Option<u8>) -> &'static str {
    match family {
        Some(4) => "inet",
        Some(6) => "inet6",
        _ => "any",
    }
}

/// OpenSSH prints yes and no of this keyword as true and false.
fn request_tty(tty: RequestTty) -> &'static str {
    match tty {
        RequestTty::Auto => "auto",
        RequestTty::Yes => "true",
        RequestTty::No => "false",
        RequestTty::Force => "force",
    }
}

fn session_type(request: &Request) -> &'static str {
    match request {
        Request::Nothing => "none",
        Request::Subsystem(_) => "subsystem",
        _ => "default",
    }
}

/// OpenSSH prints yes and no of this keyword as true and false.
fn strict(policy: StrictHostKeyChecking) -> &'static str {
    match policy {
        StrictHostKeyChecking::Yes => "true",
        StrictHostKeyChecking::No => "false",
        StrictHostKeyChecking::AcceptNew => "accept-new",
        StrictHostKeyChecking::Ask => "ask",
    }
}

/// OpenSSH's names; DEBUG1 is printed DEBUG, as OpenSSH prints it.
fn log_level(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Quiet => "QUIET",
        LogLevel::Fatal => "FATAL",
        LogLevel::Error => "ERROR",
        LogLevel::Info => "INFO",
        LogLevel::Verbose => "VERBOSE",
        LogLevel::Debug1 => "DEBUG",
        LogLevel::Debug2 => "DEBUG2",
        LogLevel::Debug3 => "DEBUG3",
    }
}

/// A control character as `\^X`, as OpenSSH prints it.
fn escape_char(c: Option<u8>) -> String {
    match c {
        None => "none".into(),
        Some(c) if c < 0x20 => format!("\\^{}", (c + 0x40) as char),
        Some(c) => (c as char).to_string(),
    }
}

/// The files, in one line, as OpenSSH prints them: expanded; `none` for
/// none.
fn files(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "none".into();
    }
    paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(" ")
}

/// An identity file under HOME as `~/...` with `/`, as OpenSSH prints its
/// defaults; another as it is.
fn shown_path(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|home| path.strip_prefix(home).ok()) {
        Some(rest) if !rest.as_os_str().is_empty() => {
            let parts: Vec<String> = rest.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
            format!("~/{}", parts.join("/"))
        }
        _ => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_spelled_as_openssh_prints_them() {
        assert_eq!(escape_char(Some(1)), "\\^A");
        assert_eq!(escape_char(Some(b'~')), "~");
        assert_eq!(escape_char(None), "none");
        let home = Path::new("/home/u");
        assert_eq!(shown_path(&home.join(".ssh").join("id_rsa"), Some(home)), "~/.ssh/id_rsa");
        assert_eq!(shown_path(Path::new("/tmp/k"), Some(home)), "/tmp/k");
        assert_eq!(files(&[]), "none");
        assert_eq!(log_level(LogLevel::Debug1), "DEBUG");
    }
}
