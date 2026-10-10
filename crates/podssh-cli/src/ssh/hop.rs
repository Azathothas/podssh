//! The hosts of a command line: a destination, a `-J` hop and a `-W`
//! target, each read before anything connects; and the request of a run.

use podssh_ssh::{Hop, Request};

use super::args::SshArgs;
use super::options::{parse_port, Settings};

/// `-W` takes `HOST:PORT` or `[ADDR]:PORT`. OpenSSH reads a value with a `/`
/// as a Unix socket on the server, and refuses a value with no port: a host
/// on port 22 would change the meaning of its command line. A `-J` hop is
/// read elsewhere, where a host alone is port 22, as in OpenSSH.
pub(super) fn stdio_forward_form(target: &str) -> Result<(), String> {
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
pub(super) fn jump_hop(text: &str) -> Result<Hop, String> {
    if text.starts_with(super::node::SCHEME) {
        return Err(format!("-J {text}: a node cannot be a -J hop yet"));
    }
    parse_hop(text)
}

/// A host that a word names: not empty, and not starting with `-`, which a
/// program would read as a flag (OpenSSH refuses it too). The same rule for a
/// destination, a `-J` hop, a `-W` target and `-o HostName`.
pub(super) fn host_rule(original: &str, host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err(format!("{original:?}: no host"));
    }
    if host.starts_with('-') {
        return Err(format!("{original:?}: a host name cannot start with '-'"));
    }
    Ok(())
}

/// The request of a run: `-W`, `-N`, a subsystem, a command or a shell.
pub(super) fn request(args: &SshArgs, settings: &Settings, remote_command: Option<&str>) -> Result<Request, String> {
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
    let command =
        if args.command.is_empty() { remote_command.unwrap_or_default().to_string() } else { args.command.join(" ") };
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
