//! `-L`, `-D`, `-o LocalForward` and `-o DynamicForward` (T-038), read as
//! OpenSSH 10.3p1's `parse_forward` reads them: fields between colons, a
//! field in brackets taken as it is (an IPv6 address), a backslash that
//! makes the next character plain, and a field with a `/` a socket path.
//! `${NAME}` is a variable. A listening port of 0 is refused, as OpenSSH
//! refuses it, and so is a port that is not a number: OpenSSH also looks a
//! name up in the services database, which podssh does not assume.

use podssh_ssh::local::Target;
use podssh_ssh::RemoteForward;

use super::args::SshArgs;
use super::options::Settings;

/// Where a forward listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listen {
    /// `[bind_address:]port`. `None` is the default address: loopback, or
    /// each address with `-g`; `""` and `*` are each address; `localhost`
    /// is loopback; another is that address.
    Port { bind: Option<String>, port: u16 },
    /// A socket path.
    Path(String),
}

/// One forward, as given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSpec {
    pub listen: Listen,
    pub target: Target,
    /// The flag or the keyword, and the spec, for lines: `-L 8080:db:5432`.
    pub shown: String,
}

impl LocalSpec {
    /// The line of `-G`, as OpenSSH prints it: `localforward 8080 [db]:5432`.
    pub fn dumped(&self) -> String {
        let listen = match &self.listen {
            Listen::Path(path) => path.clone(),
            Listen::Port { bind: None, port } => port.to_string(),
            Listen::Port { bind: Some(bind), port } => format!("[{bind}]:{port}"),
        };
        match &self.target {
            Target::Socks => format!("dynamicforward {listen}"),
            Target::Tcp { host, port } => format!("localforward {listen} [{host}]:{port}"),
            Target::Socket(path) => format!("localforward {listen} {path}"),
        }
    }
}

/// The forwards of a run.
#[derive(Debug)]
pub struct Forwards {
    pub remote: Vec<RemoteForward>,
    pub local: Vec<LocalSpec>,
    /// `ClearAllForwardings`, given or implied by `-W`: what `-G` prints.
    pub cleared: bool,
}

/// `-R`, `-L` and `-D` from the command line, then those of the keywords,
/// as OpenSSH keeps them; none with `ClearAllForwardings yes`, or with `-W`
/// (`stdio`), which implies it in OpenSSH. Each is read first, so a bad one
/// is refused all the same.
pub fn forwards(args: &SshArgs, settings: &Settings, stdio: bool) -> Result<Forwards, String> {
    let remote = super::forward::remote_forwards(&args.remote_forwards, &settings.remote_forwards)?;
    let mut local_forwards = args
        .local_forwards
        .iter()
        .map(|spec| local(spec))
        .chain(args.dynamic_forwards.iter().map(|spec| dynamic(spec)))
        .collect::<Result<Vec<_>, _>>()?;
    local_forwards.extend(settings.local_forwards.iter().cloned());
    let cleared = stdio || settings.clear_all_forwardings == Some(true);
    if cleared {
        return Ok(Forwards { remote: Vec::new(), local: Vec::new(), cleared });
    }
    Ok(Forwards { remote, local: local_forwards, cleared })
}

/// `-L SPEC`.
pub fn local(spec: &str) -> Result<LocalSpec, String> {
    read("-L ", spec, spec, false)
}

/// `-D SPEC`.
pub fn dynamic(spec: &str) -> Result<LocalSpec, String> {
    read("-D ", spec, spec, true)
}

/// `-o LocalForward=LISTEN TARGET`: the keyword's two arguments, as
/// ssh_config writes them.
pub fn local_keyword(value: &str) -> Result<LocalSpec, String> {
    match value.split_whitespace().collect::<Vec<_>>().as_slice() {
        [listen, target] => read("-o LocalForward=", value, &format!("{listen}:{target}"), false),
        _ => Err(format!("-o LocalForward={value}: expected [bind_address:]port host:hostport")),
    }
}

/// `-o DynamicForward=[bind_address:]port`.
pub fn dynamic_keyword(value: &str) -> Result<LocalSpec, String> {
    read("-o DynamicForward=", value, value.trim(), true)
}

/// `spec`, which `setting` and `given` name in a refusal and in `shown`.
fn read(setting: &str, given: &str, spec: &str, dynamic: bool) -> Result<LocalSpec, String> {
    let expanded = super::tokens::variables(setting, given, spec)?;
    let (listen, target) = parse(expanded.trim_start(), dynamic).map_err(|why| format!("{setting}{given}: {why}"))?;
    Ok(LocalSpec { listen, target, shown: format!("{setting}{given}") })
}

/// A field between colons, and whether it is a socket path.
struct Field {
    text: String,
    path: bool,
}

fn parse(spec: &str, dynamic: bool) -> Result<(Listen, Target), String> {
    let fields = fields(spec).ok_or("a bracket that is not closed, a \\ at the end, or more than four fields")?;
    let port = |f: &Field| f.text.parse::<u16>().map_err(|_| format!("{:?} is not a port", f.text));
    let text = |f: &Field| f.text.clone();
    let tcp = |host: &Field, to: &Field| Ok::<_, String>(Target::Tcp { host: text(host), port: port(to)? });
    let (listen, target) = match fields.as_slice() {
        [a] if a.path => (Listen::Path(text(a)), Target::Socks),
        [a] => (Listen::Port { bind: None, port: port(a)? }, Target::Socks),
        [a, b] if a.path && b.path => (Listen::Path(text(a)), Target::Socket(text(b))),
        [a, b] if b.path => (Listen::Port { bind: None, port: port(a)? }, Target::Socket(text(b))),
        [a, b] => (Listen::Port { bind: Some(text(a)), port: port(b)? }, Target::Socks),
        [a, b, c] if a.path => (Listen::Path(text(a)), tcp(b, c)?),
        [a, b, c] if c.path => (Listen::Port { bind: Some(text(a)), port: port(b)? }, Target::Socket(text(c))),
        [a, b, c] => (Listen::Port { bind: None, port: port(a)? }, tcp(b, c)?),
        [a, b, c, d] => (Listen::Port { bind: Some(text(a)), port: port(b)? }, tcp(c, d)?),
        _ => return Err("an empty spec".into()),
    };
    match (dynamic, &target) {
        (true, Target::Socks) | (false, Target::Tcp { .. } | Target::Socket(_)) => {}
        (true, _) => return Err("not [bind_address:]port, or a socket path".into()),
        (false, Target::Socks) => {
            return Err("not [bind_address:]port:host:hostport, with a socket path in place of either side".into())
        }
    }
    if matches!(listen, Listen::Port { port: 0, .. }) {
        return Err("a listening port of 0 is not allowed".into());
    }
    match &target {
        Target::Tcp { port: 0, .. } => Err("a port of 0 to connect to is not allowed".into()),
        Target::Tcp { host, .. } if host.is_empty() => Err("no host to connect to".into()),
        _ => Ok((listen, target)),
    }
}

/// The fields of OpenSSH's `parse_fwd_field`: at most four.
fn fields(spec: &str) -> Option<Vec<Field>> {
    let mut out = Vec::new();
    let mut chars = spec.chars().peekable();
    while chars.peek().is_some() {
        if out.len() == 4 {
            return None;
        }
        let mut text = String::new();
        let mut path = false;
        if chars.next_if_eq(&'[').is_some() {
            loop {
                match chars.next()? {
                    ']' => break,
                    c => {
                        path |= c == '/';
                        text.push(c);
                    }
                }
            }
            if !matches!(chars.next(), None | Some(':')) {
                return None;
            }
        } else {
            loop {
                match chars.next() {
                    None | Some(':') => break,
                    // The next character is plain, and never makes a path.
                    Some('\\') => text.push(chars.next()?),
                    Some(c) => {
                        path |= c == '/';
                        text.push(c);
                    }
                }
            }
        }
        out.push(Field { text, path });
    }
    Some(out)
}

#[cfg(test)]
#[path = "local_spec_tests.rs"]
mod tests;
