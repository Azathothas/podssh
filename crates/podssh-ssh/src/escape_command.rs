//! The command line of the escape `~C` (T-291), as OpenSSH's: `-L`, `-R`
//! and `-D` with a spec of the command line add a forward to the running
//! session, `-KL`, `-KR` and `-KD` with `[bind_address:]port` (or a socket
//! path, for `-KL` and `-KD`) stop one, and `help` or `?` lists them. The
//! `-` is optional, and so is a space after the letter, as in OpenSSH. The
//! caller reads a spec and binds the listeners of `-L` and `-D`, as for its
//! command line: this crate binds nothing.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use crate::local::{Listening, LocalForward};
use crate::options::RemoteForward;

/// What `help` prints: OpenSSH's lines.
pub const HELP: &str = "Commands:
      -L[bind_address:]port:host:hostport    Request local forward
      -R[bind_address:]port:host:hostport    Request remote forward
      -D[bind_address:]port                  Request dynamic forward
      -KL[bind_address:]port                 Cancel local forward
      -KR[bind_address:]port                 Cancel remote forward
      -KD[bind_address:]port                 Cancel dynamic forward
";

/// OpenSSH's words for a line that is no command.
pub const INVALID: &str = "Invalid command.";

/// The kind of a forward, as the letter of the command says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Local,
    Remote,
    Dynamic,
}

/// Where the forward that a command stops listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// `[bind_address:]port`: `None` is each address of that port.
    Port { bind: Option<String>, port: u16 },
    /// A socket path.
    Path(String),
}

impl Place {
    /// Whether a listener at `at` is here: the same path, or the same port
    /// at the address given, if one was (`localhost` is loopback; `*` and
    /// an empty one are each address).
    pub fn holds(&self, at: &Listening) -> bool {
        match (self, at) {
            (Place::Path(path), Listening::Path(there)) => path == there,
            (Place::Port { bind, port }, Listening::Tcp(addr)) => {
                *port == addr.port()
                    && match bind.as_deref() {
                        None | Some("" | "*") => true,
                        Some("localhost") => addr.ip().is_loopback(),
                        Some(other) => other.parse::<IpAddr>().is_ok_and(|ip| ip == addr.ip()),
                    }
            }
            _ => false,
        }
    }
}

/// One line of `~C`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Order {
    /// An empty line.
    Nothing,
    Help,
    /// `-L`, `-R` or `-D`, with its spec as typed.
    Add(Kind, String),
    /// `-KL`, `-KR` or `-KD`, with where the forward listens.
    Cancel(Kind, Place),
}

/// Read a line of `~C` as OpenSSH's `process_cmdline` reads it; the words
/// of a refusal are OpenSSH's.
pub fn parse(line: &str) -> Result<Order, String> {
    let line = line.trim();
    let line = line.strip_prefix('-').unwrap_or(line);
    let mut chars = line.chars();
    let (cancel, letter) = match chars.next() {
        None => return Ok(Order::Nothing),
        Some('h' | 'H' | '?') => return Ok(Order::Help),
        Some('!') => return Err("podssh runs no local command from ~C (OpenSSH's PermitLocalCommand)".into()),
        Some('K') => (true, chars.next()),
        other => (false, other),
    };
    let kind = match letter {
        Some('L') => Kind::Local,
        Some('R') => Kind::Remote,
        Some('D') => Kind::Dynamic,
        _ => return Err(INVALID.into()),
    };
    let spec = chars.as_str().trim();
    if cancel {
        let at = place(spec).ok_or_else(|| "Bad forwarding close specification.".to_string())?;
        return Ok(Order::Cancel(kind, at));
    }
    if spec.is_empty() {
        let side = if kind == Kind::Remote { "remote" } else { "local" };
        return Err(format!("Bad {side} forwarding specification."));
    }
    Ok(Order::Add(kind, spec.to_string()))
}

/// `[bind_address:]port`, an IPv6 address in brackets, or a socket path;
/// `None` for another form, or a port of 0, where nothing listens.
fn place(spec: &str) -> Option<Place> {
    if spec.contains('/') {
        return Some(Place::Path(spec.to_string()));
    }
    let (bind, port) = match spec.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']')?;
            (Some(host.to_string()), after.strip_prefix(':')?)
        }
        None => match spec.rsplit_once(':') {
            // A bare IPv6 address: its port cannot be told from it.
            Some((host, _)) if host.contains(':') => return None,
            Some((host, port)) => (Some(host.to_string()), port),
            None => (None, spec),
        },
    };
    match port.parse::<u16>() {
        Ok(port) if port > 0 => Some(Place::Port { bind, port }),
        _ => None,
    }
}

/// The forward of `-L` or `-D` that the caller makes, with its listeners.
pub type Made<'a> = Pin<Box<dyn Future<Output = Result<LocalForward, String>> + Send + 'a>>;

/// What `~C` asks of the caller: a spec read as its command line reads one
/// of `-L`, `-D` or `-R`, and the listeners of `-L` and `-D` bound as those
/// of its command line are (the probe, and `PODSSH_LISTEN`).
pub trait Forwarder: Send + Sync {
    /// `-L SPEC`, or `-D SPEC` when `dynamic`: the forward with its
    /// listeners, or why there is none.
    fn local(&self, spec: &str, dynamic: bool) -> Made<'_>;

    /// `-R SPEC`: the forward, or why the spec is refused.
    fn remote(&self, spec: &str) -> Result<RemoteForward, String>;
}

/// The caller's [`Forwarder`], which a session's `~C` uses.
#[derive(Clone)]
pub struct Commands(pub Arc<dyn Forwarder>);

impl fmt::Debug for Commands {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Commands")
    }
}

#[cfg(test)]
#[path = "escape_command_tests.rs"]
mod tests;
