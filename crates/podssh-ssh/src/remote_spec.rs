//! What `-R` asks for (T-035, T-365): where the server listens, a port with
//! the address that podssh sends or a socket path, and what each connection
//! that it takes reaches from this host: a host and a port, a socket here,
//! or the SOCKS proxy that podssh serves, as OpenSSH carries each.

/// Where the server listens for a remote forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteListen {
    /// `[bind_address:]port`, asked for with `tcpip-forward`: the address as
    /// given (`None` when none was, which `-G` prints as OpenSSH does), and
    /// the port; 0 lets the server choose.
    Port { bind: Option<String>, port: u16 },
    /// A socket path on the server, asked for with
    /// `streamlocal-forward@openssh.com`.
    Path(String),
}

/// What each connection that the server takes reaches, from this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteTarget {
    /// `host:hostport`, dialed through the proxy, as `--direct` dials.
    Tcp { host: String, port: u16 },
    /// A socket on this host.
    Socket(String),
    /// A SOCKS proxy that podssh serves on each channel: each request names
    /// its target, which is dialed as a `Tcp` one is.
    Socks,
}

/// One remote forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteForward {
    pub listen: RemoteListen,
    pub target: RemoteTarget,
}

impl RemoteForward {
    /// The form of T-035: the server listens at `bind:port`, and each
    /// connection reaches `host:host_port`.
    pub fn tcp(bind: Option<String>, port: u16, host: impl Into<String>, host_port: u16) -> RemoteForward {
        RemoteForward {
            listen: RemoteListen::Port { bind, port },
            target: RemoteTarget::Tcp { host: host.into(), port: host_port },
        }
    }

    /// The address sent to the server for a port, as OpenSSH sends it:
    /// `localhost` when none was given, and the empty string (each
    /// interface, as the server's `GatewayPorts` allows) for an empty one or
    /// `*`. A path sends no address.
    pub fn sent_address(&self) -> &str {
        match &self.listen {
            RemoteListen::Port { bind, .. } => sent(bind.as_deref()),
            RemoteListen::Path(_) => "",
        }
    }

    /// The port that the server listens on, as asked: `None` for a path.
    pub fn port(&self) -> Option<u16> {
        match self.listen {
            RemoteListen::Port { port, .. } => Some(port),
            RemoteListen::Path(_) => None,
        }
    }
}

/// The address that OpenSSH sends for a given `bind`.
pub fn sent(bind: Option<&str>) -> &str {
    match bind {
        None => "localhost",
        Some("") | Some("*") => "",
        Some(address) => address,
    }
}

impl std::fmt::Display for RemoteListen {
    /// As `-R` writes it: `[bind:]port`, an IPv6 address in brackets, or the
    /// path.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteListen::Port { bind: None, port } => write!(f, "{port}"),
            RemoteListen::Port { bind: Some(bind), port } if bind.contains(':') => write!(f, "[{bind}]:{port}"),
            RemoteListen::Port { bind: Some(bind), port } => write!(f, "{bind}:{port}"),
            RemoteListen::Path(path) => f.write_str(path),
        }
    }
}

impl std::fmt::Display for RemoteForward {
    /// As `-R` writes it, for the lines of its counts (T-041): the listening
    /// side, then the target, a SOCKS proxy having none.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.target {
            RemoteTarget::Tcp { host, port } => {
                write!(f, "-R {}:{}", self.listen, podssh_ws::dial::authority(host, *port))
            }
            RemoteTarget::Socket(path) => write!(f, "-R {}:{path}", self.listen),
            RemoteTarget::Socks => write!(f, "-R {}", self.listen),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_form_is_named_as_dash_r_writes_it() {
        assert_eq!(RemoteForward::tcp(None, 8080, "db", 5432).to_string(), "-R 8080:db:5432");
        assert_eq!(RemoteForward::tcp(Some("::1".into()), 0, "db", 5432).to_string(), "-R [::1]:0:db:5432");
        let path = |target| RemoteForward { listen: RemoteListen::Path("/tmp/r.sock".into()), target };
        assert_eq!(
            path(RemoteTarget::Tcp { host: "127.0.0.1".into(), port: 22 }).to_string(),
            "-R /tmp/r.sock:127.0.0.1:22"
        );
        assert_eq!(path(RemoteTarget::Socket("/tmp/l.sock".into())).to_string(), "-R /tmp/r.sock:/tmp/l.sock");
        assert_eq!(path(RemoteTarget::Socks).to_string(), "-R /tmp/r.sock");
        let socks =
            RemoteForward { listen: RemoteListen::Port { bind: None, port: 1080 }, target: RemoteTarget::Socks };
        assert_eq!(socks.to_string(), "-R 1080");
    }

    #[test]
    fn the_address_sent_is_openssh_s() {
        assert_eq!(RemoteForward::tcp(None, 1, "h", 2).sent_address(), "localhost");
        assert_eq!(RemoteForward::tcp(Some("*".into()), 1, "h", 2).sent_address(), "");
        assert_eq!(RemoteForward::tcp(Some("10.0.0.1".into()), 1, "h", 2).sent_address(), "10.0.0.1");
    }
}
