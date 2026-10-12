//! Everything a connection needs to know, resolved from the command line by the
//! caller. Plain data: nothing here touches the network or the terminal.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// `StrictHostKeyChecking`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictHostKeyChecking {
    /// Refuse a host whose key is not already known.
    Yes,
    /// Record an unknown key and continue.
    AcceptNew,
    /// Record an unknown key and continue. Unlike OpenSSH, a changed key is
    /// still refused: podssh never connects past one.
    No,
    /// Ask on the terminal; refuse when there is no one to ask.
    Ask,
}

impl StrictHostKeyChecking {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "yes" | "true" => Some(Self::Yes),
            "accept-new" => Some(Self::AcceptNew),
            "no" | "off" | "false" => Some(Self::No),
            "ask" => Some(Self::Ask),
            _ => None,
        }
    }
}

/// `RequestTTY`, which `-t`, `-tt` and `-T` set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTty {
    /// A pty for an interactive shell when stdin is a terminal.
    Auto,
    /// A pty when stdin is a terminal (`-t`).
    Yes,
    /// A pty even without a local terminal (`-tt`).
    Force,
    /// Never a pty (`-T`).
    No,
}

impl RequestTty {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "yes" | "true" => Some(Self::Yes),
            "force" => Some(Self::Force),
            "no" | "false" => Some(Self::No),
            _ => None,
        }
    }
}

/// What to do once logged in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// An interactive shell.
    Shell,
    /// A command line, handed to the server as one string (as OpenSSH does).
    Exec(String),
    /// A subsystem by name (`-s`), such as `sftp`.
    Subsystem(String),
    /// `-W HOST:PORT`: stdin and stdout become a TCP stream opened by the server.
    StdioForward(StdioTarget),
    /// `-N`: stay connected and run nothing.
    Nothing,
}

/// An agent: where keys come from (`IdentityAgent`), and the one that the
/// destination's server may use (`-A`, `ForwardAgent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agent {
    /// `SSH_AUTH_SOCK`; on Windows, also the OpenSSH agent's named pipe and
    /// Pageant.
    FromEnvironment,
    /// No agent: `IdentityAgent none`, or no forwarding.
    Off,
    /// `IdentityAgent PATH` (a Unix socket, or a named pipe on Windows).
    Path(PathBuf),
}

/// An authentication method podssh tries, in `PreferredAuthentications` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    PublicKey,
    KeyboardInteractive,
    Password,
}

impl Method {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "publickey" => Some(Self::PublicKey),
            "keyboard-interactive" => Some(Self::KeyboardInteractive),
            "password" => Some(Self::Password),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::PublicKey => "publickey",
            Self::KeyboardInteractive => "keyboard-interactive",
            Self::Password => "password",
        }
    }
}

/// How much podssh says about itself (`LogLevel`, `-q`, `-v`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Quiet,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug1,
    Debug2,
    Debug3,
}

impl LogLevel {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "QUIET" => Some(Self::Quiet),
            "FATAL" => Some(Self::Fatal),
            "ERROR" => Some(Self::Error),
            "INFO" => Some(Self::Info),
            "VERBOSE" => Some(Self::Verbose),
            "DEBUG" | "DEBUG1" => Some(Self::Debug1),
            "DEBUG2" => Some(Self::Debug2),
            "DEBUG3" => Some(Self::Debug3),
            _ => None,
        }
    }

    /// `-v` given `count` times, from INFO; `-q` lowers to QUIET.
    pub fn from_flags(verbose: u8, quiet: u8) -> Self {
        if quiet > 0 {
            return Self::Quiet;
        }
        match verbose {
            0 => Self::Info,
            1 => Self::Debug1,
            2 => Self::Debug2,
            _ => Self::Debug3,
        }
    }
}

/// `--sudo` and `--su` (T-032): the remote command runs as root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevate {
    /// `sudo -S`, with no pty.
    Sudo,
    /// `su -c`, with a pty: su reads a terminal alone.
    Su,
}

/// Where `-W` reaches from the server (T-040).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdioTarget {
    /// `HOST:PORT`: a TCP connection (`direct-tcpip`).
    Tcp { host: String, port: u16 },
    /// `/PATH`: a Unix socket on the server (`direct-streamlocal@openssh.com`).
    Socket(String),
}

impl StdioTarget {
    /// As a message names it: `HOST:PORT`, or the path.
    pub fn shown(&self) -> String {
        match self {
            StdioTarget::Tcp { host, port } => podssh_ws::dial::authority(host, *port),
            StdioTarget::Socket(path) => path.clone(),
        }
    }
}

/// One `-J` hop, or the final destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    /// The login name; `None` means the connection's default user.
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
}

/// A whole connection.
#[derive(Debug, Clone)]
pub struct Options {
    /// The destination.
    pub destination: Hop,
    /// `-R` and `RemoteForward`, asked of the destination after the login.
    pub remote_forwards: Vec<RemoteForward>,
    /// `-L` and `-D` (T-038), each with the listeners that the caller bound
    /// before the connection; served on the destination's connection.
    pub local_forwards: Vec<crate::local::LocalForward>,
    /// The control socket that this run serves as a master (T-039).
    #[cfg(unix)]
    pub control: Option<crate::mux::ControlSlot>,
    /// `ExitOnForwardFailure`: a forward that the server refuses ends the run.
    pub exit_on_forward_failure: bool,
    /// After a loss of `podssh ssh --persist` (T-042): a forward of `-R`
    /// that the server refuses is asked again, as [`Again`] says; `None`
    /// asks once, as OpenSSH does.
    pub forwards_again: Option<Again>,
    /// The name the destination's host key is filed under (`HostKeyAlias`);
    /// `None` uses its host name.
    pub host_key_alias: Option<String>,
    /// Hops to go through first (`-J`), in order; the caller's stream reaches
    /// the first one.
    pub jump: Vec<Hop>,
    /// The options of each hop of `jump`, in order, as the caller resolved
    /// them from the hop's own blocks of `ssh_config` (T-290); each has the
    /// hop as its destination. Empty: the connection's options hold for each
    /// hop.
    pub jump_options: Vec<Options>,
    /// The login name when a hop does not name one.
    pub user: String,
    /// Key files to try, in order. Empty means the caller found none.
    pub identity_files: Vec<PathBuf>,
    /// `IdentitiesOnly`: offer only `identity_files`, even when an agent holds
    /// other keys.
    pub identities_only: bool,
    pub agent: Agent,
    /// `-A` and `ForwardAgent` (T-036): the agent that the destination's
    /// server may use while the session lasts. Off by default, as in OpenSSH.
    pub forward_agent: Agent,
    /// `-X` and `-Y` (T-037): the display that the destination's server may
    /// open X11 channels to, probed before the connection. Off by default.
    pub forward_x11: Option<crate::x11::Forward>,
    pub strict_host_key_checking: StrictHostKeyChecking,
    /// `UserKnownHostsFile`: read, and the first one is where new keys go.
    pub user_known_hosts: Vec<PathBuf>,
    /// Why `user_known_hosts` is empty, when it is: the note on a key that
    /// is accepted and not recorded says it.
    pub no_user_known_hosts: Option<&'static str>,
    /// `GlobalKnownHostsFile`: read only.
    pub global_known_hosts: Vec<PathBuf>,
    /// `BatchMode`: never prompt.
    pub batch_mode: bool,
    /// `PreferredAuthentications`, with methods turned off by
    /// `PubkeyAuthentication`/`PasswordAuthentication`/
    /// `KbdInteractiveAuthentication` already removed.
    pub methods: Vec<Method>,
    /// Why `publickey` is not among `methods`, for a refusal: the option that
    /// removed it. `None` when it is there.
    pub publickey_off: Option<String>,
    /// `NumberOfPasswordPrompts`.
    pub password_prompts: u32,
    /// `ServerAliveInterval`; `None` turns keepalives off.
    pub keepalive_interval: Option<Duration>,
    /// `ServerAliveCountMax`.
    pub keepalive_max: usize,
    /// `ConnectTimeout`: the limit on the SSH handshake, and on each answer of
    /// the server during the authentication.
    pub connect_timeout: Duration,
    pub request: Request,
    /// `--sudo` or `--su`: the command of `request` runs as root (T-032).
    pub elevate: Option<Elevate>,
    /// `--record FILE`: the session's output, with its timing (T-033).
    pub record: Option<crate::record::Target>,
    pub request_tty: RequestTty,
    /// `EscapeChar`; `None` is `none`.
    pub escape_char: Option<u8>,
    /// Kept shells (T-158): whether the far end keeps them, which the road
    /// learns, and what `--attach` asks of them.
    pub keep: crate::keep::Keep,
    /// `SetEnv`.
    pub set_env: Vec<(String, String)>,
    /// `SendEnv` patterns, matched against the local environment.
    pub send_env: Vec<String>,
    /// `Compression`.
    pub compression: bool,
    pub log_level: LogLevel,
    /// `-n`: send end-of-file at once instead of reading stdin.
    pub stdin_null: bool,
    /// The destination's host key for the whole run, shared by each
    /// connection that a run opens again (`cp`, T-136); `None` for one
    /// connection.
    pub host_key_pin: Option<crate::hostkey::Pin>,
    /// `--host-key-fingerprint`: the destination's key must be one of these,
    /// whatever `known_hosts` and `StrictHostKeyChecking` say, and none is
    /// recorded (T-031). Jump hops keep the normal policy.
    pub host_key_fingerprints: Vec<String>,
    /// The login that worked, for each later connection of the run (`cp`,
    /// T-137): no second question for a passphrase or a password.
    pub remembered: Option<crate::remember::Remembered>,
}

/// How a forward of `-R` that the server refused is asked again after a
/// loss (T-042): the server may hold its port for the lost connection until
/// it sees that connection dead.
#[derive(Debug, Clone, Copy)]
pub struct Again {
    /// How long, from the first refusal, at most.
    pub within: Duration,
    /// The wait before round N, from 1.
    pub wait: fn(u32) -> Duration,
}

/// One remote forward: the server listens at `bind:port`, and podssh
/// connects each connection that it takes to `host:host_port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteForward {
    /// The address that the server binds, as given: `None` when none was,
    /// which `-G` prints as OpenSSH does.
    pub bind: Option<String>,
    /// The port that the server binds; 0 lets it choose.
    pub port: u16,
    pub host: String,
    pub host_port: u16,
}

impl RemoteForward {
    /// The address sent to the server, as OpenSSH sends it: `localhost` when
    /// none was given, and the empty string (each interface, as the server's
    /// `GatewayPorts` allows) for an empty one or `*`.
    pub fn sent_address(&self) -> &str {
        match self.bind.as_deref() {
            None => "localhost",
            Some("") | Some("*") => "",
            Some(address) => address,
        }
    }
}

impl Options {
    /// `BatchMode` from now on, for the destination and each hop with options
    /// of its own: a run that tries again, or connects again after a loss,
    /// asks nothing.
    pub fn set_batch_mode(&mut self) {
        self.batch_mode = true;
        for hop in &mut self.jump_options {
            hop.batch_mode = true;
        }
    }

    /// Defaults for a destination, as OpenSSH's, except that keepalives are on
    /// (every 60 s): the relay cuts a connection after 180 s without traffic.
    pub fn new(destination: Hop, user: String) -> Self {
        Options {
            destination,
            remote_forwards: Vec::new(),
            local_forwards: Vec::new(),
            #[cfg(unix)]
            control: None,
            exit_on_forward_failure: false,
            forwards_again: None,
            host_key_alias: None,
            jump: Vec::new(),
            jump_options: Vec::new(),
            user,
            identity_files: Vec::new(),
            identities_only: false,
            agent: Agent::FromEnvironment,
            forward_agent: Agent::Off,
            forward_x11: None,
            strict_host_key_checking: StrictHostKeyChecking::Ask,
            user_known_hosts: Vec::new(),
            no_user_known_hosts: None,
            global_known_hosts: Vec::new(),
            batch_mode: false,
            methods: vec![Method::PublicKey, Method::KeyboardInteractive, Method::Password],
            publickey_off: None,
            password_prompts: 3,
            keepalive_interval: Some(Duration::from_secs(60)),
            keepalive_max: 3,
            connect_timeout: Duration::from_secs(60),
            request: Request::Shell,
            elevate: None,
            record: None,
            request_tty: RequestTty::Auto,
            escape_char: Some(b'~'),
            keep: crate::keep::Keep::default(),
            set_env: Vec::new(),
            send_env: Vec::new(),
            compression: false,
            log_level: LogLevel::Info,
            stdin_null: false,
            host_key_pin: None,
            host_key_fingerprints: Vec::new(),
            remembered: None,
        }
    }
}

/// OpenSSH's default key files under `home`, in its order, for the key types
/// podssh can use (security-key types need hardware and are left out).
pub fn default_identity_files(home: &Path) -> Vec<PathBuf> {
    ["id_rsa", "id_ecdsa", "id_ed25519"].iter().map(|name| home.join(".ssh").join(name)).collect()
}

/// OpenSSH's default `UserKnownHostsFile` under `home`.
pub fn default_user_known_hosts(home: &Path) -> Vec<PathBuf> {
    vec![home.join(".ssh").join("known_hosts"), home.join(".ssh").join("known_hosts2")]
}

/// OpenSSH's default `GlobalKnownHostsFile`.
pub fn default_global_known_hosts() -> Vec<PathBuf> {
    if cfg!(windows) {
        let base =
            std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        vec![base.join("ssh").join("ssh_known_hosts")]
    } else {
        vec![PathBuf::from("/etc/ssh/ssh_known_hosts"), PathBuf::from("/etc/ssh/ssh_known_hosts2")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_values_parse_as_openssh_spells_them() {
        assert_eq!(StrictHostKeyChecking::parse("accept-new"), Some(StrictHostKeyChecking::AcceptNew));
        assert_eq!(StrictHostKeyChecking::parse("off"), Some(StrictHostKeyChecking::No));
        assert_eq!(StrictHostKeyChecking::parse("maybe"), None);
        assert_eq!(RequestTty::parse("force"), Some(RequestTty::Force));
        assert_eq!(Method::parse("keyboard-interactive"), Some(Method::KeyboardInteractive));
        assert_eq!(LogLevel::parse("debug"), Some(LogLevel::Debug1));
        assert_eq!(LogLevel::from_flags(0, 0), LogLevel::Info);
        assert_eq!(LogLevel::from_flags(3, 0), LogLevel::Debug3);
        assert_eq!(LogLevel::from_flags(2, 1), LogLevel::Quiet);
    }

    #[test]
    fn keepalives_are_on_by_default_and_below_the_relay_idle_cut() {
        let o = Options::new(Hop { user: None, host: "h".into(), port: 22 }, "u".into());
        let every = o.keepalive_interval.expect("keepalives on by default");
        assert!(every.as_secs() < 180, "the relay cuts idle connections at 180 s");
    }
}
