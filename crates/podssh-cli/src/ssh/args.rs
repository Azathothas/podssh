//! `podssh ssh`'s command line as parsed: the raw values, before any of them
//! is interpreted. [`super::options`] turns them into a connection.

use clap::ArgMatches;

/// Every value `podssh ssh` accepts, as typed. The field names follow the
/// flag rows in [`crate::flags::SSH_FLAGS`], whose long names are the ids.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshArgs {
    /// `[user@]host`, `host:port` or `ssh://[user@]host[:port]`.
    pub destination: Option<String>,
    /// The remote command, one word per argument (joined with spaces, as
    /// OpenSSH does).
    pub command: Vec<String>,
    pub port: Option<String>,
    pub login: Option<String>,
    pub identity_files: Vec<String>,
    pub jump: Option<String>,
    pub no_command: bool,
    /// `-t` given this many times.
    pub tty: u8,
    pub no_tty: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub stdio_forward: Option<String>,
    pub log_file: Option<String>,
    pub config: Option<String>,
    pub verbose: u8,
    pub quiet: u8,
    /// `-o` values, in order.
    pub options: Vec<String>,
    /// `--StrictHostKeyChecking VALUE` and the other long forms of `-o`, as
    /// `Name=Value`, in the order of the table.
    pub long_options: Vec<String>,
    pub stdin_null: bool,
    pub subsystem: bool,
    pub escape_char: Option<String>,
    pub compression: bool,
    pub version: bool,
    pub relay_host: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    pub direct: bool,
    /// For `node://NAME`: a pair, or its operator's part, in a file.
    pub pair_file: Option<String>,
    /// For `iroh:TICKET`: this client's key file, by its earlier name.
    pub iroh_key: Option<String>,
    /// For `node://NAME` and `iroh:TICKET`: this client's key file (T-087).
    pub client_key: Option<String>,
    /// For `node://NAME`: the node's key or fingerprint, in place of the pins.
    pub node_key: Option<String>,
    /// For `node://NAME`: no end-to-end channel (T-088).
    pub no_e2e: bool,
    /// For `iroh:TICKET`: the relays to try after the ticket's.
    pub iroh_relay: Option<String>,
    /// For `node://NAME`: the node's iroh ticket, to race with the pair.
    pub iroh_ticket: Option<String>,
    /// `--persist`: tmux on the server, attached again after a lost link.
    pub persist: bool,
    /// The tmux session of `--persist`.
    pub persist_name: Option<String>,
    /// `-G`: print the settings, and connect to nothing.
    pub print_config: bool,
    /// Each `-R` spec, as given.
    pub remote_forwards: Vec<String>,
}

/// The long-only rows that are spellings of `-o NAME=VALUE`.
pub const OPTION_FLAGS: &[&str] = &["StrictHostKeyChecking", "UserKnownHostsFile", "LogLevel", "ConnectTimeout"];

/// The flags that may be given once, and how to give several values instead.
/// OpenSSH refuses a second `-J` ("Only a single -J option is permitted") and
/// a second `-W`. podssh's own relay and trust flags are here too, so that no
/// relay host or trust store is chosen by its place on the command line.
pub const ONCE: &[(&str, &str)] = &[
    ("jump-host", "give the hops as one comma list, as in -J a,b"),
    ("stdio-forward", "give one HOST:PORT"),
    ("relay-host", "give the hosts as one comma list"),
    ("relay-addr", "give the addresses as one comma list"),
    ("ca-file", "give one file"),
    ("pair-file", "give one file"),
    ("iroh-key", "give one file"),
    ("client-key", "give one file"),
    ("node-key", "give one key"),
    ("iroh-relay", "give the relays as one comma list"),
    ("iroh-ticket", "give one ticket"),
    ("persist-name", "give one name"),
];

/// The refusal for a flag of [`ONCE`] given more than once, if there is one.
pub fn repeated(m: &ArgMatches) -> Option<String> {
    ONCE.iter().find_map(|(id, how)| {
        let n = m.try_get_many::<String>(id).ok().flatten().map_or(0, |v| v.len());
        (n > 1).then(|| {
            let spelling = crate::flags::SSH_FLAGS
                .iter()
                .find(|r| r.long == *id)
                .map_or_else(|| format!("--{id}"), |r| r.spelling());
            format!("podssh ssh: {spelling} was given {n} times; {how}.\n  Nothing has been attempted.")
        })
    })
}

impl SshArgs {
    /// Read the values out of `ssh`'s matches. Only ids the table declares
    /// are read, so this never panics on a missing id.
    pub fn from_matches(m: &ArgMatches) -> Self {
        let has = |id: &str| m.try_contains_id(id).unwrap_or(false);
        // A repeated value: OpenSSH keeps the first `-p` and `-l` (and the
        // first value of each `-o` keyword), but the last `-e`, `-E` and `-F`.
        // The flags of [`ONCE`] are refused before this when repeated.
        let one = |id: &str| if has(id) { m.get_one::<String>(id).cloned() } else { None };
        let last = |id: &str| {
            if has(id) {
                m.get_many::<String>(id).and_then(|mut v| v.next_back()).cloned()
            } else {
                None
            }
        };
        let many = |id: &str| -> Vec<String> {
            if has(id) {
                m.get_many::<String>(id).map(|v| v.cloned().collect()).unwrap_or_default()
            } else {
                Vec::new()
            }
        };
        let flag = |id: &str| has(id) && m.try_get_one::<bool>(id).ok().flatten().copied().unwrap_or(false);
        let count = |id: &str| if has(id) { m.try_get_one::<u8>(id).ok().flatten().copied().unwrap_or(0) } else { 0 };
        let long_options =
            OPTION_FLAGS.iter().flat_map(|name| many(name).into_iter().map(move |v| format!("{name}={v}"))).collect();
        SshArgs {
            destination: one("destination"),
            command: many("remote-command"),
            port: one("port"),
            login: one("login-name"),
            identity_files: many("identity-file"),
            jump: one("jump-host"),
            no_command: flag("no-remote-command"),
            tty: count("force-tty"),
            no_tty: flag("disable-tty"),
            ipv4: flag("ipv4-only"),
            ipv6: flag("ipv6-only"),
            stdio_forward: one("stdio-forward"),
            log_file: last("log-file"),
            config: last("config"),
            verbose: count("verbose"),
            quiet: count("quiet"),
            options: many("option"),
            long_options,
            stdin_null: flag("stdin-null"),
            subsystem: flag("subsystem"),
            escape_char: last("escape-char"),
            compression: flag("compress"),
            version: flag("version"),
            relay_host: one("relay-host"),
            relay_addr: one("relay-addr"),
            ca_file: one("ca-file"),
            direct: flag("direct"),
            pair_file: one("pair-file"),
            iroh_key: one("iroh-key"),
            client_key: one("client-key"),
            node_key: one("node-key"),
            no_e2e: flag("no-e2e"),
            iroh_relay: one("iroh-relay"),
            iroh_ticket: one("iroh-ticket"),
            persist: flag("persist"),
            persist_name: one("persist-name"),
            print_config: flag("print-config"),
            remote_forwards: many("forward-remote"),
        }
    }
}
