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
    /// `--relay-failover`: how the relay hosts are tried (T-220).
    pub relay_failover: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    pub direct: bool,
    /// `--forwarder`: the forwarders in place of the relay (T-369).
    pub forwarder: Option<String>,
    /// `--shadowsocks FILE`: Shadowsocks servers in place of the relay
    /// (T-373).
    pub shadowsocks: Option<String>,
    /// For `node://NAME`: a pair, or its operator's part, in a file.
    pub pair_file: Option<String>,
    /// For `iroh:TICKET`: this client's key file, by its earlier name.
    pub iroh_key: Option<String>,
    /// For `node://NAME` and `iroh:TICKET`: this client's key file (T-087).
    pub client_key: Option<String>,
    /// For `node://NAME`: the node's key or fingerprint, in place of the pins.
    pub node_key: Option<String>,
    /// `--host-key-fingerprint`: the only host keys that the destination may
    /// present (T-031), unparsed.
    pub host_key_fingerprint: Option<String>,
    /// For `node://NAME`: no end-to-end channel (T-088).
    pub no_e2e: bool,
    /// For `iroh:TICKET`: the relays to try after the ticket's.
    pub iroh_relay: Option<String>,
    /// For `node://NAME`: the node's iroh ticket, to race with the pair.
    pub iroh_ticket: Option<String>,
    /// For `node://NAME`: the node's DERP ticket, to race with the pair
    /// (T-379).
    pub derp_ticket: Option<String>,
    /// For `derp:TICKET` and `node://NAME`: the DERP servers after the
    /// ticket's, unparsed.
    pub derp_server: Option<String>,
    /// `-f`, `--detach`: into the background once the request went (T-380).
    pub detach: bool,
    /// `--restart`: the detached run started again whenever it ends (T-390).
    pub restart: bool,
    /// `--persist`: tmux on the server, attached again after a lost link.
    pub persist: bool,
    /// The tmux session of `--persist`.
    pub persist_name: Option<String>,
    /// `--persist-forever`: connect again with no limit (T-391).
    pub persist_forever: bool,
    /// `--attach NAME`: the kept shell to join (T-158).
    pub attach: Option<String>,
    /// `--attach DEST` with no other word: list the kept shells there; set
    /// by `ssh::attach::listing`, never by the parser.
    pub attach_list: bool,
    /// `--take`: take the kept shell from the client that has it.
    pub take: bool,
    /// `--upgrade`: the session moves to a temporary node on the server
    /// (T-167).
    pub upgrade: bool,
    /// `--no-signal`: Ctrl-C with no remote pty sends no `signal INT`, and
    /// ends podssh at once (T-293).
    pub no_signal: bool,
    /// `--resume-deadline TIME`: this client's own resume deadline, which
    /// only shortens the far end's (T-306), unparsed.
    pub resume_deadline: Option<String>,
    /// `--sudo` and `--su`: the remote command runs as root (T-032).
    pub sudo: bool,
    /// `--record FILE`: the session's output in an asciicast v2 file (T-033).
    pub record: Option<String>,
    /// `-P TAG`: the tag that `Match tagged` reads (T-045).
    pub tag: Option<String>,
    /// `--result-file FILE`: the run's result as JSON (T-054).
    pub result_file: Option<String>,
    pub su: bool,
    /// `-G`: print the settings, and connect to nothing.
    pub print_config: bool,
    /// Each `-R` spec, as given.
    pub remote_forwards: Vec<String>,
    /// Each `-L` and each `-D` spec, as given (T-038).
    pub local_forwards: Vec<String>,
    pub dynamic_forwards: Vec<String>,
    /// `-g`: `-L` and `-D` with no address listen on each address.
    pub gateway_ports: bool,
    /// `-M` (`-MM` asks), `-S PATH` and `-O CMD` (T-039).
    pub control_master: u8,
    pub control_path: Option<String>,
    pub control_command: Option<String>,
    /// The last of `-A` and `-a`: whether the server may use the agent
    /// (T-036); `None` when neither was given.
    pub forward_agent: Option<bool>,
    /// The last of `-X`, `-Y` and `-x`: whether the server may open X11
    /// channels (T-037); and whether `-Y`, trusted, was given.
    pub forward_x11: Option<bool>,
    pub x11_trusted: bool,
    /// `--snippet NAME`: the command of the settings file in place of a
    /// command, whose values are the words after the host (T-187).
    pub snippet: Option<String>,
    /// `--yes`: run the snippet with no question.
    pub yes: bool,
    /// Each `--expect` (true) and `--send` (false), in the order given
    /// (T-191).
    pub expect: Vec<(bool, String)>,
    pub expect_timeout: Option<String>,
    /// `--install NAME`, `--uninstall NAME` and `--env-file FILE`: the run
    /// as a service of this user, and the run of that service (T-393).
    pub install: Option<String>,
    pub uninstall: Option<String>,
    pub env_file: Option<String>,
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
    ("relay-failover", "give one mode"),
    ("relay-addr", "give the addresses as one comma list"),
    ("ca-file", "give one file"),
    ("forwarder", "give the forwarders as one comma list"),
    ("shadowsocks", "give one file, with a line for each server"),
    ("pair-file", "give one file"),
    ("iroh-key", "give one file"),
    ("client-key", "give one file"),
    ("node-key", "give one key"),
    ("host-key-fingerprint", "give the fingerprints as one comma list"),
    ("iroh-relay", "give the relays as one comma list"),
    ("iroh-ticket", "give one ticket"),
    ("derp-ticket", "give one ticket"),
    ("derp-server", "give the servers as one comma list"),
    ("persist-name", "give one name"),
    ("attach", "give one name"),
    ("resume-deadline", "give one time"),
    ("record", "give one file"),
    ("control-command", "give one command, as OpenSSH asks"),
    ("snippet", "give one snippet"),
    ("expect-timeout", "give one time"),
    ("install", "give one name"),
    ("uninstall", "give one name"),
    ("env-file", "give one file"),
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
        // The last of -A and -a wins, as in OpenSSH, where each sets the
        // option as it comes.
        let at = |id: &str| if flag(id) { m.indices_of(id).and_then(|i| i.max()) } else { None };
        let forward_agent = match (at("forward-agent"), at("no-agent-forwarding")) {
            (Some(yes), Some(no)) => Some(yes > no),
            (yes, no) => yes.map(|_| true).or(no.map(|_| false)),
        };
        // -X and -Y set ForwardX11, -x clears it, the last one wins; -Y also
        // sets ForwardX11Trusted, as OpenSSH's do.
        let x11_yes = at("forward-x11").max(at("forward-x11-trusted"));
        let forward_x11 = match (x11_yes, at("no-x11")) {
            (Some(yes), Some(no)) => Some(yes > no),
            (yes, no) => yes.map(|_| true).or(no.map(|_| false)),
        };
        // --expect and --send by their places on the command line (T-191).
        let mut expect: Vec<(usize, bool, String)> = Vec::new();
        for (id, is_expect) in [("expect", true), ("send", false)] {
            // clap asks for an id that the verb declares.
            if !has(id) {
                continue;
            }
            if let Some(at) = m.indices_of(id) {
                expect.extend(at.zip(many(id)).map(|(i, v)| (i, is_expect, v)));
            }
        }
        expect.sort_by_key(|(i, ..)| *i);
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
            relay_failover: one("relay-failover"),
            relay_addr: one("relay-addr"),
            ca_file: one("ca-file"),
            direct: flag("direct"),
            forwarder: one("forwarder"),
            shadowsocks: one("shadowsocks"),
            pair_file: one("pair-file"),
            iroh_key: one("iroh-key"),
            client_key: one("client-key"),
            node_key: one("node-key"),
            host_key_fingerprint: one("host-key-fingerprint"),
            no_e2e: flag("no-e2e"),
            iroh_relay: one("iroh-relay"),
            iroh_ticket: one("iroh-ticket"),
            derp_ticket: one("derp-ticket"),
            derp_server: one("derp-server"),
            detach: flag("detach"),
            restart: flag("restart"),
            persist: flag("persist"),
            persist_name: one("persist-name"),
            persist_forever: flag("persist-forever"),
            attach: one("attach"),
            attach_list: false,
            take: flag("take"),
            upgrade: flag("upgrade"),
            no_signal: flag("no-signal"),
            resume_deadline: one("resume-deadline"),
            sudo: flag("sudo"),
            record: one("record"),
            tag: one("tag").filter(|t| !t.is_empty()),
            result_file: one("result-file"),
            su: flag("su"),
            print_config: flag("print-config"),
            remote_forwards: many("forward-remote"),
            local_forwards: many("forward-local"),
            dynamic_forwards: many("dynamic-forward"),
            gateway_ports: flag("gateway-ports"),
            control_master: count("control-master"),
            control_path: last("control-path"),
            control_command: one("control-command"),
            forward_agent,
            forward_x11,
            x11_trusted: flag("forward-x11-trusted"),
            snippet: one("snippet"),
            yes: flag("yes"),
            expect: expect.into_iter().map(|(_, is_expect, v)| (is_expect, v)).collect(),
            expect_timeout: one("expect-timeout"),
            install: one("install"),
            uninstall: one("uninstall"),
            env_file: one("env-file"),
        }
    }
}
