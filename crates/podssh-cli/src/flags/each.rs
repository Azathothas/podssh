//! The flag rows of `each` (T-183): the connection flags of `ssh` that make
//! sense for many hosts, the three of the fan-out, and the two of a snippet
//! (T-187), shared with `ssh`. A module of its own
//! so that `flags.rs` stays short; the rules of the table are in [`super`].

use super::{row, FlagKind, FlagRow};

/// **`each`.** One command on each host of a list, at most `--parallel` at
/// once. The connection rows share their ids with `ssh`'s, so `SshArgs`
/// reads them from `each`'s matches too; `-p` is the port, as on `ssh`.
pub const EACH_FLAGS: &[FlagRow] = &[
    row(None, "parallel", Some("N"), FlagKind::Supported,
        "at most N hosts at once, 1 to 64 (default 8)", None),
    row(None, "fail-fast", None, FlagKind::Supported,
        "start no new host after one failed; the hosts that run end as they end", None),
    row(None, "output-dir", Some("DIR"), FlagKind::Supported,
        "each host's output, unchanged, in DIR/HOST.out and DIR/HOST.err, and its status in DIR/HOST.status", None),
    super::snippet::SNIPPET,
    super::snippet::YES,
    row(Some('p'), "port", Some("PORT"), FlagKind::Supported,
        "port to connect to, for each host that names none", None),
    row(Some('l'), "login-name", Some("USER"), FlagKind::Supported,
        "user to log in as, for each host; also user@host", None),
    row(Some('i'), "identity-file", Some("FILE"), FlagKind::Supported,
        "identity file, repeatable; also -oIdentityFile=", None),
    row(Some('o'), "option", Some("NAME=VALUE"), FlagKind::Supported,
        "an OpenSSH option, as -o Name=Value; repeatable", None),
    row(Some('F'), "config", Some("CONFIG"), FlagKind::Supported,
        "read this ssh_config file in place of ~/.ssh/config; none reads no file", None),
    row(Some('J'), "jump-host", Some("HOSTS"), FlagKind::Supported,
        "log in through these hosts first: [user@]host[:port][,...]", None),
    row(Some('v'), "verbose", None, FlagKind::Supported,
        "raise log level; repeatable", None),
    row(Some('q'), "quiet", None, FlagKind::Supported,
        "quiet: no messages from podssh itself, errors and the summary included", None),
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts to try in order, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-failover", Some("MODE"), FlagKind::Supported,
        "how the relay hosts are tried: staggered (the default), parallel or serial; also env PODSSH_RELAY_FAILOVER", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE for the relay (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "direct", None, FlagKind::Supported,
        "connect without the relay: TCP, through HTTPS_PROXY when one is set", None),
];
