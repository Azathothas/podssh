//! The flag rows of `health` (T-189): the flags that a login needs and the
//! relay's, with the ids of `ssh` so that its arguments are read the same
//! way, and the JSON of the facts. A module of its own so that `flags.rs`
//! stays short; the rules of the table are in [`super`].

use super::{row, FlagKind, FlagRow};

/// **`health`.** The facts of the far host, read over one exec that only
/// reads.
#[rustfmt::skip]
pub const HEALTH_FLAGS: &[FlagRow] = &[
    row(Some('p'), "port", Some("PORT"), FlagKind::Supported,
        "the host's port", None),
    row(Some('l'), "login-name", Some("USER"), FlagKind::Supported,
        "user to log in as; also user@host", None),
    row(Some('i'), "identity-file", Some("FILE"), FlagKind::Supported,
        "identity file, repeatable", None),
    row(Some('J'), "jump-host", Some("HOSTS"), FlagKind::Supported,
        "log in through these hosts first: [user@]host[:port][,...]", None),
    row(Some('F'), "config", Some("CONFIG"), FlagKind::Supported,
        "read this ssh_config file in place of ~/.ssh/config; none reads no file", None),
    row(Some('o'), "option", Some("NAME=VALUE"), FlagKind::Supported,
        "an OpenSSH option, as -o Name=Value; repeatable", None),
    row(Some('4'), "ipv4-only", None, FlagKind::Supported,
        "use IPv4 only; forwarded to the relay's ?family=4", None),
    row(Some('6'), "ipv6-only", None, FlagKind::Supported,
        "use IPv6 only; forwarded to the relay's ?family=6", None),
    row(Some('v'), "verbose", None, FlagKind::Supported,
        "raise log level; repeatable", None),
    row(Some('q'), "quiet", None, FlagKind::Supported,
        "quiet: no messages from podssh itself, errors included", None),
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
    row(None, "json", None, FlagKind::Supported,
        "the facts as one JSON object on stdout, also after a failure", None),
];
