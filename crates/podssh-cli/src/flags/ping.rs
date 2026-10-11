//! The flag rows of `ping` (T-053): the relay's flags, the flags that a
//! login needs, with the ids of `ssh` so that its arguments are read the
//! same way, and the size, the count and the JSON of the measures.

use super::{row, FlagKind, FlagRow};

/// **`ping`.** With no destination, the relay leg; with one, the SSH
/// measures too.
#[rustfmt::skip]
pub const PING_FLAGS: &[FlagRow] = &[
    row(Some('p'), "port", Some("PORT"), FlagKind::Supported,
        "the destination's port", None),
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
        "relay hosts to measure, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE for the relay (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "target", Some("HOST:PORT"), FlagKind::Supported,
        "where the relay leg goes (default github.com:22, which podssh doctor reaches too; never the destination)", None),
    row(None, "direct", None, FlagKind::Supported,
        "reach the destination without the relay: TCP, through HTTPS_PROXY when one is set", None),
    row(None, "size", Some("SIZE"), FlagKind::Supported,
        "bytes each way for the throughput, with K, M or G (default 8M, at most 30M: both ways stay under the relay's 64 MiB)", None),
    row(None, "count", Some("N"), FlagKind::Supported,
        "pings of each relay host, and echoes through the destination (default 10, at most 100)", None),
    row(None, "json", None, FlagKind::Supported,
        "the measures as one JSON object on stdout", None),
];
