//! The flag rows of `edit` (T-149): the connection flags of `cp`, and none
//! of the shape of a copy. A module of its own so that `flags.rs` stays
//! short; the rules of the table are in [`super`].

use super::{row, FlagKind, FlagRow};

/// **`edit`.** One file of a server, fetched, changed in an editor here, and
/// sent back. No `--timeout`: a person decides how long an edit takes, and
/// each wait of the fetch and the send has its own limit.
pub const EDIT_FLAGS: &[FlagRow] = &[
    row(Some('P'), "port", Some("PORT"), FlagKind::Supported,
        "port to connect to; this is scp's -P", None),
    row(Some('i'), "identity-file", Some("FILE"), FlagKind::Supported,
        "identity file, repeatable; also -oIdentityFile=", None),
    row(Some('F'), "config", Some("CONFIG"), FlagKind::Supported,
        "read this ssh_config file in place of ~/.ssh/config; none reads no file", None),
    // The connection, as `ssh` makes it: the same ids, so `SshArgs` reads
    // them from `edit`'s matches too.
    row(Some('o'), "option", Some("NAME=VALUE"), FlagKind::Supported,
        "an OpenSSH option, as -o Name=Value; repeatable", None),
    row(Some('J'), "jump-host", Some("HOSTS"), FlagKind::Supported,
        "log in through these hosts first: [user@]host[:port][,...]", None),
    row(Some('v'), "verbose", None, FlagKind::Supported,
        "raise log level; repeatable", None),
    row(Some('q'), "quiet", None, FlagKind::Supported,
        "quiet: no messages from podssh itself, errors included", None),
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts to try in order, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE for the relay (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "direct", None, FlagKind::Supported,
        "connect without the relay: TCP, through HTTPS_PROXY when one is set", None),
    super::forwarder::FORWARDER,
    super::shadowsocks::SHADOWSOCKS,
];
