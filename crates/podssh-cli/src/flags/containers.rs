//! The flag rows of `containers` (T-190): the three of the list and its
//! `--exec`, and the connection flags of `ssh` that reach one host. A
//! module of its own so that `flags.rs` stays short; the rules of the table
//! are in [`super`].

use super::{row, FlagKind, FlagRow};

/// **`containers`.** The rows of the connection share their ids with
/// `ssh`'s, so `SshArgs` reads them from `containers`'s matches too.
pub const CONTAINERS_FLAGS: &[FlagRow] = &[
    row(None, "exec", Some("NAME"), FlagKind::Supported,
        "enter the container NAME, as the list names it (pod/ may be left out), on the same connection", None),
    row(None, "shell", Some("PROG"), FlagKind::Supported,
        "with --exec: the program to start in the container (default sh)", None),
    row(None, "tool", Some("TOOL"), FlagKind::Supported,
        "ask docker, podman or kubectl alone (default: each of them that the host has)", None),
    row(Some('t'), "force-tty", None, FlagKind::Supported,
        "with --exec: twice (-tt), a pty also when this side has no terminal", None),
    row(Some('p'), "port", Some("PORT"), FlagKind::Supported,
        "port to connect to; never a proxy port", None),
    row(Some('l'), "login-name", Some("USER"), FlagKind::Supported,
        "user to log in as; also user@host", None),
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
    super::forwarder::FORWARDER,
    super::shadowsocks::SHADOWSOCKS,
];
