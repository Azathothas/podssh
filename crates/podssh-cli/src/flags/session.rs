//! The flag rows of `session` (T-186): where a session's socket is, what
//! `wait`, `send` and `capture` take, and the connection flags of `ssh` that
//! `start` and `serve` read. A module of its own so that `flags.rs` stays
//! short; the rules of the table are in [`super`].

use super::{row, FlagKind, FlagRow};

/// **`session`.** A session that outlives each call: `start` holds it in a
/// podssh of its own, and `send`, `wait`, `capture`, `stop` and `list` talk
/// to that podssh on its socket. The connection rows share their ids with
/// `ssh`'s, so `SshArgs` reads them from `session`'s matches too.
pub const SESSION_FLAGS: &[FlagRow] = &[
    row(None, "socket", Some("PATH"), FlagKind::Supported,
        "the session's socket: start and serve listen there, the others connect there (default: NAME.sock in the directory sessions of the cache; on Windows also \\\\.\\pipe\\NAME)", None),
    row(None, "timeout", Some("DURATION"), FlagKind::Supported,
        "start: how long to wait for the session to be ready; wait: for what it waits for (default 60s)", None),
    row(None, "idle", Some("DURATION"), FlagKind::Supported,
        "wait: until the output has stopped this long, counted from the last send (default 2s when --match is not given)", None),
    row(None, "match", Some("TEXT"), FlagKind::Supported,
        "wait: until TEXT comes in the output since the last send, the terminal's sequences taken out", None),
    row(None, "no-enter", None, FlagKind::Supported,
        "send: no Enter (a carriage return) after the text", None),
    row(None, "raw", None, FlagKind::Supported,
        "capture: the last 64 KiB of output as it came, from a clean place of the terminal's grammar, in place of the screen", None),
    row(None, "detach", None, FlagKind::Supported,
        "serve: after the line that says it is ready, write nothing more on stdout and stderr (start gives it)", None),
    row(Some('p'), "port", Some("PORT"), FlagKind::Supported,
        "start: port to connect to", None),
    row(Some('l'), "login-name", Some("USER"), FlagKind::Supported,
        "start: user to log in as; also user@host", None),
    row(Some('i'), "identity-file", Some("FILE"), FlagKind::Supported,
        "start: identity file, repeatable; also -oIdentityFile=", None),
    row(Some('o'), "option", Some("NAME=VALUE"), FlagKind::Supported,
        "start: an OpenSSH option, as -o Name=Value; repeatable", None),
    row(Some('F'), "config", Some("CONFIG"), FlagKind::Supported,
        "start: read this ssh_config file in place of ~/.ssh/config; none reads no file", None),
    row(Some('J'), "jump-host", Some("HOSTS"), FlagKind::Supported,
        "start: log in through these hosts first: [user@]host[:port][,...]", None),
    row(Some('v'), "verbose", None, FlagKind::Supported,
        "raise log level; repeatable", None),
    row(Some('q'), "quiet", None, FlagKind::Supported,
        "quiet: no messages from podssh itself", None),
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
];
