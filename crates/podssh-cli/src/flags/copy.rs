//! The flag rows of the copy verbs: `cp` and `mv`, and their `scp` and
//! `sftp` aliases. A module of its own so that `flags.rs` stays short; the
//! rules of the table are in [`super`].

use super::{row, FlagKind, FlagRow};

/// **`cp` / `mv` and their `scp` / `sftp` aliases.** `cp` copies files over
/// SFTP or by exec (T-134, T-135); `mv` copies, then removes each source
/// (T-138).
pub const CP_FLAGS: &[FlagRow] = &[
    // **The `-P` fork, and it is measured rather than remembered.**
    // MEASURED 2026-10-02, this machine, OpenSSH_10.3p1:
    //   `scp` usage prints `[-P port]`, `sftp -h` prints `[-P port]`, and
    //   `ssh` usage prints `[-P tag]`. Three programs, one letter, two meanings.
    row(Some('P'), "port", Some("PORT"), FlagKind::Supported,
        "port to connect to; this is scp's -P", None),
    // Refused by name until their entries build them (T-146, T-143): a
    // flag that parses and does nothing is a promise the binary breaks.
    row(Some('p'), "preserve", None, FlagKind::Refused,
        "keeping the mode and the times of a file is not implemented yet", Some("no flag")),
    row(Some('i'), "identity-file", Some("FILE"), FlagKind::Supported,
        "identity file, repeatable; also -oIdentityFile=", None),
    row(Some('r'), "recursive", None, FlagKind::Refused,
        "copying a directory is not implemented yet", Some("one command for each file")),
    row(Some('F'), "config", Some("CONFIG"), FlagKind::Supported,
        "read this ssh_config file in place of ~/.ssh/config; none reads no file", None),
    row(None, "jsonl", None, FlagKind::Supported,
        "one JSON object per event on stdout", None),
    row(None, "timeout", Some("DURATION"), FlagKind::Supported,
        "bound the transfer; required with no TTY (default: env PODSSH_TIMEOUT)", None),
    // The connection, as `ssh` makes it: the same ids, so `SshArgs` reads
    // them from `cp`'s matches too.
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
];
