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
    row(Some('p'), "preserve", None, FlagKind::Supported,
        "keep the access and the modification times too (the mode is kept always), with -r each directory's", None),
    row(None, "owner", None, FlagKind::Supported,
        "keep the owner and the group, by number, where the side that writes may give a file away (root); else a note", None),
    row(None, "inplace", None, FlagKind::Supported,
        "write into the destination itself: its inode and hard links stay, and no second copy needs room; a failure leaves it damaged, which is said first; a link is refused", None),
    row(None, "sparse", None, FlagKind::Supported,
        "a hole for each block of 64 KiB of zeros, whatever the source; without it only a copy up of a sparse file makes holes", None),
    row(Some('i'), "identity-file", Some("FILE"), FlagKind::Supported,
        "identity file, repeatable; also -oIdentityFile=", None),
    row(None, "parallel", Some("K"), FlagKind::Supported,
        "copy a file of more than 8 MiB as chunks, K at once, each over a channel of its own in the one connection (1 to 16; default 1)", None),
    row(None, "delta", None, FlagKind::Supported,
        "over an older version of the file, send only the blocks of 1 MiB that changed; a full copy when the server cannot, or when the digests then differ", None),
    row(Some('r'), "recursive", None, FlagKind::Supported,
        "copy a directory and what it holds, depth first; each link as a link, and a device, FIFO or socket skipped with a note", None),
    row(None, "exclude", Some("PATTERN"), FlagKind::Supported,
        "with -r, leave out a path: * and ? within a name; with a /, from the root of the copy; repeatable", None),
    row(None, "exclude-from", Some("FILE"), FlagKind::Supported,
        "with -r, the --exclude patterns of FILE, one a line; # starts a comment", None),
    row(Some('l'), "limit", Some("KBITS"), FlagKind::Supported,
        "at most KBITS Kbit/s, as OpenSSH's scp -l: a token bucket before each request", None),
    row(None, "delete", None, FlagKind::Supported,
        "with -r, delete what the target has and the source lacks, once each copy succeeded; never an excluded name, the file that a link names, the root or the home directory", None),
    row(None, "dry-run", None, FlagKind::Supported,
        "with -r, say each action (mkdir, copy, link, skip) on stdout, and change nothing", None),
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
