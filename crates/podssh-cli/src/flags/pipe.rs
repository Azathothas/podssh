//! The flag rows of `pipe` (T-174, T-175): the settings of the remote
//! addresses, with the ids of `ssh`'s flags, so that `SshArgs` reads them
//! from `pipe`'s matches too. A local address needs none; a listening side
//! may keep listening (T-177).

use super::{row, FlagKind, FlagRow};

/// `pipe`: the relay, the trust, an SSH hop's keys and options, a pair's
/// file, and the iroh road's key and relays.
#[rustfmt::skip]
pub const PIPE_FLAGS: &[FlagRow] = &[
    row(Some('i'), "identity-file", Some("FILE"), FlagKind::Supported,
        "ssh: the identity file of each hop, repeatable; also -oIdentityFile=", None),
    row(Some('o'), "option", Some("NAME=VALUE"), FlagKind::Supported,
        "ssh: an OpenSSH option of the hops, as -o Name=Value; repeatable; one of a session (RequestTTY, RemoteCommand) is refused", None),
    row(Some('v'), "verbose", None, FlagKind::Supported,
        "raise log level; repeatable", None),
    row(Some('q'), "quiet", None, FlagKind::Supported,
        "quiet: no messages from podssh itself, errors included", None),
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts to try in order, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "direct", None, FlagKind::Supported,
        "ssh: reach the first hop without the relay: TCP, through HTTPS_PROXY when one is set", None),
    row(None, "pair-file", Some("FILE"), FlagKind::Supported,
        "node: the pair in FILE, a private file, not the one stored under NAME; its operator's part will do", None),
    row(None, "iroh-key", Some("FILE"), FlagKind::Supported,
        "iroh: this client's key in FILE, made when missing (default: iroh-client.key in the cache)", None),
    row(None, "iroh-relay", Some("URLS"), FlagKind::Supported,
        "iroh: the relays, https://HOST[:PORT][,...], after the ticket's (default: env PODSSH_IROH_RELAY, else n0's)", None),
    row(None, "keep-listening", None, FlagKind::Supported,
        "unix-listen:, tcp-listen: take each client in turn, 8 at once, each with a new instance of the other side, until SIGINT or SIGTERM", None),
];
