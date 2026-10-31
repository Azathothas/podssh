//! The flag rows of the verbs of the relay itself: `relay`, `proxy`,
//! `doctor` and `status`, each with the relay's settings that it reads.

use super::{row, FlagKind, FlagRow};

/// `relay`: the pairs of the reverse road (T-083). Each request has its
/// own bound, so there is no `--timeout` (T-058).
#[rustfmt::skip]
pub const RELAY_FLAGS: &[FlagRow] = &[
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts, HOST[:PORT][,...]: status asks each, and pair, info and trace use the first (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "operator-file", Some("FILE"), FlagKind::Supported,
        "pair: write the operator's part of the pair to FILE, a new file that only its owner can read", None),
    row(None, "document", Some("FILE"), FlagKind::Supported,
        "spec: check FILE, a copy of the relay's document, and read nothing from the network", None),
    row(None, "json", None, FlagKind::Supported,
        "status with no NAME, info and trace: the answer as one JSON object on stdout, when the run ends", None),
];

/// **`proxy`.** It is **not an SSH client** (`podssh man proxy`), so not an alias of `ssh`,
/// and behaves differently, so it gets its own flag list rather than sharing
/// `ssh`'s. Sharing them is exactly how the nested-SSH mistake (an SSH client
/// as OpenSSH's ProxyCommand) gets invited.
#[rustfmt::skip]
pub const PROXY_FLAGS: &[FlagRow] = &[
    row(None, "stdin-stdout", None, FlagKind::Supported,
        "a byte pipe on stdin/stdout; not an SSH client", None),
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts to try in order, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-failover", Some("MODE"), FlagKind::Supported,
        "how the relay hosts are tried: staggered (the next starts after 2 s or a failure; the default), parallel or serial; also env PODSSH_RELAY_FAILOVER", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    super::forwarder::PROXY_FORWARDER,
];

/// `doctor` checks the relay path `ssh` and `proxy` would take, so it takes
/// their relay settings.
#[rustfmt::skip]
pub const DOCTOR_FLAGS: &[FlagRow] = &[
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts to check, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-failover", Some("MODE"), FlagKind::Supported,
        "how the relay hosts are tried: staggered (the next starts after 2 s or a failure; the default), parallel or serial; also env PODSSH_RELAY_FAILOVER", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "json", None, FlagKind::Supported,
        "write the report as one JSON object on stdout, when every check has run", None),
    row(None, "full", None, FlagKind::Supported,
        "also log in to github.com through the relay with a key made for the check, which GitHub refuses, and, with no \
         proxy set, make a QUIC handshake with the quick tunnel's edge", None),
    super::forwarder::DOCTOR_FORWARDER,
];

/// `status`: the relay settings that it reports, as `doctor` takes them.
#[rustfmt::skip]
pub const STATUS_FLAGS: &[FlagRow] = &[
    row(None, "relay-host", Some("HOSTS"), FlagKind::Supported,
        "relay hosts to report, HOST[:PORT][,...] (default: env PODSSH_RELAY, else the built-in relay and its pool)", None),
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
];
