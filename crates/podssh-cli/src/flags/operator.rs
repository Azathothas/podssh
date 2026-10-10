//! The flag rows of `operator`: those of a pair, and those of the end-to-end
//! channel (T-087, T-088): this operator's key, the node's key in place of
//! the pins, and the switch that turns the channel off.

use super::{row, FlagKind, FlagRow};

/// `operator` (T-084): a pipe, with no `--timeout`; and the channel's flags.
pub const PAIR_FLAGS: &[FlagRow] = &[
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "pair-file", Some("FILE"), FlagKind::Supported,
        "use the pair in FILE, a private file, not the one stored under NAME (operator: its operator's part will do)", None),
    row(None, "client-key", Some("FILE"), FlagKind::Supported,
        "this operator's key in FILE, made when missing (default: client.key in the cache), which a node's allowlist may name", None),
    row(None, "node-key", Some("KEY"), FlagKind::Supported,
        "the node's key, or its fingerprint SHA256:..., in place of the pins of known-nodes", None),
    row(None, "no-e2e", None, FlagKind::Supported,
        "carry the bytes with no end-to-end channel, to a node that runs none either; the relay then sees them", None),
];
