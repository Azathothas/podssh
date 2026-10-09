//! The flag rows of `node`: those of a pair, as `operator` has them, the
//! plain mode (T-263), and those of the iroh road (T-163), which a build has
//! with the feature `iroh` only; in another build, `--iroh` is refused with
//! exit 70.

use super::{row, FlagKind, FlagRow};

/// `node` (T-083, T-163): the flags of a pair, and those of the iroh road,
/// which a build has with the feature `iroh` only.
pub const NODE_FLAGS: &[FlagRow] = &[
    row(None, "relay-addr", Some("HOST=IP"), FlagKind::Supported,
        "use IP for HOST instead of DNS, HOST=IP[,...]; also env PODSSH_RELAY_ADDR (for hosts with no DNS)", None),
    row(None, "ca-file", Some("FILE"), FlagKind::Supported,
        "trust only the CA certificates in FILE (default: env SSL_CERT_FILE, else system and built-in roots)", None),
    row(None, "pair-file", Some("FILE"), FlagKind::Supported,
        "use the pair in FILE, a private file, not the one stored under NAME (operator: its operator's part will do)", None),
    row(None, "plain", None, FlagKind::Supported,
        "carry each session's bytes as they are, with no resumable layer, for an operator that does not speak it; a lost link ends the session", None),
    row(None, "iroh", None, FlagKind::Supported,
        "serve TARGET over the iroh road, with no pair: a client dials the ticket that the node prints; a build with the feature iroh", None),
    row(None, "iroh-key", Some("FILE"), FlagKind::Supported,
        "with --iroh: the node's key in FILE, made when missing (default: iroh-node-NAME.key in the cache)", None),
    row(None, "iroh-allow", Some("FILE"), FlagKind::Supported,
        "with --iroh: the client keys that may connect, one on each line, read again for each connection (default: none may)", None),
    row(None, "iroh-ephemeral", None, FlagKind::Supported,
        "with --iroh: a new key for this run only, kept in no file; the ticket lasts as long as the run", None),
    row(None, "iroh-relay", Some("URLS"), FlagKind::Supported,
        "with --iroh: the relays, https://HOST[:PORT][,...]; the first that answers is the home relay (default: env PODSSH_IROH_RELAY, else n0's)", None),
];
