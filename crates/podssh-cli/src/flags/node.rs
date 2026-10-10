//! The flag rows of `node`: those of a pair, as `operator` has them, the
//! plain mode (T-263), the node's key and allowlist on each road and the
//! end-to-end channel (T-087, T-088), and those of the iroh road (T-163),
//! which a build has with the feature `iroh` only; in another build,
//! `--iroh` is refused with exit 70. The key's flags of T-163 keep their
//! names beside the new ones.

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
    row(None, "key", Some("FILE"), FlagKind::Supported,
        "the node's key in FILE, on each road, made when missing (default: node-NAME.key in the cache); its fingerprint is said as the node starts", None),
    row(None, "ephemeral-key", None, FlagKind::Supported,
        "a new key for this run only, kept in no file; an operator that pinned the node's key refuses it", None),
    row(None, "allow", Some("FILE"), FlagKind::Supported,
        "the operator keys that may come in, on each road: one key or fingerprint on each line, read again for each session (default: on the pair's road, each operator with the connect token; on the iroh road, none)", None),
    row(None, "no-e2e", None, FlagKind::Supported,
        "carry each session's bytes with no end-to-end channel, to operators that run none either; the relay then sees them", None),
    row(None, "iroh", None, FlagKind::Supported,
        "serve TARGET over the iroh road, with no pair: a client dials the ticket that the node prints; a build with the feature iroh", None),
    row(None, "iroh-key", Some("FILE"), FlagKind::Supported,
        "the same as --key, by its earlier name", None),
    row(None, "iroh-allow", Some("FILE"), FlagKind::Supported,
        "the same as --allow, by its earlier name", None),
    row(None, "iroh-ephemeral", None, FlagKind::Supported,
        "the same as --ephemeral-key, by its earlier name; with --iroh, the ticket lasts as long as the run", None),
    row(None, "iroh-relay", Some("URLS"), FlagKind::Supported,
        "with --iroh: the relays, https://HOST[:PORT][,...]; the first that answers is the home relay (default: env PODSSH_IROH_RELAY, else n0's)", None),
];
