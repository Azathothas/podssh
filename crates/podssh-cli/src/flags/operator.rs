//! The flag rows of `operator`: those of a pair, and those of the end-to-end
//! channel (T-087, T-088): this operator's key, the node's key in place of
//! the pins, and the switch that turns the channel off. And the bound on a
//! pipe's open, `--ConnectTimeout`, of `operator`, `proxy` and `pipe` (T-589);
//! and `--carrier` of the other clients of a node (T-595).

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
    super::node::OWN_DEADLINE,
    OPERATOR_CONNECT_TIMEOUT,
    // The node at the other end of a stream that exists already (T-595).
    row(None, "carrier", Some("ADDR"), FlagKind::Supported,
        "reach the node at the other end of ADDR, a stream that exists already, with no relay and no pair: exec:CMD, a program started with no shell, as exec:'ssh -T HOST podssh node --carrier stdio NAME TARGET', or fd:N (Unix); NAME is then the label under which the node's key is pinned", None),
];

/// `--carrier ADDR` of `ssh`, `cp`, `mv`, `scp` and `sftp` (T-595).
pub const SSH_CARRIER: FlagRow = row(None, "carrier", Some("ADDR"), FlagKind::Supported,
    "node://NAME: reach the node at the other end of ADDR, a stream that exists already, as its one road, with no relay and no pair: exec:CMD, a program started with no shell, as exec:'ssh -T HOST podssh node --carrier stdio NAME TARGET', or fd:N (Unix); NAME is then the label under which the node's key is pinned", None);

/// `--carrier ADDR` of `proxy node://NAME` (T-595), as `operator` takes it.
pub const PROXY_CARRIER: FlagRow = row(None, "carrier", Some("ADDR"), FlagKind::Supported,
    "node://NAME: reach the node at the other end of ADDR, a stream that exists already, with no relay and no pair, as podssh operator --carrier does: exec:CMD, a program started with no shell, or fd:N (Unix); NAME is then the label under which the node's key is pinned", None);

/// `--carrier ADDR` of `pipe`'s `node:` side (T-595).
pub const PIPE_CARRIER: FlagRow = row(None, "carrier", Some("ADDR"), FlagKind::Supported,
    "node: and udp:node:: reach the node at the other end of ADDR, a stream that exists already, with no relay and no pair, as podssh operator --carrier does: exec:CMD, a program started with no shell, or fd:N (Unix); each client of a listening side is a session of the one stream", None);

/// `--ConnectTimeout` of `operator` (T-589).
pub const OPERATOR_CONNECT_TIMEOUT: FlagRow = row(None, "ConnectTimeout", Some("SECONDS"), FlagKind::Supported,
    "the bound on the time to the session's open, 1 to 86400: the relay's answer, the node's ready, and the handshakes of the layer and of the channel, each within its own limit too; past it one line names the step that waited, and the exit is 69; never the bytes after the open", None);
/// `--ConnectTimeout` of `proxy` (T-589).
pub const PROXY_CONNECT_TIMEOUT: FlagRow = row(None, "ConnectTimeout", Some("SECONDS"), FlagKind::Supported,
    "the bound on the time to the session's open, 1 to 86400: the relay's answer (each host's dial, TLS, the upgrade, its dial of HOST), or that of the road in its place, or the steps of node://NAME as operator has them; past it one line names the step that waited, and the exit is 69; never the bytes after the open", None);
/// `--ConnectTimeout` of `pipe` (T-589).
pub const PIPE_CONNECT_TIMEOUT: FlagRow = row(None, "ConnectTimeout", Some("SECONDS"), FlagKind::Supported,
    "node: and relay:: the bound on the time to the session's open, as operator and proxy take it, with no listening side; ssh:: each hop's ConnectTimeout too, and with no node: or relay: side the hops' alone", None);
