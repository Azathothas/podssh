//! The flag rows of `share` (T-433): a running node's local services by
//! name, for its net, as Tailscale's serve offers a node's; and the node's
//! `--shares FILE`, the file that both read.

use super::{row, FlagKind, FlagRow};

/// `node --shares FILE`.
#[rustfmt::skip]
pub const NODE_SHARES: FlagRow = row(None, "shares", Some("FILE"), FlagKind::Supported,
    "the node's shares in FILE, NAME=HOST:PORT on each line, read again for each session, so that podssh share adds and removes one while the node runs; an operator reaches one as node://NAME/SHARE, as a route (default: node-NAME.shares in the cache); not with --no-e2e, --temporary, --quick-tunnel or a udp: TARGET", None);

/// `share`.
#[rustfmt::skip]
pub const SHARE_FLAGS: &[FlagRow] = &[
    row(None, "node", Some("NAME"), FlagKind::Supported,
        "add, rm and ls: the node of this host whose shares, as podssh node NAME names it (default: the one node of this host whose key or shares are in the cache)", None),
    row(None, "shares", Some("FILE"), FlagKind::Supported,
        "add, rm and ls: the share file that a node reads when its own flag of this name names it, in place of node-NAME.shares in the cache", None),
    row(None, "net", None, FlagKind::Supported,
        "ls: the shares that the net held here lists for each member, as its owner wrote them with podssh net add NAME KEY --shares NAMES, in place of this host's", None),
];
