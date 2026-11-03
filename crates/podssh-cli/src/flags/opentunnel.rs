//! The flag rows of the OpenTunnel road (T-531): `node`'s road, and `ssh`'s
//! name of a node's race. The road is pure Rust, in each build.

use super::{row, FlagKind, FlagRow};

/// `node --opentunnel`.
#[rustfmt::skip]
pub const NODE_OPENTUNNEL: FlagRow = row(None, "opentunnel", None, FlagKind::Supported,
    "serve TARGET over the OpenTunnel road, a blind TLS tunnel of opentunnel.xyz with no account (or the service of env PODSSH_OPENTUNNEL): one tunnel for the node, kept in the cache; a client dials the name that the node prints, by TLS with no upgrade; beside the pair's road; needs the end-to-end channel, and --allow or a key that the net held here names, whose members are then the door", None);

/// `ssh node://NAME --opentunnel-name HOST`.
#[rustfmt::skip]
pub const SSH_OPENTUNNEL_NAME: FlagRow = row(None, "opentunnel-name", Some("HOST"), FlagKind::Supported,
    "node://NAME: race the OpenTunnel road to HOST, the name that the node prints (ROUTE.ID.opentunnel.xyz), 250 ms after the road before it; the name is kept under NAME, and a later run that gives none dials it when each road before it failed", None);
