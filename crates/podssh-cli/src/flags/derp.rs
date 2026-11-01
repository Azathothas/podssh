//! The flag rows of the DERP road (T-379): `ssh`'s ticket of a node's race
//! and its servers, and `node`'s road and its servers. The road is pure
//! Rust, in each build.

use super::{row, FlagKind, FlagRow};

/// `ssh node://NAME --derp-ticket TICKET`.
#[rustfmt::skip]
pub const DERP_TICKET: FlagRow = row(None, "derp-ticket", Some("TICKET"), FlagKind::Supported,
    "node://NAME: race the DERP road to TICKET, after the iroh road and the pair's road; the ticket is kept under NAME, and a later run that gives none dials it when the roads before it fail", None);

/// `ssh --derp-server SERVERS`.
#[rustfmt::skip]
pub const SSH_DERP_SERVER: FlagRow = row(None, "derp-server", Some("SERVERS"), FlagKind::Supported,
    "derp:TICKET and node://NAME: the DERP servers to try after the ticket's, HOST[:PORT][,...] (default: env PODSSH_DERP_SERVER, else Tailscale's tailcat fleet)", None);

/// `node --derp`.
#[rustfmt::skip]
pub const NODE_DERP: FlagRow = row(None, "derp", None, FlagKind::Supported,
    "serve TARGET over the DERP road, through Tailscale's tailcat fleet: a client dials the ticket that the node prints; beside the pair's road and the iroh road; needs --allow and the end-to-end channel", None);

/// `node --derp-server SERVERS`.
#[rustfmt::skip]
pub const NODE_DERP_SERVER: FlagRow = row(None, "derp-server", Some("SERVERS"), FlagKind::Supported,
    "with --derp: the DERP servers, HOST[:PORT][,...]; the first whose /derp/probe answers is the home, and after 3 failed connections the next that takes one (default: env PODSSH_DERP_SERVER, else tailcat's)", None);
