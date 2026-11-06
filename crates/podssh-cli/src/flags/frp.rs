//! The flag row of the frp road (T-498): `node`'s road through the user's
//! own frps. Its clients name the same file in `PODSSH_FRP`.

use super::{row, FlagKind, FlagRow};

/// `node --frp FILE`.
#[rustfmt::skip]
pub const NODE_FRP: FlagRow = row(None, "frp", Some("FILE"), FlagKind::Supported,
    "serve TARGET through your own frps, as an STCP service of NAME with no public port: FILE, a private file, names frps (frp://HOST[:PORT] or wss://HOST[:PORT][/PATH]), its token and the service's secret, a line each; a client names the same file in env PODSSH_FRP; the road alone, with no pair; needs the end-to-end channel, and --allow or a key that the net held here names, whose members are then the door", None);
