//! The rows of `--shadowsocks` (T-373): for `ssh` and each command that
//! reaches its server as `ssh` does, for `proxy`, and for `doctor`, which
//! checks the first server.

use super::{row, FlagKind, FlagRow};

/// `ssh`, `cp`, `each` and the others of `ssh`'s road.
pub const SHADOWSOCKS: FlagRow = row(None, "shadowsocks", Some("FILE"), FlagKind::Supported,
    "reach the first hop through Shadowsocks servers, in order, in place of the relay: FILE is private, with \
     ss:// lines (chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm; no plugin) and subscription https://URL \
     lines", None);

/// `proxy`.
pub const PROXY_SHADOWSOCKS: FlagRow = row(None, "shadowsocks", Some("FILE"), FlagKind::Supported,
    "reach the target through the Shadowsocks servers of FILE, in order, in place of the relay: ss:// lines and \
     subscription https://URL lines, in a private file", None);

/// `doctor`.
pub const DOCTOR_SHADOWSOCKS: FlagRow = row(None, "shadowsocks", Some("FILE"), FlagKind::Supported,
    "also check the first Shadowsocks server of FILE: TCP, the server's salt, then one of GitHub's published host \
     keys on github.com port 22 through it", None);
