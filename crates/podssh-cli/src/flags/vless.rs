//! The rows of `--vless` (T-440): VLESS servers that the user runs, in
//! place of the relay, for `ssh` and each command that reaches its server as
//! `ssh` does, for `proxy`, and for `doctor`, which checks each server; and
//! of `--trojan` (T-491), Trojan servers of a file, read as `--vless` reads
//! its own.

use super::{row, FlagKind, FlagRow};

/// `ssh`, `cp`, `each` and the others of `ssh`'s road.
pub const VLESS: FlagRow = row(
    None,
    "vless",
    Some("FILE"),
    FlagKind::Supported,
    "reach the first hop through VLESS servers that you run (Xray-core, shoes), in order, in place of the relay: \
     FILE is private, with a vless:// share link on each line, over a WebSocket (type=ws) or XHTTP on HTTP/2 \
     (type=xhttp), which passes where a proxy refuses the upgrade",
    None,
);

/// `proxy`.
pub const PROXY_VLESS: FlagRow = row(
    None,
    "vless",
    Some("FILE"),
    FlagKind::Supported,
    "reach the target through the VLESS servers of FILE, in order, in place of the relay: vless:// share links \
     in a private file",
    None,
);

/// `doctor`.
pub const DOCTOR_VLESS: FlagRow = row(
    None,
    "vless",
    Some("FILE"),
    FlagKind::Supported,
    "also check each VLESS server of FILE, on each mode of XHTTP where its link says auto: the transport that \
     carried it, then one of GitHub's published host keys on github.com port 22 through it",
    None,
);

/// `--trojan` for `ssh`, `cp`, `each` and the others of `ssh`'s road (T-491).
pub const TROJAN: FlagRow = row(
    None,
    "trojan",
    Some("FILE"),
    FlagKind::Supported,
    "reach the first hop through Trojan servers that you run (trojan-gfw, trojan-go, Xray-core), in order, in \
     place of the relay: FILE is private, with a trojan:// share link on each line, in TLS alone (type=tcp) or \
     in a WebSocket over TLS (type=ws)",
    None,
);

/// `--trojan` for `proxy`.
pub const PROXY_TROJAN: FlagRow = row(
    None,
    "trojan",
    Some("FILE"),
    FlagKind::Supported,
    "reach the target through the Trojan servers of FILE, in order, in place of the relay: trojan:// share links \
     in a private file",
    None,
);
