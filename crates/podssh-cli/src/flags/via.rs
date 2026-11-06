//! The rows of `--via` and `--via-auth-file` (T-439): a forward proxy over
//! TLS that the user runs, in place of the relay, for `ssh` and each command
//! that reaches its server as `ssh` does, for `proxy` and `pipe`, and for
//! `doctor`, which checks it. And those of `--wstunnel` and
//! `--wstunnel-secret-file` (T-441), a wstunnel server that the user runs,
//! for `ssh`, the commands of its road and `proxy`; and those of `--chisel`
//! and `--chisel-auth-file` (T-490), a chisel server that the user runs, for
//! the same commands: each is a road of Q66 to a server of the user's own.

use super::{row, FlagKind, FlagRow};

/// `ssh`, `cp`, `each`, `proxy`, `pipe` and the others of `ssh`'s road.
pub const VIA: FlagRow = row(
    None,
    "via",
    Some("https://[USER@]HOST[:PORT]"),
    FlagKind::Supported,
    "reach the first hop through a forward proxy over TLS that you run (Caddy's forwardproxy, squid's \
     https_port), in place of the relay: TLS to it, through HTTPS_PROXY when one is set, then CONNECT inside, \
     HTTP/2 when it chooses h2, else HTTP/1.1; also env PODSSH_VIA",
    None,
);

/// The same commands, and `doctor`.
pub const VIA_AUTH_FILE: FlagRow = row(
    None,
    "via-auth-file",
    Some("FILE"),
    FlagKind::Supported,
    "the Basic credentials of --via in FILE, a private file: one line, USER:PASSWORD, or the password alone \
     when the URL names USER; never in the URL; also env PODSSH_VIA_AUTH_FILE",
    None,
);

/// `doctor`.
pub const DOCTOR_VIA: FlagRow = row(
    None,
    "via",
    Some("https://[USER@]HOST[:PORT]"),
    FlagKind::Supported,
    "also check this forward proxy over TLS: TLS to it, the version of HTTP that it chose, then one of \
     GitHub's published host keys on github.com port 22 through its CONNECT (default: env PODSSH_VIA)",
    None,
);

/// `ssh`, `cp`, `each`, `proxy` and the others of `ssh`'s road.
pub const WSTUNNEL: FlagRow = row(
    None,
    "wstunnel",
    Some("wss://HOST[:PORT]"),
    FlagKind::Supported,
    "reach the first hop through a wstunnel server that you run (wstunnel server wss://[::]:443), in place of \
     the relay: the WebSocket to it, through HTTPS_PROXY when one is set, its token naming the target; ws:// \
     has no TLS; also env PODSSH_WSTUNNEL",
    None,
);

/// The same commands.
pub const WSTUNNEL_SECRET_FILE: FlagRow = row(
    None,
    "wstunnel-secret-file",
    Some("FILE"),
    FlagKind::Supported,
    "what the server of --wstunnel checks, in FILE, a private file: path-prefix PREFIX, credentials \
     USER[:PASSWORD] or authorization VALUE, or the prefix alone; never in the URL; also env \
     PODSSH_WSTUNNEL_SECRET_FILE",
    None,
);

/// `ssh`, `cp`, `each`, `proxy` and the others of `ssh`'s road (T-490).
pub const CHISEL: FlagRow = row(
    None,
    "chisel",
    Some("https://HOST[:PORT][/PATH]"),
    FlagKind::Supported,
    "reach the first hop through a chisel server that you run (chisel server --port 443 --auth USER:PASS), \
     in place of the relay: its WebSocket, through HTTPS_PROXY when one is set, then SSH inside it and a \
     channel to the target; http:// to this host alone; also env PODSSH_CHISEL",
    None,
);

/// The same commands.
pub const CHISEL_AUTH_FILE: FlagRow = row(
    None,
    "chisel-auth-file",
    Some("FILE"),
    FlagKind::Supported,
    "what the server of --chisel takes and shows, in FILE, a private file: auth USER:PASSWORD, as chisel's \
     --auth, and fingerprint BASE64, the key that chisel server prints, which podssh then checks; never in \
     the URL; also env PODSSH_CHISEL_AUTH_FILE",
    None,
);
