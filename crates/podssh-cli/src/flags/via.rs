//! The rows of `--via` and `--via-auth-file` (T-439): a forward proxy over
//! TLS that the user runs, in place of the relay, for `ssh` and each command
//! that reaches its server as `ssh` does, for `proxy` and `pipe`, and for
//! `doctor`, which checks it.

use super::{row, FlagKind, FlagRow};

/// `ssh`, `cp`, `each`, `proxy`, `pipe` and the others of `ssh`'s road.
pub const VIA: FlagRow = row(None, "via", Some("https://[USER@]HOST[:PORT]"), FlagKind::Supported,
    "reach the first hop through a forward proxy over TLS that you run (Caddy's forwardproxy, squid's \
     https_port), in place of the relay: TLS to it, through HTTPS_PROXY when one is set, then CONNECT inside, \
     HTTP/2 when it chooses h2, else HTTP/1.1; also env PODSSH_VIA", None);

/// The same commands, and `doctor`.
pub const VIA_AUTH_FILE: FlagRow = row(None, "via-auth-file", Some("FILE"), FlagKind::Supported,
    "the Basic credentials of --via in FILE, a private file: one line, USER:PASSWORD, or the password alone \
     when the URL names USER; never in the URL; also env PODSSH_VIA_AUTH_FILE", None);

/// `doctor`.
pub const DOCTOR_VIA: FlagRow = row(None, "via", Some("https://[USER@]HOST[:PORT]"), FlagKind::Supported,
    "also check this forward proxy over TLS: TLS to it, the version of HTTP that it chose, then one of \
     GitHub's published host keys on github.com port 22 through its CONNECT (default: env PODSSH_VIA)", None);
