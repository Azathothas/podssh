//! The flag rows of `ssh` and `proxy` for the warning before the relay's idle
//! cut (T-463), in a file of their own so that `flags.rs` stays under 500
//! lines. `SSH_FLAGS` and `PROXY_FLAGS` name each row in its place.

use super::{row, FlagKind, FlagRow};

/// `--idle-warn SECONDS` of `ssh`.
#[rustfmt::skip]
pub const IDLE_WARN: FlagRow = row(None, "idle-warn", Some("SECONDS"), FlagKind::Supported,
    "through the relay: warn this long before its idle cut, once nothing crossed for the rest of it (default 30; 0: no warning; none with -q)", None);

/// `--idle-warn SECONDS` of `proxy`, whose stderr its SSH client shows.
#[rustfmt::skip]
pub const PROXY_IDLE_WARN: FlagRow = row(None, "idle-warn", Some("SECONDS"), FlagKind::Supported,
    "warn on stderr this long before the relay's idle cut, once nothing crossed for the rest of it (default 30; 0: no warning)", None);
