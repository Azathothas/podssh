//! The flag rows of `agent` (T-034): where the agent serves, and the
//! lifetime and the choice of keys for the subcommands that talk to it.

use super::{row, FlagKind, FlagRow};

/// **`agent`.** With no subcommand it serves; `add`, `add-password`,
/// `add-passphrase`, `list`, `remove`, `lock` and `unlock` talk to the agent
/// of `SSH_AUTH_SOCK`.
#[rustfmt::skip]
pub const AGENT_FLAGS: &[FlagRow] = &[
    row(None, "socket", Some("PATH"), FlagKind::Supported,
        "serve on PATH, a socket of mode 0600, or \\\\.\\pipe\\NAME on Windows (default: a new directory of mode 0700 in XDG_RUNTIME_DIR or the temporary directory)", None),
    row(Some('t'), "lifetime", Some("SECONDS"), FlagKind::Supported,
        "add, add-password and add-passphrase: the key or the secret leaves the agent after SECONDS", None),
    row(None, "all", None, FlagKind::Supported,
        "remove: each key of the agent", None),
];
