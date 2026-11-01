//! The rows of a run in the background: `-f` and `--restart` of `ssh`
//! (T-380, T-390), `--detach-name` of `ssh`, `pipe` and `node` (T-392), and
//! the table of `podssh detached`, which takes no flag. A module of its own
//! so that `flags.rs` stays short.

use super::{row, FlagKind, FlagRow};

/// `ssh`: OpenSSH's `-f`, and `--detach` of each command that serves.
pub const SSH_DETACH: FlagRow = row(Some('f'), "detach", None, FlagKind::Supported,
    "go to the background once logged in and the request went, with a command or -N (see --detach)", None);

/// `ssh`: the supervisor of a detached run.
pub const SSH_RESTART: FlagRow = row(None, "restart", None, FlagKind::Supported,
    "with -f or --detach: a small process in the background starts the run again whenever it ends, but after 64, 77 or 78 or a stop of that process; it never gives up (T-390)", None);

/// `ssh`, `pipe` and `node`: the name of a detached run.
pub const DETACH_NAME: FlagRow = row(None, "detach-name", Some("NAME"), FlagKind::Supported,
    "with --detach: the run's name, letters, digits, _ and -, 64 at most; a second start of a name that runs refuses (75), and podssh detached shows and stops it (default: the verb and the pid)", None);

/// **`detached`.** `list`, `status NAME` and `stop NAME`: the subcommand
/// and the name are its arguments, and it takes no flag.
pub const DETACHED_FLAGS: &[FlagRow] = &[];
