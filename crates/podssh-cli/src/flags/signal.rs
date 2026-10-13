//! The flag row of `ssh` for Ctrl-C with no remote pty (T-293), in a file of
//! its own so that `flags.rs` stays under 500 lines. `SSH_FLAGS` names it in
//! its place.

use super::{row, FlagKind, FlagRow};

/// `--no-signal`: Ctrl-C ends podssh at once, as OpenSSH's ssh does, and no
/// `signal INT` goes to the command.
#[rustfmt::skip]
pub const NO_SIGNAL: FlagRow = row(None, "no-signal", None, FlagKind::Supported,
    "with no pty, Ctrl-C ends podssh at once, as OpenSSH's ssh; by default it sends signal INT to the command first", None);
