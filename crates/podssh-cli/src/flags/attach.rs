//! The flag rows of `ssh` for a shell that the far end keeps (T-158), in a
//! file of their own so that `flags.rs` stays under 500 lines.
//! `SSH_FLAGS` names each row in its place.

use super::{row, FlagKind, FlagRow};

/// `--attach NAME DEST` joins a kept shell; `--attach DEST`, with no other
/// word, lists them (`ssh::attach`).
#[rustfmt::skip]
pub const ATTACH: FlagRow = row(None, "attach", Some("NAME"), FlagKind::Supported,
    "node://NAME: join the shell that the far end keeps as NAME, which ~d left; --attach DEST alone lists the kept shells", None);

/// `--take`: the far end gives one client a shell at a time.
#[rustfmt::skip]
pub const TAKE: FlagRow = row(None, "take", None, FlagKind::Supported,
    "with --attach NAME: take the shell from the client that has it, whose session ends", None);
