//! The flag rows of `man`, apart from the table of verbs so that `flags.rs`
//! stays within 500 lines.

use super::{row, FlagKind, FlagRow};

/// `man`: the manual of this binary, generated from these tables.
#[rustfmt::skip]
pub const MAN_FLAGS: &[FlagRow] = &[
    row(None, "no-pager", None, FlagKind::Supported,
        "write the whole manual to stdout; never page, even on a terminal", None),
    row(None, "roff", None, FlagKind::Supported,
        "write the manual as a man(7) page instead of text, for man -l; never paged", None),
    row(None, "json", None, FlagKind::Supported,
        "write the tables (commands, flags, keywords, variables, files, exit codes) as JSON; never paged", None),
];
