//! The flag rows of a snippet (T-187), the same on `ssh` and `each`, in a
//! file of their own so that `flags.rs` stays under 500 lines. `SSH_FLAGS`
//! and `EACH_FLAGS` name each row in its place.

use super::{row, FlagKind, FlagRow};

/// `--snippet NAME`: a command of the settings file's `[snippets]` in place
/// of a command; the words after the host are its values (`snippets`).
#[rustfmt::skip]
pub const SNIPPET: FlagRow = row(None, "snippet", Some("NAME"), FlagKind::Supported,
    "run the command NAME of the settings file's [snippets]: the words after the host fill its {{1}} to {{9}}, each value quoted; it is shown, and asked, before it runs", None);

/// `--yes`: the answer to the question of `--snippet`, for a run that
/// nobody watches.
#[rustfmt::skip]
pub const YES: FlagRow = row(None, "yes", None, FlagKind::Supported,
    "run the --snippet with no question; its command is still shown on stderr, but with -q", None);
