//! The flag rows of `play` (T-033): the speed of a recording played again,
//! and the longest wait between two of its events.

use super::{row, FlagKind, FlagRow};

/// **`play`.** A recording of `podssh ssh --record`, or another asciicast v2
/// file, played again on stdout with its timing.
#[rustfmt::skip]
pub const PLAY_FLAGS: &[FlagRow] = &[
    row(None, "speed", Some("FACTOR"), FlagKind::Supported,
        "play this many times as fast, as 2 or 0.5 (default 1)", None),
    row(None, "idle-limit", Some("SECONDS"), FlagKind::Supported,
        "wait this long at most between two events (default: the file's idle_time_limit, else no limit)", None),
];
