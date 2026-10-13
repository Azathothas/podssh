//! The flag rows of `ssh` for expect rules (T-191), in a file of their own
//! so that `flags.rs` stays under 500 lines. `SSH_FLAGS` names each row in
//! its place.

use super::{row, FlagKind, FlagRow};

/// `--expect TEXT`: a rule waits for TEXT in the output (`ssh::expect`).
#[rustfmt::skip]
pub const EXPECT: FlagRow = row(None, "expect", Some("TEXT"), FlagKind::Supported,
    "with a pty: wait for TEXT in the output, then send the --send after it; repeatable, the rules in order", None);

/// `--send TEXT`: the keys of the rule before it.
#[rustfmt::skip]
pub const SEND: FlagRow = row(None, "send", Some("TEXT"), FlagKind::Supported,
    "the keys of the --expect before it: \\r, \\n, \\t, \\\\ and \\xNN are read; no secret, as each process reads argv", None);

/// `--expect-timeout TIME`: how long each rule waits.
#[rustfmt::skip]
pub const EXPECT_TIMEOUT: FlagRow = row(None, "expect-timeout", Some("TIME"), FlagKind::Supported,
    "how long each --expect waits, as 30s, 2m or 500ms (default 30s); a miss ends the session with 255", None);
