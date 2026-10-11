//! The flag rows of `mcp` (T-055): the hosts that its tool `ssh_exec` may
//! reach, and the settings of each of its sessions.

use super::{row, FlagKind, FlagRow};

/// **`mcp`.** The commands as tools for an agent, over stdin and stdout.
#[rustfmt::skip]
pub const MCP_FLAGS: &[FlagRow] = &[
    row(None, "allow-host", Some("PATTERN"), FlagKind::Supported,
        "a host that ssh_exec may reach: [USER@]HOST with * and ?, or !PATTERN to exclude; repeat it (default: none)", None),
    row(Some('F'), "config", Some("FILE"), FlagKind::Supported,
        "the ssh_config of each session, as podssh ssh -F FILE", None),
    row(None, "direct", None, FlagKind::Supported,
        "each session over TCP with no relay, as podssh ssh --direct", None),
];
