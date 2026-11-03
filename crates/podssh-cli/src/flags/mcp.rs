//! The flag rows of `mcp` (T-055): the hosts that its tools may reach, the
//! directories of this host that its copies may read and write and whether
//! it keeps sessions (T-488), and the settings of each of its sessions.

use super::{row, FlagKind, FlagRow};

/// **`mcp`.** The commands as tools for an agent, over stdin and stdout.
#[rustfmt::skip]
pub const MCP_FLAGS: &[FlagRow] = &[
    row(None, "allow-host", Some("PATTERN"), FlagKind::Supported,
        "a host that ssh_exec, health, the job_ tools and the copies may reach: [USER@]HOST with * and ?, or !PATTERN to exclude; repeat it (default: none)", None),
    row(None, "allow-dir", Some("DIR"), FlagKind::Supported,
        "a directory of this host that cp_put may read and cp_get may write, links followed and held inside it; repeat it (default: none, and no copy tool); one that holds ~/.ssh or podssh's cache is refused", None),
    row(None, "allow-session", None, FlagKind::Supported,
        "offer the session_ tools, a shell with a pty on an allowed host that outlives each call; the server stops each that it started as it ends", None),
    row(Some('F'), "config", Some("FILE"), FlagKind::Supported,
        "the ssh_config of each session, as podssh ssh -F FILE", None),
    row(None, "direct", None, FlagKind::Supported,
        "each session over TCP with no relay, as podssh ssh --direct", None),
];
