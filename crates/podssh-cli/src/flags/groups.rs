//! The verbs by purpose, apart from the flag table so that `flags.rs`
//! stays one file of 500 lines or fewer.

/// **The verbs by purpose, in the order that `--help` and the manual print
/// them** (T-013). Each verb is in one group, as a test of the flag table
/// holds; a purpose does not change between releases and builds, as a list
/// of the commands that work would.
pub const GROUPS: &[(&str, &[&str])] = &[
    ("Connect", &["ssh", "each", "containers", "proxy", "pipe", "ts"]),
    ("Work on a host", &["run", "job"]),
    ("Copy files", &["cp", "mv", "scp", "sftp", "edit"]),
    ("Keys", &["keygen", "agent"]),
    ("Check this host and the path", &["doctor", "status", "ping", "health"]),
    ("The reverse road", &["node", "operator", "net", "exit", "share"]),
    ("Runs in the background", &["detached"]),
    ("Messages", &["chat"]),
    ("Recordings", &["play"]),
    ("Settings", &["config"]),
    ("Tools for an agent", &["mcp", "session"]),
    ("The relay", &["relay"]),
    ("This manual", &["man"]),
    ("This binary", &["update"]),
];
