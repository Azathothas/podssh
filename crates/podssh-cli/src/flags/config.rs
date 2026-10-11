//! The flag rows of `config` (T-047): its subcommand `import` takes a format
//! and a file, and no flag.

use super::FlagRow;

/// **`config`.** `import FORMAT FILE` prints `Host` blocks of `ssh_config`
/// from the host list of another tool.
pub const CONFIG_FLAGS: &[FlagRow] = &[];
