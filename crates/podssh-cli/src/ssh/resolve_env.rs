//! What the process environment gives the resolve of `podssh ssh`: the home,
//! the user, the relay's variables, the CA file and the settings file, apart
//! from `resolve.rs` for the length of that file (T-379).

use std::path::PathBuf;

use podssh_relay::relay;

use super::args::SshArgs;

/// What the process environment contributes, gathered once so it can be
/// replaced in tests.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub home: Option<PathBuf>,
    pub user: Option<String>,
    pub relay: Option<String>,
    /// `PODSSH_RELAY_FAILOVER` (T-220).
    pub relay_failover: Option<String>,
    pub ssl_cert_file: Option<String>,
    /// The local host name and user id, for the `%` tokens.
    pub local_host: Option<String>,
    pub uid: Option<u32>,
    /// `PODSSH_SSH_CONFIG`: the file of `-F`, when `-F` is not given.
    pub ssh_config: Option<String>,
    /// The system's `ssh_config`, read after `~/.ssh/config`; `None` reads
    /// none, as in the tests.
    pub system_config: Option<PathBuf>,
    /// podssh's own settings file (T-048); none in the tests.
    pub settings: crate::settings::Defaults,
}

impl Env {
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let home = var("HOME").or_else(|| if cfg!(windows) { var("USERPROFILE") } else { None }).map(PathBuf::from);
        let user = var("USER").or_else(|| var("LOGNAME")).or_else(|| var("USERNAME")).or_else(uid_zero_is_root);
        Env {
            home,
            user,
            relay: var(relay::RELAY_ENV),
            relay_failover: var(podssh_relay::failover::MODE_ENV),
            ssl_cert_file: var("SSL_CERT_FILE"),
            local_host: super::tokens::local_host_name(),
            uid: super::tokens::local_uid(),
            ssh_config: var("PODSSH_SSH_CONFIG"),
            system_config: Some(super::config::system_file()),
            settings: crate::settings::here().clone(),
        }
    }
}

/// The CA file: `--ca-file`, else `SSL_CERT_FILE`, else the settings
/// file's `CaFile` (T-048).
pub(super) fn ca_file(args: &SshArgs, env: &Env) -> Option<String> {
    crate::settings::ca_file_from(args.ca_file.as_deref(), env.ssl_cert_file.clone(), &env.settings)
}

/// With no user name in the environment, uid 0 is `root` by convention; any
/// other uid has no name podssh may assume (never `getpwuid`: hosts without a
/// passwd entry make OpenSSH fail exactly there).
#[cfg(unix)]
fn uid_zero_is_root() -> Option<String> {
    // SAFETY: getuid has no preconditions.
    (unsafe { libc::getuid() } == 0).then(|| "root".to_string())
}

#[cfg(not(unix))]
fn uid_zero_is_root() -> Option<String> {
    None
}
