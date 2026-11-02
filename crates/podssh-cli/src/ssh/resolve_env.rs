//! What the process environment gives the resolve of `podssh ssh`: the home,
//! the user, the relay's variables, the CA file and the settings file, apart
//! from `resolve.rs` for the length of that file (T-379).
//!
//! The local user's name (T-500, the operator's ruling Q68) is the first of
//! [`USER_VARIABLES`] that is set, then the name of the effective uid's entry
//! in the user database, then `root` for uid 0. A host with no entry, where
//! OpenSSH's own tools refuse to run, goes on with no name, and a login that
//! needs one is refused with what was read and what to do.

use std::path::PathBuf;

use podssh_relay::relay;

use super::args::SshArgs;

/// The variables that name the local user, in their order (Q68): podssh's
/// own, then those that shells and Windows set.
pub const USER_VARIABLES: [&str; 4] = ["PODSSH_USER", "USER", "LOGNAME", "USERNAME"];

/// The user database, as the lines of `-v` and of a refusal name it.
#[cfg(not(target_os = "macos"))]
const DATABASE: &str = "/etc/passwd";
#[cfg(target_os = "macos")]
const DATABASE: &str = "the user database";

/// The file of the user database, read as a file: a static binary has no
/// NSS, and the file is what each C library reads first.
#[cfg(unix)]
const PASSWD: &str = "/etc/passwd";

/// The most of that file that is read: a file synced from a directory can be
/// large, and an entry past this is not looked for.
#[cfg(unix)]
const PASSWD_MOST: u64 = 16 << 20;

/// What a refusal and a line of `-v` say was read and found empty.
const NOT_SET: &str = "PODSSH_USER, USER, LOGNAME and USERNAME are not set";

/// What the process environment contributes, gathered once so it can be
/// replaced in tests.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub home: Option<PathBuf>,
    pub user: Option<String>,
    /// Where `user` came from, for `-v` and the refusal (T-500).
    pub user_from: UserFrom,
    pub relay: Option<String>,
    /// `PODSSH_RELAY_FAILOVER` (T-220).
    pub relay_failover: Option<String>,
    /// `PODSSH_DIRECT`: whether the direct road follows the relay hosts
    /// (T-363).
    pub direct: Option<String>,
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
        let local = local_user();
        Env {
            home,
            user: local.name,
            user_from: local.from,
            relay: var(relay::RELAY_ENV),
            relay_failover: var(podssh_relay::failover::MODE_ENV),
            direct: var(crate::relay_settings::DIRECT_ENV),
            ssl_cert_file: var("SSL_CERT_FILE"),
            local_host: super::tokens::local_host_name(),
            uid: super::tokens::local_uid(),
            ssh_config: var("PODSSH_SSH_CONFIG"),
            system_config: Some(super::config::system_file()),
            settings: crate::settings::here().clone(),
        }
    }

    /// The local user's name as the login, when nothing else names one; else
    /// the refusal, which says what was read and what to do. `hop` names a
    /// jump host, whose user `-l` does not give, as in OpenSSH.
    pub fn login_user(&self, hop: Option<&str>) -> Result<String, String> {
        self.user.clone().ok_or_else(|| self.user_from.refusal(hop))
    }

    /// The line of `-v` that says where the local user's name came from,
    /// when no variable gave it.
    pub fn user_note(&self) -> Option<String> {
        self.user_from.note(self.user.as_deref()?)
    }
}

/// Where the local user's name came from (T-500).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum UserFrom {
    /// One of [`USER_VARIABLES`], or a value that a test gave.
    #[default]
    Variable,
    /// The entry of this effective uid in the user database.
    Entry { uid: u32 },
    /// uid 0 with no entry: `root`, by convention.
    Root,
    /// No name: no variable, and no entry for this uid; no uid on a system
    /// that has none.
    Missing { uid: Option<u32> },
}

impl UserFrom {
    /// The refusal of a login with no user name: what was read, then each
    /// way to give one. `hop` names a jump host.
    pub fn refusal(&self, hop: Option<&str>) -> String {
        let head = match hop {
            Some(host) => format!("no user name for the jump host {host}"),
            None => "no user name".to_string(),
        };
        let read = match self {
            UserFrom::Missing { uid: Some(uid) } => format!("{NOT_SET}, and uid {uid} has no entry in {DATABASE}"),
            _ => NOT_SET.to_string(),
        };
        let give = if hop.is_some() { "give one as user@host in -J" } else { "give user@host or -l USER" };
        format!("{head}: {read}: {give}, set PODSSH_USER or USER, or set User in ssh_config")
    }

    /// The line of `-v` for `name`, when no variable gave it.
    pub fn note(&self, name: &str) -> Option<String> {
        match self {
            UserFrom::Entry { uid } => {
                Some(format!("the local user name {name} is uid {uid}'s entry in {DATABASE}, as {NOT_SET}"))
            }
            UserFrom::Root => Some(format!(
                "the local user name {name} is uid 0's by convention, as {NOT_SET} and uid 0 has no entry in \
                 {DATABASE}"
            )),
            UserFrom::Variable | UserFrom::Missing { .. } => None,
        }
    }
}

/// The local user's name, and where it came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalUser {
    pub name: Option<String>,
    pub from: UserFrom,
}

/// The local user of this process: the login, the `%u` token, `Match
/// localuser`, the nick of `chat` and the comment of `keygen` take it.
pub fn local_user() -> LocalUser {
    local_user_from(&|name| std::env::var(name).ok(), effective_uid(), &entry_of)
}

/// The local user from `var`, else from the entry of `uid` that `entry`
/// reads, else `root` for uid 0. A variable that is set wins; a blank one is
/// not set.
fn local_user_from(
    var: &dyn Fn(&str) -> Option<String>,
    uid: Option<u32>,
    entry: &dyn Fn(u32) -> Option<String>,
) -> LocalUser {
    if let Some(name) = USER_VARIABLES.into_iter().find_map(|n| var(n).filter(|v| !v.trim().is_empty())) {
        return LocalUser { name: Some(name), from: UserFrom::Variable };
    }
    let Some(uid) = uid else { return LocalUser { name: None, from: UserFrom::Missing { uid: None } } };
    match entry(uid) {
        Some(name) => LocalUser { name: Some(name), from: UserFrom::Entry { uid } },
        None if uid == 0 => LocalUser { name: Some("root".into()), from: UserFrom::Root },
        None => LocalUser { name: None, from: UserFrom::Missing { uid: Some(uid) } },
    }
}

/// The name of the first entry of `uid` in the text of a passwd file, whose
/// lines are `name:password:uid:gid:gecos:home:shell`. A comment, a line of
/// NIS (`+` or `-`), a line with too few fields and a name with a blank or a
/// control character are passed over, as the C library passes them over.
#[cfg_attr(not(unix), allow(dead_code))]
fn passwd_name(text: &str, uid: u32) -> Option<String> {
    text.lines().filter(|line| !line.starts_with(['#', '+', '-'])).find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        let name = fields[0];
        let usable = fields.len() >= 7
            && !name.is_empty()
            && !name.chars().any(|c| c.is_whitespace() || c.is_control() || c == char::REPLACEMENT_CHARACTER);
        (usable && fields[2].parse::<u32>().is_ok_and(|u| u == uid)).then(|| name.to_string())
    })
}

/// The entry of `uid` in `/etc/passwd`, read as a file: one that is missing,
/// unreadable or with no such line gives none, and no error.
#[cfg(unix)]
fn passwd_file_entry(uid: u32) -> Option<String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(PASSWD).ok()?.take(PASSWD_MOST).read_to_end(&mut bytes).ok()?;
    passwd_name(&String::from_utf8_lossy(&bytes), uid)
}

/// The name of `uid`'s entry: on Linux and the BSDs the file alone.
#[cfg(all(unix, not(target_os = "macos")))]
fn entry_of(uid: u32) -> Option<String> {
    passwd_file_entry(uid)
}

/// On macOS the users are in the system's directory, which `getpwuid_r`
/// reads; the file, which holds the system's own accounts, is the fallback.
#[cfg(target_os = "macos")]
fn entry_of(uid: u32) -> Option<String> {
    directory_entry(uid).or_else(|| passwd_file_entry(uid))
}

#[cfg(not(unix))]
fn entry_of(_uid: u32) -> Option<String> {
    None
}

/// The name of `uid`'s entry as macOS's directory gives it.
#[cfg(target_os = "macos")]
fn directory_entry(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        // SAFETY: an all-zero passwd is valid (null pointers).
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: getpwuid_r writes only within `buf`, whose length it is
        // given, and into `pwd` and `found`, which outlive the call.
        let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        // SAFETY: on success the name is NUL-terminated inside `buf`.
        let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }.to_str().ok()?.to_string();
        return (!name.is_empty()).then_some(name);
    }
}

/// The effective uid, whose entry names the user, as OpenSSH reads it.
#[cfg(unix)]
fn effective_uid() -> Option<u32> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    Some(unsafe { libc::geteuid() })
}

#[cfg(not(unix))]
fn effective_uid() -> Option<u32> {
    None
}

/// The CA file: `--ca-file`, else `SSL_CERT_FILE`, else the settings
/// file's `CaFile` (T-048).
pub(super) fn ca_file(args: &SshArgs, env: &Env) -> Option<String> {
    crate::settings::ca_file_from(args.ca_file.as_deref(), env.ssl_cert_file.clone(), &env.settings)
}

#[cfg(test)]
#[path = "resolve_env_tests.rs"]
mod tests;
