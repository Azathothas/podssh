//! podssh's own settings file (T-048): the defaults of its relay settings,
//! below the flags and the variables, above the built-in defaults. The
//! file has `Keyword value` lines, `#` comments and `Keyword=value` too, as
//! an `ssh_config` has: `RelayHost`, `RelayAddr` (which adds up), `RelayFailover`
//! and `CaFile`, and `SessionLog` (T-056). It is found once for the process: the file that
//! `PODSSH_SETTINGS` names (`none` names none), else the first that exists
//! of `$XDG_CONFIG_HOME/podssh/settings` (`~/.config/podssh/settings`, and
//! `%APPDATA%\podssh\settings` on Windows) and `podssh.settings` next to the
//! binary; never the working directory or `/tmp`, as a file that names relay
//! hosts decides where tokens go. A symbolic link, a file of another user
//! than this one or root, and one that others can change are refused. podssh
//! never writes the file, and no keyword holds a token. After a line
//! `[groups]`, each line is `NAME HOSTS`: a group of hosts, `@NAME` on the
//! command line (T-184, [`crate::hosts`]).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::relay_settings::Refusal;

/// The variable that names the settings file.
pub const SETTINGS_ENV: &str = "PODSSH_SETTINGS";
/// The name of the file next to the binary.
pub const BESIDE_BINARY: &str = "podssh.settings";
/// The keywords, as the manual lists them.
pub const KEYWORDS: &[(&str, &str)] = &[
    ("RelayHost", "HOST[:PORT][,...]: the relay hosts, as --relay-host and PODSSH_RELAY"),
    ("RelayAddr", "HOST=IP[,...]: addresses for relay hosts, as --relay-addr; each line adds to the others"),
    ("RelayFailover", "MODE: how the relay hosts are tried, as --relay-failover"),
    ("CaFile", "FILE: trust only the CA certificates in FILE, as --ca-file and SSL_CERT_FILE; ~ is the home"),
    ("SessionLog", "yes, no or FILE: a line for each session of this host, as PODSSH_SESSION_LOG; ~ is the home"),
];
/// The largest file read.
const MAX_FILE: u64 = 1 << 20;

/// A value of the file, with its place for a refusal: `FILE:LINE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub text: String,
    pub at: String,
}

/// The settings of the file, or none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Defaults {
    /// The file read, when one was.
    pub path: Option<PathBuf>,
    /// Why the file could not be read, when it could not.
    pub problem: Option<String>,
    pub relay_host: Option<Value>,
    pub relay_addr: Vec<Value>,
    pub relay_failover: Option<Value>,
    pub ca_file: Option<Value>,
    /// `SessionLog` (T-056).
    pub session_log: Option<Value>,
    /// The `[groups]` table (T-184): each group's name and its hosts.
    pub groups: crate::hosts::Groups,
}

impl Defaults {
    /// The refusal of a file that could not be read (78), or nothing.
    pub fn check(&self) -> Result<(), Refusal> {
        match &self.problem {
            Some(why) => Err(Refusal::config(why.clone())),
            None => Ok(()),
        }
    }
}

/// Where the settings could be, from the process: what [`locate`] reads.
#[derive(Debug, Clone, Default)]
pub struct Places {
    /// `PODSSH_SETTINGS`.
    pub given: Option<String>,
    /// `$XDG_CONFIG_HOME`, or `%APPDATA%` on Windows.
    pub config_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
    /// The directory of the binary.
    pub binary_dir: Option<PathBuf>,
}

impl Places {
    fn of_process() -> Places {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let config_home = if cfg!(windows) { var("APPDATA") } else { var("XDG_CONFIG_HOME") };
        let home = var("HOME").or_else(|| if cfg!(windows) { var("USERPROFILE") } else { None });
        Places {
            given: std::env::var(SETTINGS_ENV).ok(),
            config_home: config_home.map(PathBuf::from).filter(|p| p.is_absolute()),
            home: home.map(PathBuf::from),
            binary_dir: std::env::current_exe().ok().and_then(|exe| exe.parent().map(Path::to_path_buf)),
        }
    }
}

/// The file to read: the one that `PODSSH_SETTINGS` names, which must
/// exist; else the first of the usual places that exists; else none.
pub fn locate(places: &Places) -> Result<Option<PathBuf>, String> {
    if let Some(given) = places.given.as_deref().filter(|g| !g.trim().is_empty()) {
        if given == "none" {
            return Ok(None);
        }
        let path = PathBuf::from(given);
        if !path.is_absolute() {
            return Err(format!("{SETTINGS_ENV}={given}: give an absolute path; the working directory is never read"));
        }
        return match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(Some(path)),
            Err(e) => Err(format!("{SETTINGS_ENV}={given}: {e}")),
        };
    }
    let config = match (&places.config_home, &places.home) {
        (Some(dir), _) => Some(dir.join("podssh").join("settings")),
        (None, Some(home)) if !cfg!(windows) => Some(home.join(".config").join("podssh").join("settings")),
        _ => None,
    };
    let beside = places.binary_dir.as_ref().map(|dir| dir.join(BESIDE_BINARY));
    Ok(config.into_iter().chain(beside).find(|p| std::fs::symlink_metadata(p).is_ok()))
}

/// The settings of the process, found and read once.
pub fn here() -> &'static Defaults {
    static HERE: OnceLock<Defaults> = OnceLock::new();
    HERE.get_or_init(|| load(&Places::of_process()))
}

/// The settings from `places`: a file that cannot be read is a problem,
/// which each command that reaches the relay refuses (78).
pub fn load(places: &Places) -> Defaults {
    let path = match locate(places) {
        Ok(Some(path)) => path,
        Ok(None) => return Defaults::default(),
        Err(why) => return Defaults { problem: Some(why), ..Defaults::default() },
    };
    let read = read_checked(&path).and_then(|text| parse(&text, &path.display().to_string(), places.home.as_deref()));
    match read {
        Ok(defaults) => Defaults { path: Some(path), ..defaults },
        Err(why) => Defaults { path: Some(path), problem: Some(why), ..Defaults::default() },
    }
}

/// The text of the file, refused when it is a symbolic link, not a regular
/// file, another user's than this one or root, or open to others' writes.
fn read_checked(path: &Path) -> Result<String, String> {
    let shown = path.display();
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{shown} is a symbolic link, which podssh does not follow for its settings; name the file itself with \
             {SETTINGS_ENV}"
        ));
    }
    let file = std::fs::File::open(path).map_err(|e| format!("{shown}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    crate::ssh::config::owner_alone_writes(path, &file, &meta)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(&file, MAX_FILE + 1), &mut bytes)
        .map_err(|e| format!("{shown}: {e}"))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(format!("{shown} is larger than 1 MiB, which no settings file is"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{shown} is not UTF-8 text"))
}

/// The settings of `text`, read from `file`: the first value of a keyword
/// wins, but `RelayAddr`, whose lines add up. Each value is checked here, as
/// its flag is, so that each command that reaches the relay refuses a bad
/// file alike.
pub fn parse(text: &str, file: &str, home: Option<&Path>) -> Result<Defaults, String> {
    let mut d = Defaults::default();
    // Past `[groups]`, each line is a group, to the end of the file.
    let mut in_groups = false;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = format!("{file}:{}", i + 1);
        if line.starts_with('[') {
            match crate::ssh::config::uncomment(line).trim() {
                "[groups]" => in_groups = true,
                other => return Err(format!("{at}: {other} is not a table of podssh's settings; the one is [groups]")),
            }
            continue;
        }
        let (keyword, value) = crate::ssh::config::split(line);
        let value = crate::ssh::config::uncomment(value).trim();
        if value.is_empty() {
            return Err(format!("{at}: {keyword} needs a value"));
        }
        if in_groups {
            crate::hosts::group_line(&mut d.groups, keyword, value, &at)?;
            continue;
        }
        let value = Value { text: value.to_string(), at: at.clone() };
        let text = &value.text;
        match keyword.to_ascii_lowercase().as_str() {
            "relayhost" => {
                podssh_relay::relay::select_relays(Some(text), None, &[])
                    .map_err(|why| format!("{at}: RelayHost {text}: {why}"))?;
                d.relay_host.get_or_insert(value);
            }
            "relayaddr" => {
                podssh_ws::resolve::parse_pins(text).map_err(|e| format!("{at}: RelayAddr {text}: {e}"))?;
                d.relay_addr.push(value);
            }
            "relayfailover" => {
                if podssh_relay::failover::Mode::parse(text).is_none() {
                    let modes = podssh_relay::failover::Mode::NAMES;
                    return Err(format!("{at}: RelayFailover {text:?} is not a mode: give {modes}"));
                }
                d.relay_failover.get_or_insert(value);
            }
            "cafile" => {
                let text = crate::ssh::tokens::tilde(&value.text, home).display().to_string();
                d.ca_file.get_or_insert(Value { text, ..value });
            }
            "sessionlog" => {
                crate::session_log::parse(text, home).map_err(|why| format!("{at}: SessionLog {why}"))?;
                d.session_log.get_or_insert(value);
            }
            _ => {
                let names: Vec<&str> = KEYWORDS.iter().map(|(k, _)| *k).collect();
                return Err(format!(
                    "{at}: {keyword} is not a setting of podssh; the settings are {}",
                    names.join(", ")
                ));
            }
        }
    }
    // A group that names one that is not there, or itself, is the file's fault.
    crate::hosts::check_groups(&d.groups)?;
    Ok(d)
}

/// The CA file: `--ca-file`, else `SSL_CERT_FILE`, else the settings
/// file's `CaFile`.
pub fn ca_file(flag: Option<&str>) -> Option<String> {
    let env = std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty());
    ca_file_from(flag, env, here())
}

/// [`ca_file`] with the variable and the settings given.
pub fn ca_file_from(flag: Option<&str>, env: Option<String>, file: &Defaults) -> Option<String> {
    flag.map(str::to_string).or(env).or_else(|| file.ca_file.as_ref().map(|v| v.text.clone()))
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
