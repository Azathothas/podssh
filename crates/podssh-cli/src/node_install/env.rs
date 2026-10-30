//! The node's variables for its service (T-121): what `--install` carries
//! into a private file beside the pair, and what `--env-file` reads back
//! before anything else. A service starts with none of the user's shell:
//! with no proxy variable, a node behind a proxy cannot reach the relay. No
//! token of the environment is carried: the node's credentials are its
//! pair's, and `PODSSH_CF_ACCESS_TOKEN_FILE` names a file for Cloudflare
//! Access.

use std::path::{Path, PathBuf};

use crate::relay_settings::Refusal;

/// The variables of other programs that the node reads and that a service
/// would not have: the proxy, the trust, the places of the user's files.
/// Each of podssh's own is carried too, but for [`SECRET`] and
/// [`NOT_CARRIED`].
pub(super) const CARRIED: &[&str] = &[
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
];

/// The prefix of podssh's own variables.
const OWN: &str = "PODSSH_";

/// The variables that are secrets themselves: never carried, and refused in
/// a file of variables.
pub(super) const SECRET: &[&str] = &["PODSSH_RELAY_TOKEN", "PODSSH_CF_ACCESS_TOKEN", "PODSSH_CF_ACCESS_CLIENT_SECRET"];

/// A service that tries no connection serves nothing.
const NOT_CARRIED: &[&str] = &["PODSSH_OFFLINE"];

/// Whether a file of variables may hold `name`.
fn readable(name: &str) -> bool {
    CARRIED.contains(&name) || name.starts_with(OWN) && !SECRET.contains(&name)
}

/// The file of a node's variables in podssh's cache, beside its pair.
pub(super) fn file_name(label: &str) -> String {
    format!("node-{label}.env")
}

/// The file's text from this process's variables, and the secrets that are
/// set and left out.
pub(super) fn body() -> (String, Vec<String>) {
    body_of(std::env::vars_os().filter_map(|(n, v)| Some((n.into_string().ok()?, v.into_string().ok()?))))
}

/// [`body`] over the given variables, for tests, in the order of their
/// names. A value with a line break cannot be a line of the file, and is
/// left out.
pub(super) fn body_of(vars: impl Iterator<Item = (String, String)>) -> (String, Vec<String>) {
    let mut vars: Vec<(String, String)> = vars.filter(|(_, v)| !v.is_empty()).collect();
    vars.sort();
    let mut text = String::from("# The variables of a podssh node's service: podssh node NAME --install wrote them.\n");
    let mut left = Vec::new();
    for (name, value) in vars {
        if SECRET.contains(&name.as_str()) {
            left.push(name);
        } else if readable(&name) && !NOT_CARRIED.contains(&name.as_str()) && !value.contains(['\n', '\r', '\0']) {
            text.push_str(&format!("{name}={value}\n"));
        }
    }
    (text, left)
}

/// The variables of a file: `NAME=VALUE` lines, with blank lines and `#`
/// comments. A name that the node does not read, and a secret, are refused
/// with their line.
pub(super) fn parse(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut vars = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!("line {}: not NAME=VALUE", i + 1));
        };
        let name = name.trim();
        if SECRET.contains(&name) {
            return Err(format!("line {}: {name} is a token, and a service keeps none of the environment", i + 1));
        }
        if !readable(name) {
            return Err(format!("line {}: {name} is not a variable that podssh reads", i + 1));
        }
        vars.push((name.to_string(), value.to_string()));
    }
    Ok(vars)
}

/// Read FILE, a private file, and set each of its variables in this process.
pub(super) fn apply(path: &Path) -> Result<(), Refusal> {
    let text = podssh_relay::cache::read_private(path).map_err(|e| Refusal::config(format!("--env-file: {e}")))?;
    let vars = parse(&text).map_err(|e| Refusal::config(format!("--env-file {}: {e}", path.display())))?;
    for (name, value) in vars {
        // The first thing that the node does, while this process has one
        // thread: no reader of a variable can race this write.
        std::env::set_var(name, value);
    }
    Ok(())
}

/// Remove the file of `label`'s variables from each directory of the cache
/// where it is ours: the first one removed, if any.
pub(super) fn remove(label: &str) -> Option<PathBuf> {
    let name = file_name(label);
    let dirs = podssh_relay::cache::candidate_dirs();
    let found = dirs.iter().map(|dir| dir.join(&name)).find(|path| path.is_file());
    podssh_relay::cache::remove_named_from(&dirs, &name);
    found.filter(|path| !path.exists())
}
