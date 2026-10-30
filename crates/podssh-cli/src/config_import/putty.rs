//! PuTTY's sessions (T-292): a `.reg` file of the registry's key
//! `Software\SimonTatham\PuTTY\Sessions` (`Windows Registry Editor Version
//! 5.00` or `REGEDIT4`, in any case), or the session files of PuTTY on Unix
//! (`key=value`, one file for each session, its name `%XX` escaped). The
//! session `Default Settings` is the template, never a host. PuTTY keeps no
//! login password; `ProxyPassword` is counted. A key of PuTTY's format
//! (`.ppk`), which ssh cannot read, and each command, are comments.

use std::collections::BTreeMap;

use super::sessions::{decode, unescape_percent, Read, Session};
use super::Input;

/// A session's values by their names.
type Values = BTreeMap<String, String>;

/// The registry key under which PuTTY keeps its sessions.
const SESSIONS_KEY: &str = "\\software\\simontatham\\putty\\sessions\\";

/// The proxy methods, in the order of `ProxyMethod`.
const PROXIES: [&str; 9] = [
    "none",
    "SOCKS 4",
    "SOCKS 5",
    "HTTP",
    "Telnet",
    "a local command",
    "SSH, with port forwarding",
    "SSH, with exec",
    "SSH, with a subsystem",
];

/// The sessions of `inputs`: one `.reg` file, or session files of Unix.
pub fn read(inputs: &[Input]) -> Result<Read, String> {
    let mut read = Read::default();
    for input in inputs {
        let text = decode(&input.bytes);
        let first = text.lines().next().unwrap_or("").trim();
        let sessions = if first.eq_ignore_ascii_case("Windows Registry Editor Version 5.00")
            || first.eq_ignore_ascii_case("REGEDIT4")
        {
            registry(&text).map_err(|why| format!("{}:{why}", input.name))?
        } else {
            let label = input.name.rsplit(['/', '\\']).next().unwrap_or(&input.name);
            vec![(unescape_percent(label), unix(&text))]
        };
        for (label, values) in sessions {
            read.sessions.push(session(label, &values, &mut read.secrets));
        }
    }
    Ok(read)
}

/// The sessions of a `.reg` file: each key under [`SESSIONS_KEY`], with its
/// values. A key of another place (`SshHostKeys`, `Jumplist`) is skipped.
fn registry(text: &str) -> Result<Vec<(String, Values)>, String> {
    let mut sessions: Vec<(String, Values)> = Vec::new();
    let mut current: Option<usize> = None;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if let Some(key) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let lower = key.to_ascii_lowercase();
            current = lower.find(SESSIONS_KEY).map(|at| {
                let name = &key[at + SESSIONS_KEY.len()..];
                sessions.push((unescape_percent(name), BTreeMap::new()));
                sessions.len() - 1
            });
            continue;
        }
        let Some(at) = current else { continue };
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!("{}: {line:?}: not \"NAME\"=VALUE", i + 1));
        };
        let name = name.trim().trim_matches('"').to_string();
        sessions[at].1.insert(name, reg_value(value.trim()));
    }
    Ok(sessions)
}

/// A value of a `.reg` line: a string with `\\` and `\"` escaped, or
/// `dword:` in hex, as its number in decimal; another kind as it is.
fn reg_value(value: &str) -> String {
    if let Some(quoted) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        let mut out = String::new();
        let mut chars = quoted.chars();
        while let Some(c) = chars.next() {
            match (c, chars.clone().next()) {
                ('\\', Some(next @ ('\\' | '"'))) => {
                    out.push(next);
                    chars.next();
                }
                _ => out.push(c),
            }
        }
        return out;
    }
    match value.strip_prefix("dword:").and_then(|h| u32::from_str_radix(h, 16).ok()) {
        Some(n) => n.to_string(),
        None => value.to_string(),
    }
}

/// The values of a session file of Unix: `key=value` lines, unquoted.
fn unix(text: &str) -> BTreeMap<String, String> {
    text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim().to_string(), v.to_string())).collect()
}

/// One session from its values.
fn session(label: String, values: &BTreeMap<String, String>, secrets: &mut usize) -> Session {
    let get = |name: &str| values.get(name).map(String::as_str).filter(|v| !v.is_empty());
    let mut s = Session { label: label.clone(), ..Session::default() };
    if get("ProxyPassword").is_some() {
        *secrets += 1;
    }
    if label == "Default Settings" {
        s.skipped = Some("PuTTY's template for new sessions, not a host".into());
        return s;
    }
    let protocol = get("Protocol").unwrap_or("ssh");
    if !protocol.eq_ignore_ascii_case("ssh") {
        s.not_ssh = Some(protocol.to_string());
        return s;
    }
    // PuTTY takes `user@host` in the host's box, as ssh does.
    match get("HostName").map(|h| h.rsplit_once('@').map_or((None, h), |(u, h)| (Some(u), h))) {
        Some((user, host)) => {
            s.host = Some(host.to_string());
            s.user = user.or(get("UserName")).map(str::to_string);
        }
        None => s.user = get("UserName").map(str::to_string),
    }
    s.port = get("PortNumber").map(str::to_string);
    if let Some(key) = get("PublicKeyFile") {
        if key.to_ascii_lowercase().ends_with(".ppk") {
            s.notes.push(format!(
                "IdentityFile {key} is a key of PuTTY's format, which ssh cannot read; puttygen KEY -O \
                 private-openssh -o FILE converts it"
            ));
        } else {
            s.identity = Some(key.to_string());
        }
    }
    proxy(&mut s, &get);
    if let Some(vars) = get("Environment") {
        let n = vars.split(',').filter(|v| !v.is_empty()).count();
        s.notes.push(format!("Environment ({n} variables) is not imported: a variable can hold a secret"));
    }
    s
}

/// The proxy of a session: an SSH proxy becomes `ProxyJump`; another kind,
/// and a command, a comment.
fn proxy<'a>(s: &mut Session, get: &impl Fn(&str) -> Option<&'a str>) {
    let method: usize = get("ProxyMethod").and_then(|m| m.parse().ok()).unwrap_or(0);
    if method == 0 {
        return;
    }
    let host = get("ProxyHost").unwrap_or("");
    let port = get("ProxyPort").filter(|p| *p != "22").map(|p| format!(":{p}")).unwrap_or_default();
    let user = get("ProxyUsername").map(|u| format!("{u}@")).unwrap_or_default();
    match method {
        6 if !host.is_empty() => s.jump = Some(format!("{user}{host}{port}")),
        5 => s.notes.push("the proxy is a local command, which is not imported: a command can hold a secret".into()),
        _ => {
            let kind = PROXIES.get(method).copied().unwrap_or("of an unknown kind");
            s.notes.push(format!("the proxy {host}{port} ({kind}) is not imported: ssh_config has no such proxy"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reg_value_is_unescaped_and_a_dword_is_a_number() {
        assert_eq!(reg_value("\"C:\\\\Users\\\\x.ppk\""), "C:\\Users\\x.ppk");
        assert_eq!(reg_value("\"say \\\"hi\\\"\""), "say \"hi\"");
        assert_eq!(reg_value("dword:00000016"), "22");
        assert_eq!(reg_value("hex:01,02"), "hex:01,02");
    }

    #[test]
    fn user_at_host_splits_and_an_ssh_proxy_is_a_jump() {
        let values: BTreeMap<String, String> = [
            ("HostName", "root@nas.example"),
            ("UserName", "other"),
            ("PortNumber", "2222"),
            ("ProxyMethod", "6"),
            ("ProxyHost", "bastion.example"),
            ("ProxyPort", "22"),
            ("ProxyUsername", "jump"),
            ("ProxyPassword", "x"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let mut secrets = 0;
        let s = session("nas".into(), &values, &mut secrets);
        assert_eq!(
            (s.host.as_deref(), s.user.as_deref(), s.port.as_deref()),
            (Some("nas.example"), Some("root"), Some("2222"))
        );
        assert_eq!(s.jump.as_deref(), Some("jump@bastion.example"));
        assert_eq!(secrets, 1);
        let telnet: BTreeMap<String, String> = [("Protocol".to_string(), "telnet".to_string())].into();
        assert_eq!(session("t".into(), &telnet, &mut secrets).not_ssh.as_deref(), Some("telnet"));
    }
}
