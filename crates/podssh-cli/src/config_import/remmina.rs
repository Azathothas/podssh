//! Remmina's profiles (T-292): one `.remmina` file for each, an INI file
//! with one `[remmina]` section, or a directory of them. `protocol=SSH` makes
//! a block; another protocol a comment. `server` is `host[:port]` or
//! `[v6]:port`, `name` the label, `group` the folder. A secret
//! (`password`, `ssh_passphrase` and the tunnel's) is `.` when the keyring
//! keeps it, else a blob that Remmina encrypts: each is counted. A value of a
//! template (`%Host%`) is no host.

use super::sessions::{decode, placeholder, Read, Session};
use super::Input;

/// The keys that hold a secret.
const SECRETS: [&str; 4] = ["password", "ssh_passphrase", "ssh_tunnel_password", "ssh_tunnel_passphrase"];

/// The profiles of each input.
pub fn read(inputs: &[Input]) -> Result<Read, String> {
    let mut read = Read::default();
    for input in inputs {
        let text = decode(&input.bytes);
        let mut in_section = false;
        let mut values = std::collections::BTreeMap::new();
        for line in text.lines().map(|l| l.trim_end_matches('\r')) {
            if let Some(name) = line.trim().strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                in_section = name.eq_ignore_ascii_case("remmina");
                continue;
            }
            if let (true, Some((key, value))) = (in_section, line.split_once('=')) {
                values.insert(key.trim().to_string(), value.to_string());
            }
        }
        if values.is_empty() {
            return Err(format!("{}: no [remmina] section, so no profile of Remmina", input.name));
        }
        read.secrets += SECRETS.iter().filter(|k| values.get(**k).is_some_and(|v| !v.is_empty())).count();
        read.sessions.push(profile(&input.name, &values));
    }
    Ok(read)
}

/// One profile from its values.
fn profile(file: &str, values: &std::collections::BTreeMap<String, String>) -> Session {
    let get = |key: &str| values.get(key).map(String::as_str).filter(|v| !v.is_empty());
    let label = get("name").unwrap_or(file).to_string();
    let mut s = Session { label, folder: get("group").map(str::to_string), ..Session::default() };
    let protocol = get("protocol").unwrap_or("RDP");
    if !protocol.eq_ignore_ascii_case("SSH") {
        s.not_ssh = Some(protocol.to_string());
        return s;
    }
    if let Some(server) = get("server") {
        let (host, port) = split_server(server);
        if placeholder(host) {
            s.skipped = Some(format!("the host {host} is a placeholder of a template"));
        }
        s.host = Some(host.to_string());
        s.port = port.map(str::to_string);
    }
    s.user = get("username").filter(|u| !placeholder(u)).map(str::to_string);
    s.identity = get("ssh_privatekey").map(str::to_string);
    if get("ssh_proxycommand").is_some() {
        s.notes.push("ssh_proxycommand is not imported: a command can hold a secret".into());
    }
    let keyring = SECRETS.iter().filter(|k| get(k) == Some(".")).count();
    if keyring > 0 {
        s.notes.push(format!("{keyring} of its secrets are in the keyring, as Remmina keeps them"));
    }
    s
}

/// `host`, `host:port` or `[v6]:port`.
fn split_server(server: &str) -> (&str, Option<&str>) {
    if let Some(rest) = server.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            return (host, after.strip_prefix(':'));
        }
    }
    match server.split_once(':') {
        Some((host, port)) if !port.contains(':') => (host, Some(port)),
        _ => (server, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_s_forms_split_into_a_host_and_a_port() {
        assert_eq!(split_server("web.example"), ("web.example", None));
        assert_eq!(split_server("web.example:2222"), ("web.example", Some("2222")));
        assert_eq!(split_server("[2001:db8::1]:22"), ("2001:db8::1", Some("22")));
        assert_eq!(split_server("2001:db8::1"), ("2001:db8::1", None));
    }
}
