//! MobaXterm's sessions (T-292): an `.mxtsessions` export, or the bookmarks
//! of `MobaXterm.ini`. `[Bookmarks]` and `[Bookmarks_N]` each give a folder
//! (`SubRep=A\B`) and its sessions, `NAME= #ICON#TYPE%F1%F2...#FONT...`: the
//! fields after the type are split by `%`, and their meaning depends on the
//! type. For SSH (type 0): 1 the host, 2 the port, 3 the user, 7 a command
//! after the login, 8 to 10 the gateways' hosts, ports and users (several
//! joined by `__PIPE__`), 14 a private key, 19 the proxy's type (0 none), 20
//! and 21 its host and port, 26 a proxy command. MobaXterm keeps passwords
//! under its master password, in `[Passwords]` and `[Sesspass]`: each entry is
//! counted.

use super::sessions::{decode, Read, Session};
use super::Input;

/// MobaXterm's escapes inside a field.
const ESCAPES: [(&str, &str); 5] =
    [("__PIPE__", "|"), ("__PTVIRG__", ";"), ("__DBLQUO__", "\""), ("__DIEZE__", "#"), ("__PERCENT__", "%")];

/// The types of session by their number, as MobaXterm 26.3 writes them;
/// another number is named as it is.
const TYPES: [(&str, &str); 9] = [
    ("0", "SSH"),
    ("1", "Telnet"),
    ("2", "Rlogin"),
    ("3", "XDMCP"),
    ("4", "RDP"),
    ("5", "VNC"),
    ("6", "FTP"),
    ("7", "SFTP"),
    ("8", "serial"),
];

fn unescape(field: &str) -> String {
    ESCAPES.iter().fold(field.to_string(), |text, (from, to)| text.replace(from, to))
}

/// The sessions of each input.
pub fn read(inputs: &[Input]) -> Result<Read, String> {
    let mut read = Read::default();
    for input in inputs {
        let text = decode(&input.bytes);
        let mut section = String::new();
        let mut folder: Option<String> = None;
        for raw in text.lines() {
            let line = raw.trim_end_matches('\r');
            if let Some(name) = line.trim().strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.to_ascii_lowercase();
                folder = None;
                continue;
            }
            let Some((name, value)) = line.split_once('=') else { continue };
            match section.as_str() {
                "passwords" | "sesspass" => read.secrets += 1,
                s if s == "bookmarks" || s.starts_with("bookmarks_") => match name {
                    "SubRep" => folder = Some(value.replace('\\', "/")).filter(|f| !f.is_empty()),
                    "ImgNum" => {}
                    _ => {
                        if let Some(mut s) = session(name, value) {
                            s.folder = folder.clone();
                            read.sessions.push(s);
                        }
                    }
                },
                _ => {}
            }
        }
    }
    Ok(read)
}

/// One session of a bookmark's line, or `None` for a line that is none.
fn session(label: &str, value: &str) -> Option<Session> {
    let parts: Vec<&str> = value.trim_start().split('#').collect();
    // "", the icon, then the type and its fields.
    let fields: Vec<String> = parts.get(2)?.split('%').map(unescape).collect();
    let field = |n: usize| fields.get(n).map(String::as_str).filter(|v| !v.is_empty());
    let mut s = Session { label: label.to_string(), ..Session::default() };
    let kind = fields.first()?.as_str();
    if kind != "0" {
        let name =
            TYPES.iter().find(|(n, _)| *n == kind).map_or(format!("a session of type {kind}"), |(_, t)| t.to_string());
        s.not_ssh = Some(name);
        return Some(s);
    }
    s.host = field(1).map(str::to_string);
    s.port = field(2).map(str::to_string);
    s.user = field(3).filter(|u| *u != "<default>").map(str::to_string);
    if field(7).is_some() {
        s.notes.push("the command after the login is not imported: a command can hold a secret".into());
    }
    if let Some(hosts) = field(8) {
        let ports: Vec<&str> = field(9).map(|p| p.split('|').collect()).unwrap_or_default();
        let users: Vec<&str> = field(10).map(|u| u.split('|').collect()).unwrap_or_default();
        let jumps: Vec<String> = hosts
            .split('|')
            .enumerate()
            .map(|(i, host)| {
                let user = users.get(i).filter(|u| !u.is_empty() && **u != "<default>").map(|u| format!("{u}@"));
                let port = ports.get(i).filter(|p| !p.is_empty() && **p != "22").map(|p| format!(":{p}"));
                format!("{}{host}{}", user.unwrap_or_default(), port.unwrap_or_default())
            })
            .collect();
        s.jump = Some(jumps.join(","));
    }
    if let Some(key) = field(14) {
        s.notes.push(format!(
            "IdentityFile {key}: a path as MobaXterm writes it (_CurrentDrive_, _ProfileDir_ and the like are its \
             own); not imported"
        ));
    }
    match field(19) {
        None | Some("0") => {}
        Some(kind) => {
            let at = [field(20), field(21)].iter().flatten().copied().collect::<Vec<_>>().join(":");
            s.notes.push(format!("the proxy {at} (MobaXterm's type {kind}) is not imported"));
        }
    }
    if field(26).is_some() {
        s.notes.push("the proxy command is not imported: a command can hold a secret".into());
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_of_ssh_gives_its_host_its_gateways_and_its_notes() {
        let line = " #109#0%web.example%2222%alice%%-1%-1%cd /srv%gw1.example__PIPE__gw2.example%22__PIPE__2200%\
                    bob__PIPE__<default>%-1%0%%_ProfileDir_\\id.key%%-1%0%0%0%%1080%%0%0#MobaFont%10#0";
        let s = session("Web (prod)", line).unwrap();
        assert_eq!(
            (s.host.as_deref(), s.port.as_deref(), s.user.as_deref()),
            (Some("web.example"), Some("2222"), Some("alice"))
        );
        assert_eq!(s.jump.as_deref(), Some("bob@gw1.example,gw2.example:2200"));
        assert!(
            s.notes.iter().any(|n| n.contains("after the login")) && s.notes.iter().any(|n| n.contains("_ProfileDir_"))
        );
        let rdp = session("Desktop", " #91#4%host.example%3389%%-1%-1#MobaFont#0").unwrap();
        assert_eq!(rdp.not_ssh.as_deref(), Some("RDP"));
        assert!(session("SubRep", "ice").is_none());
        assert_eq!(unescape("a__PTVIRG__b__DIEZE__c"), "a;b#c");
    }
}
