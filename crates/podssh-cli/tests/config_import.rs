//! `podssh config import ansible` (T-047), against what Ansible itself made
//! of the same inventory: ansible-core 2.21.0 in the build image,
//! 2026-10-12 (`tests/fixtures/ansible/`): `ansible-inventory --list`, and
//! the command line of ssh that `ansible all -m ping -vvv` ran for each host.
//! Nothing connects.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ansible");

fn inventory() -> String {
    format!("{DIR}/inventory.ini")
}

/// `podssh ARGS` with `stdin`: its exit code, stdout and stderr.
fn podssh(args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(args)
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_OFFLINE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into(), String::from_utf8_lossy(&out.stderr).into())
}

/// Each block of `text`: its name, and its keywords lowercased with their
/// values.
fn blocks(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut all: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (keyword, value) = line.split_once(' ').unwrap_or((line, ""));
        let value = value.trim().trim_matches('"').to_string();
        if keyword == "Host" {
            all.insert(value.clone(), BTreeMap::new());
            current = Some(value);
        } else {
            let name = current.as_ref().unwrap_or_else(|| panic!("a line before any Host: {line}"));
            all.get_mut(name).unwrap().insert(keyword.to_ascii_lowercase(), value);
        }
    }
    all
}

/// For each host that Ansible's ssh reached: its address, and the options
/// that the inventory gave it (`Port`, `User`, `IdentityFile`, `ProxyJump`).
fn ansible_ssh() -> Vec<(String, BTreeMap<String, String>)> {
    let text = std::fs::read_to_string(format!("{DIR}/ssh-exec.txt")).unwrap();
    text.lines()
        .filter(|l| l.starts_with('<') && l.contains("SSH: EXEC"))
        .map(|line| {
            let address = line[1..line.find('>').unwrap()].to_string();
            let mut options = BTreeMap::new();
            for piece in line.split(" -o ").skip(1) {
                let word = piece.split(' ').next().unwrap().trim_matches('\'');
                let (keyword, value) = word.split_once('=').unwrap();
                if ["Port", "User", "IdentityFile", "ProxyJump"].contains(&keyword) {
                    options.insert(keyword.to_ascii_lowercase(), value.trim_matches('"').to_string());
                }
            }
            (address, options)
        })
        .collect()
}

#[test]
fn each_host_gets_what_ansibles_ssh_used() {
    let (code, out, err) = podssh(&["config", "import", "ansible", &inventory()], "");
    assert_eq!(code, Some(0), "{err}");
    let ours = blocks(&out);
    let theirs = ansible_ssh();
    assert_eq!(theirs.len(), 15, "the capture holds 15 hosts");
    for (address, options) in &theirs {
        let (name, block) = ours
            .iter()
            .find(|(name, block)| block.get("hostname").unwrap_or(name) == address)
            .unwrap_or_else(|| panic!("no block reaches {address}: {out}"));
        for keyword in ["port", "user", "identityfile", "proxyjump"] {
            // Ansible expanded `~` with the home of the capture, /root.
            let ours = block.get(keyword).map(|v| v.replacen("~/", "/root/", 1));
            assert_eq!(ours.as_ref(), options.get(keyword), "{name}: {keyword}");
        }
    }
    assert_eq!(ours.len(), theirs.len(), "a block for each host that ssh reached: {out}");
}

/// No password is printed, and the summary counts each variable whose name
/// holds `pass`, as Ansible's listing holds them.
#[test]
fn no_password_is_printed_and_each_is_counted() {
    let (code, out, err) = podssh(&["config", "import", "ansible", &inventory()], "");
    assert_eq!(code, Some(0), "{err}");
    for text in [&out, &err] {
        assert!(!text.contains("not-a-real-secret"), "a secret was printed: {text}");
    }
    let listing: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/inventory.list.json")).unwrap()).unwrap();
    let hostvars = listing["_meta"]["hostvars"].as_object().unwrap();
    let count: usize =
        hostvars.values().map(|vars| vars.as_object().unwrap().keys().filter(|k| k.contains("pass")).count()).sum();
    assert_eq!(count, 21, "16 hosts with the password of all, one of its own, and 4 of dbservers");
    assert!(err.contains(&format!("{count} passwords were not imported")), "{err}");
}

/// The groups of each host, as Ansible's listing gives them, are in its
/// comment; a host that Ansible reaches with no SSH gets no block.
#[test]
fn the_groups_and_a_host_with_no_ssh_are_in_comments() {
    let (_, out, err) = podssh(&["config", "import", "ansible", &inventory()], "");
    for (host, group) in
        [("web1.example.org", "webservers"), ("db-legacy.example.org", "dbservers"), ("node3.example.org", "edge")]
    {
        assert!(out.contains(&format!("# {host} (in {group})\nHost {host}\n")), "{host}: {out}");
    }
    assert!(out.contains("# mail.example.org\nHost mail.example.org\n"), "{out}");
    assert!(out.contains("# win1.example.org (in windows): ansible_connection=winrm, no SSH; no Host block"), "{out}");
    assert!(!blocks(&out).contains_key("win1.example.org"));
    assert!(err.contains("15 hosts from") && err.contains("1 host reached with no SSH"), "{err}");
}

/// podssh's own reader takes what it printed: the settings of a block, and
/// the ProxyJump of ansible_ssh_common_args.
#[test]
fn podssh_reads_what_it_printed() {
    let (_, out, _) = podssh(&["config", "import", "ansible", &inventory()], "");
    let dir = std::env::temp_dir().join(format!("podssh-config-import-{}", std::process::id()));
    podssh_relay::cache::private_dir(&dir).unwrap();
    let file = dir.join("ssh_config");
    std::fs::write(&file, &out).unwrap();
    let file = file.display().to_string();
    for (host, want) in [
        ("web1.example.org", vec!["user deploy", "port 2200"]),
        ("db-legacy.example.org", vec!["user legacy", "hostname 192.0.2.60", "port 2022"]),
        ("node1.example.org", vec!["user admin", "proxyjump bastion.example.org"]),
    ] {
        let (code, lines, err) = podssh(&["ssh", "-G", "-F", &file, host], "");
        assert_eq!(code, Some(0), "{host}: {err}");
        for line in want {
            assert!(lines.lines().any(|l| l == line), "{host}: no {line:?} in {lines}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdin_a_bad_line_a_bad_name_and_the_other_formats() {
    let (code, out, _) = podssh(&["config", "import", "ansible", "-"], "[web]\nw1 ansible_port=2200\n");
    assert_eq!(code, Some(0));
    assert!(out.contains("Host w1\n  Port 2200\n"), "{out}");
    let (code, _, err) = podssh(&["config", "import", "ansible", "-"], "[web]\nw1\n[web:vars]\nno pair here\n");
    assert_eq!(code, Some(65), "{err}");
    assert!(err.contains("-:4: no pair here: expected key=value"), "{err}");
    let (code, out, err) = podssh(&["config", "import", "ansible", "-"], "web* ansible_port=1\nok\n");
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("web*: not a name that a Host line can hold; not imported"), "{err}");
    assert!(!out.contains("web*") && out.contains("Host ok\n"), "{out}");
    let missing = format!("{DIR}/no-such-inventory.ini");
    assert_eq!(podssh(&["config", "import", "ansible", &missing], "").0, Some(66));
    for (words, says) in [
        (vec!["config", "import", "mremoteng", "x.xml"], "import mremoteng: not yet"),
        (vec!["config", "import", "finalshell", "x.json"], "import finalshell: not yet"),
        (vec!["config", "import", "termius", "x"], "import termius: not yet"),
        (vec!["config", "import", "ansible-yaml", "x.yml"], "import ansible-yaml: not yet"),
        (vec!["config", "import", "toml", "x"], "import toml: not a format; give ansible, putty, mobaxterm or remmina"),
        (vec!["config", "import", "ansible"], "give the format and the file"),
        (vec!["config", "export"], "export: not a subcommand of config"),
        (vec!["config"], "give a subcommand"),
    ] {
        let (code, _, err) = podssh(&words, "");
        assert_eq!(code, Some(64), "{words:?}: {err}");
        assert!(err.contains(says), "{words:?}: {err}");
    }
}

/// The exports of other programs (T-292), each as its program wrote it and
/// published under a license that this repository can hold
/// (`tests/fixtures/sessions/THIRD-PARTY.md`).
const SESSIONS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sessions");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{SESSIONS}/{name}")).unwrap()
}

/// A scratch directory for the copies with made-up values.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-config-import-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Each block by its name, with its keywords.
type Hosts = BTreeMap<String, BTreeMap<String, String>>;

/// `podssh config import FORMAT FILE`: the code, the blocks and stderr.
fn import(format: &str, file: &str) -> (Option<i32>, Hosts, String, String) {
    let (code, out, err) = podssh(&["config", "import", format, file], "");
    (code, blocks(&out), out, err)
}

/// No made-up secret anywhere in what podssh printed.
fn no_secret(texts: &[&str]) {
    for text in texts {
        assert!(!text.contains("made-up"), "a secret was printed: {text}");
    }
}

#[test]
fn putty_each_real_export_and_the_template_that_is_no_host() {
    let (code, hosts, out, err) = import("putty", &format!("{SESSIONS}/putty-session.reg"));
    assert_eq!(code, Some(0), "{err}");
    let want: BTreeMap<String, String> =
        [("hostname", "127.0.0.1"), ("user", "blue")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    assert_eq!(hosts.get("John-Doe"), Some(&want), "{out}");
    assert!(out.contains("# John Doe\n") && out.contains("priv.ppk is a key of PuTTY's format"), "{out}");
    assert!(out.contains("Environment (2 variables) is not imported"), "{out}");
    assert!(err.contains("1 host from"), "{err}");
    for file in ["putty-default-jumplist.reg", "putty-utf8-bom.reg", "putty-unix"] {
        let (code, hosts, out, err) = import("putty", &format!("{SESSIONS}/{file}"));
        assert_eq!(code, Some(0), "{file}: {err}");
        assert!(hosts.is_empty() && out.contains("# Default Settings: PuTTY's template"), "{file}: {out}");
    }
    // As regedit /e writes it: UTF-16LE with its mark. No such real file was
    // found, so the real one is transcoded here.
    let text = String::from_utf8(fixture("putty-session.reg")).unwrap();
    let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain(text.encode_utf16().flat_map(u16::to_le_bytes)).collect();
    let file = scratch("utf16").join("putty-session.reg");
    std::fs::write(&file, utf16).unwrap();
    let (code, again, _, err) = import("putty", &file.display().to_string());
    assert_eq!((code, again), (Some(0), hosts_of_session()), "{err}");
}

fn hosts_of_session() -> Hosts {
    import("putty", &format!("{SESSIONS}/putty-session.reg")).1
}

/// A copy of a real file with a made-up proxy password: counted, never
/// printed; an SSH proxy becomes ProxyJump; a session file of Unix takes its
/// name from the file's.
#[test]
fn putty_a_password_is_counted_and_never_printed() {
    let text = String::from_utf8(fixture("putty-session.reg")).unwrap();
    let text = text
        .replace("\"ProxyPassword\"=\"\"", "\"ProxyPassword\"=\"made-up-secret\"")
        .replace("\"ProxyMethod\"=dword:00000000", "\"ProxyMethod\"=dword:00000006")
        .replace("\"ProxyHost\"=\"proxy\"", "\"ProxyHost\"=\"bastion.example\"");
    let dir = scratch("putty-secret");
    std::fs::write(dir.join("with-password.reg"), &text).unwrap();
    let (code, hosts, out, err) = import("putty", &dir.join("with-password.reg").display().to_string());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(hosts["John-Doe"]["proxyjump"], "bastion.example:80", "{out}");
    assert!(err.contains("1 password was not imported"), "{err}");
    no_secret(&[&out, &err]);
    let unix = String::from_utf8(fixture("putty-unix/Default%20Settings")).unwrap();
    let sessions = dir.join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::write(sessions.join("web%20server"), unix.replace("ProxyPassword=\n", "ProxyPassword=made-up-secret\n"))
        .unwrap();
    let (code, hosts, out, err) = import("putty", &sessions.display().to_string());
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(hosts["web-server"].get("hostname").map(String::as_str), Some("localhost"), "{out}");
    assert!(out.contains("# web server\n") && err.contains("1 password was not imported"), "{out}{err}");
    no_secret(&[&out, &err]);
}

#[test]
fn mobaxterm_each_session_of_the_real_export_with_its_folder() {
    let (code, hosts, out, err) = import("mobaxterm", &format!("{SESSIONS}/mobaxterm-ice.mxtsessions"));
    assert_eq!(code, Some(0), "{err}");
    let lines = String::from_utf8(fixture("mobaxterm-ice.mxtsessions")).unwrap();
    let sessions = lines.lines().filter(|l| l.contains("#MobaFont")).count();
    assert!(sessions > 5 && hosts.len() == sessions, "{} of {sessions}: {out}", hosts.len());
    for (name, block) in &hosts {
        assert_eq!(block.get("hostname").map(String::as_str), Some("localhost"), "{name}");
        assert_eq!((block["port"].as_str(), block["user"].as_str()), ("64673", "vagrant"), "{name}");
    }
    assert!(out.contains("# MONGODB-ACCOUNT (DEV) (in ice/DEV/Backing)\nHost MONGODB-ACCOUNT-DEV\n"), "{out}");
    // A copy with the section of passwords that MobaXterm.ini holds.
    let dir = scratch("moba-secret");
    let file = dir.join("with-passwords.mxtsessions");
    std::fs::write(&file, format!("{lines}\r\n[Passwords]\r\nssh22:vagrant@localhost=made-up-blob\r\n")).unwrap();
    let (code, _, out, err) = import("mobaxterm", &file.display().to_string());
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("1 password was not imported"), "{err}");
    no_secret(&[&out, &err]);
}

#[test]
fn remmina_the_real_template_and_a_profile_made_from_it() {
    let (code, hosts, out, err) = import("remmina", &format!("{SESSIONS}/remmina-ssh-template.remmina"));
    assert_eq!(code, Some(0), "{err}");
    assert!(hosts.is_empty() && out.contains("the host %Host% is a placeholder of a template"), "{out}");
    let text = String::from_utf8(fixture("remmina-ssh-template.remmina")).unwrap();
    let profile = text
        .replace("server=%Host%", "server=web.example:2222")
        .replace("username=%User%", "username=alice")
        .replace("\npassword=\n", "\npassword=.\n")
        .replace("ssh_passphrase=\n", "ssh_passphrase=made-up-blob\n");
    let dir = scratch("remmina");
    std::fs::write(dir.join("group_ssh_web.remmina"), profile).unwrap();
    let (code, hosts, out, err) = import("remmina", &dir.display().to_string());
    assert_eq!(code, Some(0), "{err}");
    let block = &hosts["scalusSSH"];
    assert_eq!(
        (block["hostname"].as_str(), block["port"].as_str(), block["user"].as_str()),
        ("web.example", "2222", "alice")
    );
    assert!(out.contains("1 of its secrets are in the keyring"), "{out}");
    assert!(err.contains("2 passwords were not imported"), "{err}");
    no_secret(&[&out, &err]);
}
