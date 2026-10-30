//! `podssh config import FORMAT FILE` (T-047, T-292): the host list of
//! another tool as `Host` blocks of `ssh_config`, on stdout, with a summary
//! on stderr: an Ansible inventory, or the saved sessions of PuTTY,
//! MobaXterm, Remmina or mRemoteNG. It never writes `~/.ssh/config`; the user adds
//! what it printed. A password or a passphrase is never imported and never
//! printed: it is counted. What has no keyword of `ssh_config` is named in a
//! comment, never dropped silently.

use std::io::Write;

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::{EX_DATAERR, EX_NOINPUT};

pub mod ansible;
mod mobaxterm;
mod mremoteng;
mod putty;
mod remmina;
mod sessions;

/// A reader of the sessions of one program.
type Reader = fn(&[Input]) -> Result<sessions::Read, String>;

/// A file of another program, as read: its name and its bytes.
pub struct Input {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// The arguments of `podssh config`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigArgs {
    pub subcommand: Option<String>,
    pub args: Vec<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// The formats that need a real export of their program to be tested
/// against, published under a license that this repository can hold, which
/// podssh does not have yet (T-292, T-328).
const NOT_YET: &[&str] = &["finalshell", "termius", "ansible-yaml"];

/// The largest file read: far above any host list.
const MAX_FILE: u64 = 16 << 20;

pub fn run(args: &ConfigArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match (args.subcommand.as_deref(), args.args.as_slice()) {
        (Some("import"), [format, file]) => import(format, file, out, err),
        (Some("import"), _) => usage(err, "give the format and the file: podssh config import ansible FILE"),
        (Some(other), _) => usage(err, &format!("{other}: not a subcommand of config; it has import")),
        (None, _) => usage(err, "give a subcommand: podssh config import FORMAT FILE"),
    }
}

fn usage(err: &mut dyn Write, why: &str) -> i32 {
    let _ = writeln!(err, "podssh config: {why}");
    EXIT_USAGE
}

fn import(format: &str, file: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let format = format.to_ascii_lowercase();
    if NOT_YET.contains(&format.as_str()) {
        return usage(
            err,
            &format!("import {format}: not yet; it waits for a real export of that program to be tested against"),
        );
    }
    let (reader, program): (Reader, &str) = match format.as_str() {
        "ansible" => return inventory(file, out, err),
        "putty" => (putty::read, "PuTTY"),
        "mobaxterm" => (mobaxterm::read, "MobaXterm"),
        "remmina" => (remmina::read, "Remmina"),
        "mremoteng" => (mremoteng::read, "mRemoteNG"),
        _ => {
            let why = format!("import {format}: not a format; give ansible, putty, mobaxterm, remmina or mremoteng");
            return usage(err, &why);
        }
    };
    let inputs = match inputs(file) {
        Ok(inputs) => inputs,
        Err(why) => {
            let _ = writeln!(err, "podssh config import: {file}: {why}");
            return EX_NOINPUT;
        }
    };
    let read = match reader(&inputs) {
        Ok(read) => read,
        Err(why) => {
            let _ = writeln!(err, "podssh config import: {why}");
            return EX_DATAERR;
        }
    };
    let blocks = sessions::write(&read, program, file);
    let _ = out.write_all(blocks.text.as_bytes());
    let _ = writeln!(err, "{}", blocks.summary(file));
    0
}

/// An Ansible inventory, which is text.
fn inventory(file: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let text = match read(file) {
        Ok(text) => text,
        Err(why) => {
            let _ = writeln!(err, "podssh config import: {file}: {why}");
            return EX_NOINPUT;
        }
    };
    let hosts = match ansible::read(&text) {
        Ok(hosts) => hosts,
        Err(why) => {
            let _ = writeln!(err, "podssh config import: {file}:{why}");
            return EX_DATAERR;
        }
    };
    let blocks = write(&hosts, file);
    let _ = out.write_all(blocks.text.as_bytes());
    for refused in &blocks.refused {
        let _ = writeln!(err, "podssh config import: {refused}: not a name that a Host line can hold; not imported");
    }
    let _ = writeln!(err, "{}", blocks.summary(file));
    0
}

/// A file of text, `-` for stdin.
fn read(file: &str) -> Result<String, String> {
    String::from_utf8(bytes(file)?).map_err(|_| "not UTF-8 text".into())
}

/// The bytes of a file, `-` for stdin.
fn bytes(file: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    let reader: Box<dyn Read> = if file == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(file).map_err(|e| e.to_string())?)
    };
    reader.take(MAX_FILE + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(format!("larger than {} MiB, which no host list is", MAX_FILE >> 20));
    }
    Ok(bytes)
}

/// The files of FILE: itself, or each file of a directory in the order of
/// their names, as PuTTY on Unix and Remmina keep one file for each session.
fn inputs(file: &str) -> Result<Vec<Input>, String> {
    let path = std::path::Path::new(file);
    if file == "-" || !path.is_dir() {
        return Ok(vec![Input { name: file.to_string(), bytes: bytes(file)? }]);
    }
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(path)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    if files.is_empty() {
        return Err("a directory with no file".into());
    }
    files
        .iter()
        .map(|p| {
            let name = p.display().to_string();
            bytes(&name).map(|bytes| Input { name, bytes }).map_err(|why| format!("{}: {why}", p.display()))
        })
        .collect()
}

/// The variables of a host that hold a secret: never imported, never
/// printed, counted.
fn secret(name: &str) -> bool {
    name.to_ascii_lowercase().contains("pass")
}

/// The variables whose words Ansible adds to ssh's command line.
const SSH_ARGS: &[&str] = &["ansible_ssh_common_args", "ansible_ssh_extra_args"];

/// The keywords that run a command, which can hold a secret: named in a
/// comment, with no value.
const COMMANDS: &[&str] = &["proxycommand", "localcommand", "remotecommand", "knownhostscommand"];

/// The words that Ansible adds to ssh's command line, as lines of a block:
/// each `-o KEYWORD=VALUE`, and `-J` as `ProxyJump`. A keyword that runs a
/// command, and another flag, are named in a comment, with no value.
fn ssh_args(name: &str, value: &str, out: &mut String) {
    let Ok(words) = ansible::split(value) else {
        out.push_str(&format!("  # {name} is not imported: a quote in it is not closed\n"));
        return;
    };
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        let option = match word.as_str() {
            "-o" => words.next(),
            "-J" => {
                if let Some(hosts) = words.next() {
                    setting(out, "ProxyJump", &hosts);
                }
                continue;
            }
            w => w.strip_prefix("-o").filter(|o| !o.is_empty()).map(str::to_string),
        };
        let Some(option) = option else {
            if word.starts_with('-') {
                out.push_str(&format!("  # the ssh flag {word} of {name} is not imported\n"));
            }
            continue;
        };
        let at = option.find(|c: char| c == '=' || c.is_whitespace()).unwrap_or(option.len());
        let (keyword, value) =
            (&option[..at], option[at..].trim_start_matches(|c: char| c == '=' || c.is_whitespace()));
        if COMMANDS.contains(&keyword.to_ascii_lowercase().as_str()) {
            out.push_str(&format!("  # {keyword} of {name} is not imported: a command can hold a secret\n"));
        } else {
            setting(out, keyword, value);
        }
    }
}

/// One line of a block, the value quoted when it holds a space.
fn setting(out: &mut String, keyword: &str, value: &str) {
    if value.contains('"') {
        out.push_str(&format!("  # {keyword}: its value holds a double quote, which ssh_config cannot\n"));
    } else if value.contains(char::is_whitespace) {
        out.push_str(&format!("  {keyword} \"{value}\"\n"));
    } else {
        out.push_str(&format!("  {keyword} {value}\n"));
    }
}

/// What `import` wrote.
#[derive(Debug, Default)]
pub struct Blocks {
    pub text: String,
    pub hosts: usize,
    pub secrets: usize,
    pub not_ssh: usize,
    pub refused: Vec<String>,
}

impl Blocks {
    fn summary(&self, file: &str) -> String {
        let mut line = format!("podssh config import: {} {} from {file}", self.hosts, plural(self.hosts, "host"));
        if self.secrets > 0 {
            line.push_str(&format!(
                "; {} {} not imported",
                self.secrets,
                if self.secrets == 1 { "password was" } else { "passwords were" }
            ));
        }
        if self.not_ssh > 0 {
            line.push_str(&format!(
                "; {} {} reached with no SSH, in a comment",
                self.not_ssh,
                plural(self.not_ssh, "host")
            ));
        }
        if !self.refused.is_empty() {
            line.push_str(&format!("; {} refused", self.refused.len()));
        }
        line
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

/// The value of the variable that Ansible's ssh connection takes: the last
/// of `names` that is set wins, as its options read them.
fn connection<'a>(host: &'a ansible::Host, names: &[&str]) -> Option<&'a str> {
    names.iter().rev().find_map(|n| host.vars.get(*n)).map(String::as_str)
}

/// The `Host` blocks of `hosts`, read from `file`.
pub fn write(hosts: &[ansible::Host], file: &str) -> Blocks {
    let mut b = Blocks::default();
    b.text.push_str(&format!("# The Ansible inventory {file}, as podssh config import read it.\n"));
    for host in hosts {
        b.secrets += host.vars.keys().filter(|k| secret(k)).count();
        if host.name.chars().any(|c| c.is_whitespace() || matches!(c, '*' | '?' | '!' | '"' | '#')) {
            b.refused.push(host.name.clone());
            continue;
        }
        let groups = if host.groups.is_empty() { String::new() } else { format!(" (in {})", host.groups.join(", ")) };
        if let Some(other) =
            connection(host, &["ansible_connection"]).filter(|c| !matches!(*c, "ssh" | "smart" | "paramiko"))
        {
            b.not_ssh += 1;
            b.text.push_str(&format!("\n# {}{groups}: ansible_connection={other}, no SSH; no Host block\n", host.name));
            continue;
        }
        b.hosts += 1;
        b.text.push_str(&format!("\n# {}{groups}\nHost {}\n", host.name, host.name));
        let settings = [
            ("HostName", connection(host, &["ansible_host", "ansible_ssh_host"])),
            ("Port", connection(host, &["ansible_port", "ansible_ssh_port"])),
            ("User", connection(host, &["ansible_user", "ansible_ssh_user"])),
            ("IdentityFile", connection(host, &["ansible_private_key_file", "ansible_ssh_private_key_file"])),
        ];
        for (keyword, value) in settings {
            match value {
                None => {}
                Some(v) if keyword == "HostName" && v == host.name => {}
                Some(v) => setting(&mut b.text, keyword, v),
            }
        }
        // After Ansible's own settings, as on its command line, where the
        // first value wins, as in a block.
        for name in SSH_ARGS {
            if let Some(value) = host.vars.get(*name) {
                ssh_args(name, value, &mut b.text);
            }
        }
        if host.vars.contains_key("ansible_ssh_args") {
            b.text.push_str("  # ansible_ssh_args is not imported: it holds ssh's flags for each host\n");
        }
    }
    b
}
