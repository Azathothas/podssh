//! The text of each kind of service (T-121), built on each system so that
//! each is tested on each: the node's words with each file by its absolute
//! path, a user unit of systemd, a line of the crontab and a task of the
//! Task Scheduler, each with its own quoting. None holds a token: the words
//! are the node's flags, and its variables are in the file of `--env-file`.

use std::path::Path;

use super::Spec;
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The first line of a unit that podssh wrote, which `--uninstall` checks.
#[cfg_attr(windows, allow(dead_code))]
pub(super) const UNIT_MARK: &str = "# Written by podssh node ";

/// The node's words for its service: NAME, each TARGET and the flags of this
/// run, each file by its absolute path, as the service does not start in
/// this directory; then `--env-file`.
pub(super) fn service_args(args: &NodeArgs, name: &str, env_file: &Path) -> Result<Vec<String>, Refusal> {
    let mut words = vec!["node".to_string(), name.to_string()];
    words.extend(args.targets.iter().cloned());
    let values =
        [("--relay-addr", &args.relay_addr), ("--iroh-relay", &args.iroh_relay), ("--derp-server", &args.derp_server)];
    for (flag, value) in values {
        if let Some(value) = value {
            words.extend([flag.to_string(), value.clone()]);
        }
    }
    let files = [
        ("--ca-file", &args.ca_file),
        ("--pair-file", &args.pair_file),
        ("--key", &args.key),
        ("--allow", &args.allow),
        ("--iroh-key", &args.iroh_key),
        ("--iroh-allow", &args.iroh_allow),
    ];
    for (flag, value) in files {
        if let Some(value) = value {
            let path = std::path::absolute(value).map_err(|e| Refusal::config(format!("{flag} {value}: {e}")))?;
            words.extend([flag.to_string(), path.display().to_string()]);
        }
    }
    let switches = [
        ("--plain", args.plain),
        ("--iroh", args.iroh),
        ("--derp", args.derp),
        ("--no-e2e", args.no_e2e),
        ("--sshd", args.sshd),
    ];
    for (flag, on) in switches {
        if on {
            words.push(flag.to_string());
        }
    }
    words.extend(["--env-file".to_string(), env_file.display().to_string()]);
    if let Some(bad) = words.iter().find(|w| w.contains(['\n', '\r', '\0'])) {
        return Err(Refusal::usage(format!(
            "--install: {bad:?} has a line break, which no service's command can hold"
        )));
    }
    Ok(words)
}

/// The bytes that need no quote in each syntax here.
fn plain(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-=:,@+".contains(&b))
}

/// The binary, then the words.
fn command(spec: &Spec) -> impl Iterator<Item = String> + '_ {
    std::iter::once(spec.exe.display().to_string()).chain(spec.args.iter().cloned())
}

/// A word as `ExecStart=` reads it: `%` and `$` doubled, as systemd expands
/// them, and in double quotes when it is not plain.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn systemd_word(word: &str) -> String {
    let escaped = word.replace('%', "%%").replace('$', "$$");
    if plain(word) {
        return escaped;
    }
    format!("\"{}\"", escaped.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The user unit. It starts again 10 s after a failure, but not after a
/// refused flag, pair or setting (64, 77, 78), which no restart changes.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn unit(spec: &Spec) -> String {
    let name = &spec.name;
    let words: Vec<String> = command(spec).map(|w| systemd_word(&w)).collect();
    format!(
        "{UNIT_MARK}{name} --install; podssh node {name} --uninstall removes it.\n\
         [Unit]\n\
         Description=podssh node {name}\n\
         \n\
         [Service]\n\
         ExecStart={}\n\
         Restart=on-failure\n\
         RestartSec=10\n\
         RestartPreventExitStatus=64 77 78\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        words.join(" ")
    )
}

/// A word for a POSIX shell: as it is when plain, else in single quotes.
pub(super) fn sh_word(word: &str) -> String {
    if plain(word) {
        return word.to_string();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The comment above the line of `name` in the crontab.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn cron_mark(name: &str) -> String {
    format!("# podssh node {name} --install wrote the line below; podssh node {name} --uninstall removes it")
}

/// The line of the crontab. cron runs it with sh, and reads `%` as a line
/// break: `\%` is a `%`.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn cron_line(spec: &Spec) -> String {
    let words: Vec<String> = command(spec).map(|w| sh_word(&w)).collect();
    format!("@reboot {}", words.join(" ").replace('%', "\\%"))
}

/// `table` without the lines of `name`, then with `line` and its mark when
/// one is given; and whether the lines of `name` were there. The line below
/// a mark is removed only when it is an `@reboot` line.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn cron_table(table: &str, name: &str, line: Option<&str>) -> (String, bool) {
    let mark = cron_mark(name);
    let mut kept: Vec<&str> = Vec::new();
    let mut found = false;
    let mut lines = table.lines().peekable();
    while let Some(next) = lines.next() {
        if next == mark {
            found = true;
            if lines.peek().is_some_and(|l| l.starts_with("@reboot ")) {
                lines.next();
            }
            continue;
        }
        kept.push(next);
    }
    let mut text: String = kept.iter().map(|l| format!("{l}\n")).collect();
    if let Some(line) = line {
        text.push_str(&format!("{mark}\n{line}\n"));
    }
    (text, found)
}

/// A word of a Windows command line, as `CommandLineToArgvW` reads it: in
/// double quotes when it holds a space, a tab or a quote, with the
/// backslashes before a quote doubled.
pub(super) fn windows_word(word: &str) -> String {
    if !word.is_empty() && !word.contains([' ', '\t', '"']) {
        return word.to_string();
    }
    let mut quoted = String::from('"');
    let mut slashes = 0;
    for c in word.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(slashes * 2 + 1));
                quoted.push('"');
                slashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(slashes));
                quoted.push(c);
                slashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(slashes * 2));
    quoted.push('"');
    quoted
}

/// `text` for an XML element or attribute.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn xml(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// The task: at the logon of `user`, this user, who needs no privilege to
/// make a task that runs as itself with its own token. It starts again a
/// minute after a failure, and has no time limit.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn task_xml(spec: &Spec, user: &str) -> String {
    let name = &spec.name;
    let arguments: Vec<String> = spec.args.iter().map(|w| windows_word(w)).collect();
    let description = format!("podssh node {name}; podssh node {name} --uninstall removes it");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
         <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n  \
           <RegistrationInfo><Description>{}</Description></RegistrationInfo>\n  \
           <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>\n  \
           <Principals><Principal id=\"Author\"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType>\
         <RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n  \
           <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\
         <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\
         <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\
         <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>\n  \
           <Actions Context=\"Author\"><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions>\n\
         </Task>\n",
        xml(&description),
        xml(&spec.exe.display().to_string()),
        xml(&arguments.join(" ")),
        user = xml(user),
    )
}

/// The command to run at login, in this system's shell.
pub(super) fn login_line(spec: &Spec) -> String {
    let words: Vec<String> =
        command(spec).map(|w| if cfg!(windows) { windows_word(&w) } else { sh_word(&w) }).collect();
    words.join(" ")
}
