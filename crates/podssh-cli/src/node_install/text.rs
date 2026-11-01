//! The text of each kind of service (T-121, T-393), built on each system so
//! that each is tested on each: the node's words with each file by its
//! absolute path, a user unit of systemd, the lines of the crontab, a
//! LaunchAgent of launchd and a task of the Task Scheduler, each with its
//! own quoting. None holds a token: the words are the run's flags, and its
//! variables are in the file of `--env-file`. Each starts the run again
//! whenever it ends, with no limit of starts: a tunnel that stays down locks
//! its server out.

use std::path::Path;

use super::{Kind, Spec};
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The start of the first line of a unit that podssh wrote, which
/// `--uninstall` checks.
#[cfg_attr(windows, allow(dead_code))]
pub(super) const UNIT_MARK: &str = "# Written by podssh ";

/// The time of the crontab's watchdog: each 5 minutes.
#[cfg_attr(windows, allow(dead_code))]
pub(super) const WATCHDOG: &str = "*/5 * * * *";

/// The start of the comment of a LaunchAgent that podssh wrote, which
/// `--uninstall` checks. A comment of XML may hold no `--`, so it names no
/// flag.
#[cfg_attr(windows, allow(dead_code))]
pub(super) const PLIST_MARK: &str = "<!-- Written by podssh";

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
    one_line(&words)?;
    Ok(words)
}

/// No word with a line break, which no service's command can hold.
pub(super) fn one_line(words: &[String]) -> Result<(), Refusal> {
    match words.iter().find(|w| w.contains(['\n', '\r', '\0'])) {
        Some(bad) => {
            Err(Refusal::usage(format!("--install: {bad:?} has a line break, which no service's command can hold")))
        }
        None => Ok(()),
    }
}

/// The bytes that need no quote in each syntax here.
fn plain(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-=:,@+".contains(&b))
}

/// The binary, then the words.
fn command(spec: &Spec) -> impl Iterator<Item = String> + '_ {
    std::iter::once(spec.exe.display().to_string()).chain(spec.args.iter().cloned())
}

/// The run's directory as a path of text, when it has one.
fn dir_text(spec: &Spec) -> Option<String> {
    spec.dir.as_ref().map(|dir| dir.display().to_string())
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

/// The user unit. It starts the run again 5 s after each end, with no
/// limit of starts, but not after a refused command line or setting (64,
/// 78), which no start changes. 77, an expired pair or a refusal of the
/// relay, is started again, so that a new pair is taken with no new
/// install.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn unit(spec: &Spec) -> String {
    let (kind, name) = (spec.kind, &spec.name);
    let words: Vec<String> = command(spec).map(|w| systemd_word(&w)).collect();
    // `-`: a directory that went away is no reason to stay down.
    let dir = dir_text(spec).map_or_else(String::new, |d| format!("WorkingDirectory=-{}\n", d.replace('%', "%%")));
    format!(
        "{UNIT_MARK}{}; podssh {} removes it.\n\
         [Unit]\n\
         Description=podssh {} {name}\n\
         # No limit of starts: a tunnel that stays down locks its server out.\n\
         StartLimitIntervalSec=0\n\
         \n\
         [Service]\n\
         ExecStart={}\n\
         {dir}\
         Restart=always\n\
         RestartSec=5\n\
         RestartPreventExitStatus=64 78\n\
         # The same limit, where a systemd older than 230 reads it.\n\
         StartLimitInterval=0\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        kind.install_words(name),
        kind.uninstall_words(name),
        kind.verb(),
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

/// The comment above the lines of `kind`'s `name` in the crontab.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn cron_mark(kind: Kind, name: &str) -> String {
    let (made, removes) = (kind.install_words(name), kind.uninstall_words(name));
    format!("# podssh {made} wrote the lines below; podssh {removes} removes them")
}

/// The comment of T-121 above its one `@reboot` line, which `--uninstall`
/// and a new `--install` still find.
#[cfg_attr(windows, allow(dead_code))]
fn old_cron_mark(kind: Kind, name: &str) -> String {
    let (made, removes) = (kind.install_words(name), kind.uninstall_words(name));
    format!("# podssh {made} wrote the line below; podssh {removes} removes it")
}

/// The lines of the crontab: one at boot, and the watchdog each 5 minutes,
/// which starts the run again when it ended; while it serves, the lock of
/// its `--env-file` ends the watchdog's start at once. cron runs each line
/// with sh, and reads `%` as a line break: `\%` is a `%`.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn cron_lines(spec: &Spec) -> [String; 2] {
    let words: Vec<String> = command(spec).map(|w| sh_word(&w)).collect();
    let mut run = words.join(" ");
    if let Some(dir) = dir_text(spec) {
        run = format!("cd {} 2>/dev/null; {run}", sh_word(&dir));
    }
    let run = run.replace('%', "\\%");
    [format!("@reboot {run}"), format!("{WATCHDOG} {run}")]
}

/// `table` without the lines of `kind`'s `name`, then with `lines` and their
/// mark when they are given; and whether lines of `name` were there. Below a
/// mark, only an `@reboot` line, and after it the watchdog's line of the
/// same command, are removed: any other line is the user's.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn cron_table(table: &str, kind: Kind, name: &str, lines: Option<&[String]>) -> (String, bool) {
    let marks = [cron_mark(kind, name), old_cron_mark(kind, name)];
    let mut kept: Vec<&str> = Vec::new();
    let mut found = false;
    let mut rest = table.lines().peekable();
    while let Some(next) = rest.next() {
        if !marks.iter().any(|mark| mark == next) {
            kept.push(next);
            continue;
        }
        found = true;
        let Some(command) = rest.peek().copied().and_then(|line| line.strip_prefix("@reboot ")) else { continue };
        let watchdog = format!("{WATCHDOG} {command}");
        rest.next();
        if rest.peek().copied() == Some(watchdog.as_str()) {
            rest.next();
        }
    }
    let mut text: String = kept.iter().map(|l| format!("{l}\n")).collect();
    if let Some(lines) = lines {
        text.push_str(&format!("{}\n", cron_mark(kind, name)));
        for line in lines {
            text.push_str(&format!("{line}\n"));
        }
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

/// `text` for an element or an attribute of XML.
pub(super) fn xml(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// The task: at the logon of `user`, this user, who needs no privilege to
/// make a task that runs as itself with its own token; and each 5 minutes
/// while `user` is logged on, which starts it again when it ended, as a
/// second instance is never started beside a running one. It starts again
/// a minute after a failure, and has no time limit.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn task_xml(spec: &Spec, user: &str) -> String {
    let (kind, name) = (spec.kind, &spec.name);
    let arguments: Vec<String> = spec.args.iter().map(|w| windows_word(w)).collect();
    let description = format!("podssh {} {name}; podssh {} removes it", kind.verb(), kind.uninstall_words(name));
    let dir = dir_text(spec).map_or_else(String::new, |d| format!("<WorkingDirectory>{}</WorkingDirectory>", xml(&d)));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
         <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n  \
           <RegistrationInfo><Description>{}</Description></RegistrationInfo>\n  \
           <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger>\
         <TimeTrigger><Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>\
         <StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>\n  \
           <Principals><Principal id=\"Author\"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType>\
         <RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n  \
           <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\
         <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\
         <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\
         <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>\n  \
           <Actions Context=\"Author\"><Exec><Command>{}</Command><Arguments>{}</Arguments>{dir}</Exec></Actions>\n\
         </Task>\n",
        xml(&description),
        xml(&spec.exe.display().to_string()),
        xml(&arguments.join(" ")),
        user = xml(user),
    )
}

/// The LaunchAgent `label`: the run at once and at each login (RunAtLoad),
/// and again 5 s after each end, whatever its code (KeepAlive); its stderr
/// in `log`, as launchd keeps no journal.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn plist(spec: &Spec, label: &str, log: &Path) -> String {
    let string = |text: &str| format!("  <string>{}</string>", xml(text));
    let mut lines = vec![
        r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_string(),
        r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">"#
            .to_string(),
        format!("{PLIST_MARK}; its uninstall of the service removes this file. -->"),
        r#"<plist version="1.0">"#.to_string(),
        "<dict>".to_string(),
        "  <key>Label</key>".to_string(),
        string(label),
        "  <key>ProgramArguments</key>".to_string(),
        "  <array>".to_string(),
    ];
    lines.extend(command(spec).map(|word| format!("  {}", string(&word))));
    lines.push("  </array>".to_string());
    if let Some(dir) = dir_text(spec) {
        lines.extend(["  <key>WorkingDirectory</key>".to_string(), string(&dir)]);
    }
    let keys = [("RunAtLoad", "<true/>"), ("KeepAlive", "<true/>"), ("ThrottleInterval", "<integer>5</integer>")];
    for (key, value) in keys {
        lines.extend([format!("  <key>{key}</key>"), format!("  {value}")]);
    }
    lines.extend(["  <key>StandardErrorPath</key>".to_string(), string(&log.display().to_string())]);
    lines.extend(["</dict>".to_string(), "</plist>".to_string()]);
    lines.join("\n") + "\n"
}

/// The command to run at login, in this system's shell.
pub(super) fn login_line(spec: &Spec) -> String {
    let words: Vec<String> =
        command(spec).map(|w| if cfg!(windows) { windows_word(&w) } else { sh_word(&w) }).collect();
    let line = words.join(" ");
    match dir_text(spec) {
        Some(dir) if cfg!(windows) => format!("cd /d {} && {line}", windows_word(&dir)),
        Some(dir) => format!("cd {} && {line}", sh_word(&dir)),
        None => line,
    }
}
