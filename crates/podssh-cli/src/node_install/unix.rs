//! The services of a Unix user (T-121): a user unit of systemd, when
//! `systemctl --user` answers, else an `@reboot` line of the crontab, when
//! `crontab -l` answers. Each program is the one that a probe found on
//! PATH, run within a bound. No `loginctl` is run: lingering is the user's
//! choice, and this host's.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{run, said, text, Made, Spec};
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::relay_settings::Refusal;

fn found(program: &str) -> Option<PathBuf> {
    crate::pager::find_program(program, std::env::var_os("PATH"))
}

/// `systemctl` when the user's manager answers it.
fn systemctl() -> Result<PathBuf, String> {
    let program = found("systemctl").ok_or("no systemctl on PATH")?;
    match run(Command::new(&program).args(["--user", "show-environment"])) {
        Ok(output) if output.status.success() => Ok(program),
        Ok(output) => Err(format!("systemctl --user does not answer: {}", said(&output))),
        Err(why) => Err(why),
    }
}

/// Where the user's units are: `$XDG_CONFIG_HOME/systemd/user`, else
/// `~/.config/systemd/user`.
fn unit_dir() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config")))?;
    Some(config.join("systemd").join("user"))
}

fn unit_name(name: &str) -> String {
    format!("podssh-node-{name}.service")
}

fn failed(what: &str, why: String) -> Made {
    Made::Failed(Refusal { message: format!("{what}: {why}"), code: EX_UNAVAILABLE })
}

/// `systemctl --user ARGS`, as a step that must pass.
fn step(program: &Path, args: &[&str]) -> Result<(), String> {
    match run(Command::new(program).arg("--user").args(args)) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!("systemctl --user {}: {}", args.join(" "), said(&output))),
        Err(why) => Err(why),
    }
}

/// A user unit, enabled and started now: a unit that was there is replaced,
/// and the node restarted with it.
pub(super) fn systemd(spec: &Spec) -> Made {
    let program = match systemctl() {
        Ok(program) => program,
        Err(why) => return Made::Absent(why),
    };
    let Some(dir) = unit_dir() else { return Made::Absent("no HOME, for the directory of user units".into()) };
    let unit = unit_name(&spec.name);
    let path = dir.join(&unit);
    if let Err(e) = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&path, text::unit(spec))) {
        return failed(&path.display().to_string(), e.to_string());
    }
    let steps: [&[&str]; 3] = [&["daemon-reload"], &["enable", &unit], &["restart", &unit]];
    for args in steps {
        if let Err(why) = step(&program, args) {
            // A unit that cannot run is not left behind.
            let _ = std::fs::remove_file(&path);
            let _ = step(&program, &["daemon-reload"]);
            return failed("the user unit", why);
        }
    }
    Made::Done(vec![format!("a user unit of systemd, {}, enabled and started", path.display()), linger()])
}

/// Whether the user's units run without a session, as systemd records it.
fn linger() -> String {
    let user = ["USER", "LOGNAME"].iter().find_map(|n| std::env::var(n).ok().filter(|u| !u.is_empty()));
    match user {
        Some(user) if Path::new("/var/lib/systemd/linger").join(&user).exists() => {
            format!("lingering is on for {user}: the node runs at boot and after logout")
        }
        Some(user) => format!(
            "lingering is off for {user}: the node runs while {user} has a session; loginctl enable-linger \
             {user}, where this host allows it, keeps it running at boot and after logout"
        ),
        None => {
            "a user unit runs while this user has a session, unless lingering is on (loginctl enable-linger)".into()
        }
    }
}

/// The crontab and the program, when `crontab -l` answers: a user with no
/// table yet has an empty one.
fn crontab() -> Result<(PathBuf, String), String> {
    let program = found("crontab").ok_or("no crontab on PATH")?;
    let output = run(Command::new(&program).arg("-l"))?;
    if output.status.success() {
        return Ok((program, String::from_utf8_lossy(&output.stdout).into_owned()));
    }
    // "no crontab for USER" is an empty table; anything else (cron.deny,
    // no daemon's directory) is a crontab that this user cannot have.
    let complaint = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    match complaint.contains("no crontab") {
        true => Ok((program, String::new())),
        false => Err(format!("crontab -l: {}", said(&output))),
    }
}

/// Give `table` to crontab, through a private file of the cache, as it may
/// hold the user's other lines.
fn put_table(program: &Path, name: &str, table: &str) -> Result<(), String> {
    let file = podssh_relay::cache::store_file(&format!("node-{name}.crontab"), table.as_bytes())?;
    let ran = run(Command::new(program).arg(&file));
    let _ = std::fs::remove_file(&file);
    match ran? {
        output if output.status.success() => Ok(()),
        output => Err(format!("crontab: {}", said(&output))),
    }
}

/// An `@reboot` line of the crontab, which replaces one of the same NAME.
/// It runs at the next boot: the node is not started now.
pub(super) fn cron(spec: &Spec) -> Made {
    let (program, table) = match crontab() {
        Ok(found) => found,
        Err(why) => return Made::Absent(why),
    };
    let (table, _) = text::cron_table(&table, &spec.name, Some(&text::cron_line(spec)));
    if let Err(why) = put_table(&program, &spec.name, &table) {
        return failed("the crontab", why);
    }
    let now = text::login_line(spec);
    Made::Done(vec![
        "an @reboot line of the crontab: it runs at the next boot, where this host's cron runs such lines".into(),
        format!("to start the node now: {now}"),
    ])
}

/// Remove what `--install` wrote for NAME: the user unit that podssh wrote,
/// stopped first, and the line of the crontab with its mark.
pub(super) fn remove(name: &str) -> Vec<String> {
    let mut removed = Vec::new();
    let unit = unit_name(name);
    if let Some(path) = unit_dir().map(|dir| dir.join(&unit)) {
        let ours = std::fs::read_to_string(&path).is_ok_and(|t| t.starts_with(text::UNIT_MARK));
        if ours {
            let stopped = systemctl().and_then(|program| {
                step(&program, &["disable", "--now", &unit])?;
                step(&program, &["daemon-reload"]).map(|()| program)
            });
            if std::fs::remove_file(&path).is_ok() {
                let how = match stopped {
                    Ok(_) => "stopped and disabled".to_string(),
                    Err(why) => format!("not stopped: {why}"),
                };
                removed.push(format!("removed the user unit {} ({how})", path.display()));
            }
        }
    }
    if let Ok((program, table)) = crontab() {
        let (rest, found) = text::cron_table(&table, name, None);
        if found {
            match put_table(&program, name, &rest) {
                Ok(()) => removed.push("removed its line of the crontab".into()),
                Err(why) => removed.push(format!("kept its line of the crontab, which refused the change: {why}")),
            }
        }
    }
    removed
}
