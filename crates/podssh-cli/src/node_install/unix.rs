//! The services of a Unix user (T-121, T-393): a user unit of systemd, when
//! `systemctl --user` answers, else (after a LaunchAgent, `launchd`) two
//! lines of the crontab, when `crontab -l` answers: one at boot, and one
//! each 5 minutes that starts the run again when it ended. Each program is
//! the one that a probe found on PATH, run within a bound. No `loginctl` is
//! run: lingering is the user's choice, and this host's.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{run, said, text, Kind, Made, Spec};
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::relay_settings::Refusal;

pub(super) fn found(program: &str) -> Option<PathBuf> {
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

/// `podssh-node-NAME.service`, `podssh-ssh-NAME.service`.
fn unit_name(kind: Kind, name: &str) -> String {
    format!("podssh-{}.service", kind.stem(name))
}

pub(super) fn failed(what: &str, why: String) -> Made {
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
/// and the run restarted with it.
pub(super) fn systemd(spec: &Spec) -> Made {
    let program = match systemctl() {
        Ok(program) => program,
        Err(why) => return Made::Absent(why),
    };
    let Some(dir) = unit_dir() else { return Made::Absent("no HOME, for the directory of user units".into()) };
    let unit = unit_name(spec.kind, &spec.name);
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
    Made::Done(vec![
        format!("a user unit of systemd, {}, enabled and started", path.display()),
        "it starts again 5 s after each end, with no limit of starts; after 64 or 78, a refused command line or \
         setting, it stays down until it is fixed and started"
            .into(),
        linger(),
    ])
}

/// Whether the user's units run without a session, as systemd records it.
fn linger() -> String {
    let user = ["USER", "LOGNAME"].iter().find_map(|n| std::env::var(n).ok().filter(|u| !u.is_empty()));
    match user {
        Some(user) if Path::new("/var/lib/systemd/linger").join(&user).exists() => {
            format!("lingering is on for {user}: the service runs at boot and after logout")
        }
        Some(user) => format!(
            "lingering is off for {user}: the service runs while {user} has a session; loginctl enable-linger \
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
fn put_table(program: &Path, stem: &str, table: &str) -> Result<(), String> {
    let file = podssh_relay::cache::store_file(&format!("{stem}.crontab"), table.as_bytes())?;
    let ran = run(Command::new(program).arg(&file));
    let _ = std::fs::remove_file(&file);
    match ran? {
        output if output.status.success() => Ok(()),
        output => Err(format!("crontab: {}", said(&output))),
    }
}

/// The lines of the crontab, which replace those of the same NAME: one at
/// boot, and the watchdog each 5 minutes, whose first start is the run's,
/// so that it starts within 5 minutes with no reboot.
pub(super) fn cron(spec: &Spec) -> Made {
    let (program, table) = match crontab() {
        Ok(found) => found,
        Err(why) => return Made::Absent(why),
    };
    let lines = text::cron_lines(spec);
    let (table, _) = text::cron_table(&table, spec.kind, &spec.name, Some(lines.as_slice()));
    if let Err(why) = put_table(&program, &spec.kind.stem(&spec.name), &table) {
        return failed("the crontab", why);
    }
    let now = text::login_line(spec);
    Made::Done(vec![
        "two lines of the crontab: one at boot, and one each 5 minutes that starts it again when it is not \
         running, where this host's cron runs them"
            .into(),
        format!("it starts within 5 minutes; to start it now: {now}"),
    ])
}

/// Remove the user unit of `kind`'s NAME that podssh wrote, stopped first.
pub(super) fn remove_systemd(kind: Kind, name: &str) -> Vec<String> {
    let unit = unit_name(kind, name);
    let Some(path) = unit_dir().map(|dir| dir.join(&unit)) else { return Vec::new() };
    let ours = std::fs::read_to_string(&path).is_ok_and(|t| t.starts_with(text::UNIT_MARK));
    if !ours {
        return Vec::new();
    }
    let stopped = systemctl().and_then(|program| {
        step(&program, &["disable", "--now", &unit])?;
        step(&program, &["daemon-reload"]).map(|()| program)
    });
    if std::fs::remove_file(&path).is_err() {
        return Vec::new();
    }
    let how = match stopped {
        Ok(_) => "stopped and disabled".to_string(),
        Err(why) => format!("not stopped: {why}"),
    };
    vec![format!("removed the user unit {} ({how})", path.display())]
}

/// Remove the lines of `kind`'s NAME from the crontab, with their mark. A
/// run that the lines started goes on until it ends.
pub(super) fn remove_cron(kind: Kind, name: &str) -> Vec<String> {
    let Ok((program, table)) = crontab() else { return Vec::new() };
    let (rest, found) = text::cron_table(&table, kind, name, None);
    if !found {
        return Vec::new();
    }
    match put_table(&program, &kind.stem(name), &rest) {
        Ok(()) => vec!["removed its lines of the crontab; a run that they started goes on until it ends".into()],
        Err(why) => vec![format!("kept its lines of the crontab, which refused the change: {why}")],
    }
}
