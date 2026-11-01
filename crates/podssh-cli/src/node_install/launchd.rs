//! A LaunchAgent of this user (T-393): macOS's own way, with no privilege,
//! to start a program at login and again whenever it ends. A plist in
//! `~/Library/LaunchAgents`, loaded by `launchctl bootstrap` into the domain
//! of this user's login session, `gui/UID`, which exists while the user is
//! logged in at the screen. With no such session (a Mac reached only over
//! SSH) this way is absent and the crontab's is next, whose line at boot
//! needs no login: an agent of the background domain would not load again
//! after a reboot either.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::unix::{failed, found};
use super::{env, run, said, text, Kind, Made, Spec};

/// `dev.podssh.node.NAME`, `dev.podssh.ssh.NAME`.
fn label(kind: Kind, name: &str) -> String {
    format!("dev.podssh.{}.{name}", kind.verb())
}

/// `~/Library/LaunchAgents`.
fn agents_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(|home| Path::new(&home).join("Library/LaunchAgents"))
}

/// `gui/UID`, this user's login session at the screen.
fn domain() -> String {
    // SAFETY: getuid has no preconditions and cannot fail.
    format!("gui/{}", unsafe { libc::getuid() })
}

/// `launchctl ARGS`, as a step that must pass.
fn step(program: &Path, args: &[&str]) -> Result<(), String> {
    match run(Command::new(program).args(args)) {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!("launchctl {}: {}", args.join(" "), said(&output))),
        Err(why) => Err(why),
    }
}

/// The log beside the file of variables, made private before launchd opens
/// it, which keeps the mode of a file that is there; an older one stays.
fn log_file(spec: &Spec) -> Result<PathBuf, String> {
    let name = env::log_name(spec.kind, &spec.name);
    let path = spec.env_file.parent().map_or_else(|| PathBuf::from(&name), |dir| dir.join(&name));
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&path).map(|_| path.clone()).map_err(|e| format!("{}: {e}", path.display()))
}

/// The LaunchAgent, written, and loaded now in this user's session: one
/// that was loaded is booted out first, so that the new words take.
pub(super) fn launchd(spec: &Spec) -> Made {
    let Some(program) = found("launchctl") else { return Made::Absent("no launchctl on PATH".into()) };
    let Some(dir) = agents_dir() else { return Made::Absent("no HOME, for ~/Library/LaunchAgents".into()) };
    let domain = domain();
    if let Err(why) = step(&program, &["print", &domain]) {
        return Made::Absent(format!("no login session at this Mac's screen ({why})"));
    }
    let label = label(spec.kind, &spec.name);
    let path = dir.join(format!("{label}.plist"));
    let log = match log_file(spec) {
        Ok(log) => log,
        Err(why) => return failed("the LaunchAgent's log", why),
    };
    let written = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&path, text::plist(spec, &label, &log)));
    if let Err(e) = written {
        return failed(&path.display().to_string(), e.to_string());
    }
    // launchd refuses a plist that others may write.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
    }
    let target = format!("{domain}/{label}");
    let _ = step(&program, &["bootout", &target]);
    // A service that a person disabled would not load.
    let _ = step(&program, &["enable", &target]);
    if let Err(why) = step(&program, &["bootstrap", &domain, &path.display().to_string()]) {
        // An agent that cannot load is not left behind.
        let _ = std::fs::remove_file(&path);
        return failed("the LaunchAgent", why);
    }
    Made::Done(vec![
        format!(
            "a LaunchAgent, {}, loaded in {domain}: it starts now, at each login, and 5 s after each end",
            path.display()
        ),
        format!("its lines go to {}", log.display()),
        "it runs while this user is logged in at the screen: after a reboot, from the login on (macOS's automatic \
         login starts it with no person)"
            .into(),
    ])
}

/// Remove the LaunchAgent of `kind`'s NAME that podssh wrote, booted out
/// first.
pub(super) fn remove(kind: Kind, name: &str) -> Vec<String> {
    let label = label(kind, name);
    let Some(path) = agents_dir().map(|dir| dir.join(format!("{label}.plist"))) else { return Vec::new() };
    let ours = std::fs::read_to_string(&path).is_ok_and(|t| t.contains(text::PLIST_MARK));
    if !ours {
        return Vec::new();
    }
    let stopped = match found("launchctl") {
        Some(program) => step(&program, &["bootout", &format!("{}/{label}", domain())]),
        None => Err("no launchctl on PATH".into()),
    };
    if std::fs::remove_file(&path).is_err() {
        return Vec::new();
    }
    let how = match stopped {
        Ok(()) => "stopped".to_string(),
        Err(why) => format!("not stopped: {why}"),
    };
    vec![format!("removed the LaunchAgent {} ({how})", path.display())]
}
