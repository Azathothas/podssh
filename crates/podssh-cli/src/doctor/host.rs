//! Checks of the host itself, with no network: where podssh can record host
//! keys and cache tokens, where programs can run, `/proc`, and the terminal.
//! The probes that need libc (user database, pty, bind) are in `unix.rs`.

use std::io::IsTerminal;
use std::path::Path;

use super::Report;

pub(super) fn check(report: &mut Report<'_>) {
    #[cfg(unix)]
    report.line("user", super::unix::user());
    known_hosts(report);
    token_cache(report);
    #[cfg(target_os = "linux")]
    proc_fs(report);
    #[cfg(unix)]
    {
        report.line("pty", super::unix::pty());
        report.line("bind AF_INET", super::unix::bind_inet());
        report.line("bind AF_UNIX", super::unix::bind_unix());
        exec::check(report);
    }
    terminal(report);
}

/// Where `podssh ssh` records host keys by default, and whether it can. A key
/// that cannot be recorded is trusted on first use again at every connection,
/// so this is a failure, not a fact.
fn known_hosts(report: &mut Report<'_>) {
    let env = crate::ssh::resolve::Env::from_process();
    let Some(home) = env.home else {
        report.fail(
            "known_hosts",
            "HOME is not set, so an accepted host key cannot be recorded and every connection trusts \
             on first use again; set HOME, or pass -o UserKnownHostsFile=FILE",
        );
        return;
    };
    let Some(file) = podssh_ssh::options::default_user_known_hosts(&home).into_iter().next() else {
        return;
    };
    match writable(&file) {
        Ok(how) => report.ok("known_hosts", format!("{}: {how}", file.display())),
        Err(why) => report.fail(
            "known_hosts",
            format!(
                "{}: {why}; an accepted host key cannot be recorded, so every connection trusts on first \
                 use again (-o UserKnownHostsFile=FILE)",
                file.display()
            ),
        ),
    }
}

/// Whether `file` could be appended to, or created along with its
/// directories, without changing anything that exists: an existing file is
/// opened for appending and closed; otherwise a probe file is created and
/// removed in the nearest directory that exists.
fn writable(file: &Path) -> Result<String, String> {
    if file.exists() {
        return std::fs::OpenOptions::new()
            .append(true)
            .open(file)
            .map(|_| "exists and can be written".to_string())
            .map_err(|e| format!("cannot be written: {e}"));
    }
    let mut dir = file.parent();
    while let Some(d) = dir {
        if d.is_dir() {
            return probe_dir(d)
                .map(|()| format!("does not exist yet; {} can be written, so it will be created", d.display()))
                .map_err(|e| format!("does not exist, and {} cannot be written: {e}", d.display()));
        }
        dir = d.parent();
    }
    Err("no directory above it exists".into())
}

/// A name no other run uses at the same time.
pub(super) fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{prefix}-{}-{nanos}", std::process::id())
}

/// Create and remove a file in `dir`.
fn probe_dir(dir: &Path) -> std::io::Result<()> {
    let probe = dir.join(unique(".podssh-doctor"));
    std::fs::OpenOptions::new().write(true).create_new(true).open(&probe)?;
    std::fs::remove_file(&probe)
}

/// The first token cache directory podssh can write, in the order
/// `podssh-relay` tries them. With none, a token is minted on every run:
/// podssh still works, but the relay limits how fast tokens are minted.
fn token_cache(report: &mut Report<'_>) {
    let mut refused = Vec::new();
    for dir in podssh_relay::cache::candidate_dirs() {
        let existed = dir.is_dir();
        let result = std::fs::create_dir_all(&dir).and_then(|()| probe_dir(&dir));
        if !existed {
            // Leave nothing behind; podssh creates it again when it caches.
            let _ = std::fs::remove_dir(&dir);
        }
        match result {
            Ok(()) => {
                let skipped = if refused.is_empty() {
                    String::new()
                } else {
                    format!(" (before it: {})", refused.join("; "))
                };
                report.ok("token cache", format!("{} can be written{skipped}", dir.display()));
                return;
            }
            Err(e) => refused.push(format!("{}: {e}", dir.display())),
        }
    }
    report.ok(
        "token cache",
        format!("no directory can be written ({}), so a token is minted on every run", refused.join("; ")),
    );
}

/// Without `/proc`, podssh cannot find its own file, and so does not read a
/// `podssh-ca.pem` beside it.
#[cfg(target_os = "linux")]
fn proc_fs(report: &mut Report<'_>) {
    match std::fs::read_link("/proc/self/exe") {
        Ok(path) => report.ok("/proc", format!("mounted; this program is {}", path.display())),
        Err(e) => report.ok(
            "/proc",
            format!(
                "/proc/self/exe cannot be read ({e}): podssh cannot find its own file, so a podssh-ca.pem \
                 beside it is not used"
            ),
        ),
    }
}

fn terminal(report: &mut Report<'_>) {
    let stdin = std::io::stdin().is_terminal();
    let stdout = std::io::stdout().is_terminal();
    let term = match std::env::var("TERM").ok().filter(|t| !t.is_empty()) {
        Some(t) => format!("TERM={t}"),
        None => "TERM is not set".to_string(),
    };
    let detail = match (stdin, stdout) {
        (true, true) => format!("stdin and stdout are terminals; {term}"),
        (true, false) => format!("stdin is a terminal, stdout is not; {term}"),
        (false, true) => format!("stdout is a terminal, stdin is not; {term}"),
        (false, false) => format!(
            "neither stdin nor stdout is a terminal: commands run over pipes, and ssh -tt still gives the \
             remote side a pty; {term}"
        ),
    };
    report.ok("terminal", detail);
}

/// Which directories programs can run from, found by running a copy of
/// podssh from each: a mount flag or a security policy can forbid it, and
/// only a real attempt tells them apart from a directory that allows it.
#[cfg(unix)]
mod exec {
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::Report;

    /// The longest a copy of podssh may take to answer `--version`.
    const WAIT: Duration = Duration::from_secs(5);

    enum Tried {
        Ran,
        NotWritable(String),
        Refused(String),
        Other(String),
    }

    pub(in crate::doctor) fn check(report: &mut Report<'_>) {
        let own = own_file();
        let mut seen: Vec<PathBuf> = Vec::new();
        for dir in candidates() {
            if !dir.is_dir() {
                continue;
            }
            let real = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
            if seen.contains(&real) {
                continue;
            }
            seen.push(real);
            let noexec = noexec_note(&dir);
            let shown = dir.display();
            let Some(own) = &own else {
                report.unknown("exec", format!("{shown}: not tried: podssh cannot find its own file to copy{noexec}"));
                continue;
            };
            match try_exec(&dir, own) {
                Tried::Ran => report.ok("exec", format!("{shown}: a copy of podssh ran from here")),
                Tried::NotWritable(e) => {
                    report.ok("exec", format!("{shown}: cannot be written ({e}), so nothing can be installed there"))
                }
                Tried::Refused(e) => {
                    report.ok("exec", format!("{shown}: can be written, but programs cannot run from it ({e}){noexec}"))
                }
                Tried::Other(e) => report.unknown("exec", format!("{shown}: {e}{noexec}")),
            }
        }
    }

    fn candidates() -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        dirs.extend(var("TMPDIR"));
        dirs.extend(["/tmp", "/var/tmp", "/dev/shm"].map(PathBuf::from));
        dirs.extend(var("HOME"));
        dirs.extend(std::env::current_dir().ok());
        dirs
    }

    #[cfg(target_os = "linux")]
    fn noexec_note(dir: &Path) -> &'static str {
        match crate::doctor::unix::noexec(dir) {
            Some(true) => "; it is on a noexec mount",
            _ => "",
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn noexec_note(_dir: &Path) -> &'static str {
        ""
    }

    /// This program's file: from `/proc` when it is there, else from argv[0]
    /// and `PATH`.
    fn own_file() -> Option<PathBuf> {
        if let Ok(path) = std::env::current_exe() {
            if path.is_file() {
                return Some(path);
            }
        }
        let arg0 = PathBuf::from(std::env::args_os().next()?);
        if arg0.components().count() > 1 {
            return arg0.is_file().then_some(arg0);
        }
        std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(&arg0)).find(|p| p.is_file())
    }

    fn try_exec(dir: &Path, own: &Path) -> Tried {
        let copy = dir.join(super::unique(".podssh-doctor"));
        let tried = match std::fs::copy(own, &copy) {
            Err(e) => Tried::NotWritable(e.to_string()),
            Ok(_) => {
                use std::os::unix::fs::PermissionsExt;
                match std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o700)) {
                    Ok(()) => run(&copy),
                    Err(e) => Tried::Other(format!("could not mark the copy executable: {e}")),
                }
            }
        };
        let _ = std::fs::remove_file(&copy);
        tried
    }

    fn run(path: &Path) -> Tried {
        let mut busy = 0;
        let mut child = loop {
            let spawned = Command::new(path)
                .arg("--version")
                .env(podssh_relay::open::OFFLINE_ENV, "1")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            match spawned {
                Ok(child) => break child,
                // "Text file busy": a process started at the same moment
                // inherited the copy's write handle; it clears at once.
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && busy < 3 => {
                    busy += 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Tried::Refused(e.to_string()),
                Err(e) => return Tried::Other(format!("the copy could not be started: {e}")),
            }
        };
        let deadline = Instant::now() + WAIT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut out = Vec::new();
                    if let Some(mut stdout) = child.stdout.take() {
                        let _ = stdout.read_to_end(&mut out);
                    }
                    return if status.success() && out.starts_with(b"podssh ") {
                        Tried::Ran
                    } else {
                        Tried::Other(format!("the copy started but did not answer --version ({status})"))
                    };
                }
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Tried::Other(format!("the copy did not finish within {} s", WAIT.as_secs()));
                }
                Err(e) => return Tried::Other(e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_reports_an_existing_file_and_a_missing_one() {
        let dir = std::env::temp_dir().join(unique("podssh-doctor-test"));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("known_hosts");
        let missing = writable(&dir.join("sub").join("known_hosts")).unwrap();
        assert!(missing.contains("does not exist yet"), "{missing}");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(writable(&file).unwrap(), "exists and can be written");
        // Nothing was left behind by the probes.
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from("known_hosts")]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unique_names_differ_between_calls() {
        let a = unique("x");
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_ne!(a, unique("x"));
        assert!(a.starts_with(&format!("x-{}-", std::process::id())));
    }
}
