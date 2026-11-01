//! A detached run asks the user's systemd for a scope of its own (T-381),
//! against a dbus-daemon of the test, which podssh did not write: the bus
//! takes the login, `Hello` and the call `StartTransientUnit`, which it
//! checks against its signature before it routes it, and answers that no
//! systemd serves the name; the run says so in its log and serves on.
//! `PODSSH_SYSTEMD=no` asks nothing, and outside a session's scope nothing
//! is asked unless `PODSSH_SYSTEMD=yes`. The live scope of a real systemd is
//! `service-live.yml`'s. The check says that it did not run where no
//! dbus-daemon is found.
#![cfg(target_os = "linux")]

mod cleanup;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-scope-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// A process ended when the test ends.
struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A detached run's pid, ended when the test ends.
struct Detached(i32);
impl Drop for Detached {
    fn drop(&mut self) {
        // SAFETY: a signal to a process that the test started.
        unsafe { libc::kill(self.0, libc::SIGKILL) };
    }
}

/// A dbus-daemon of the test on `dir/bus`, with no activation, so that no
/// service of this host answers for systemd; or none where none runs here.
fn bus(dir: &Path) -> Option<Kill> {
    let config = dir.join("bus.conf");
    std::fs::write(
        &config,
        format!(
            "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN\"\n \
             \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n\
             <busconfig><type>session</type><listen>unix:path={}</listen><auth>EXTERNAL</auth>\
             <policy context=\"default\"><allow send_destination=\"*\" eavesdrop=\"true\"/>\
             <allow eavesdrop=\"true\"/><allow own=\"*\"/><allow receive_sender=\"*\"/></policy></busconfig>\n",
            dir.join("bus").display()
        ),
    )
    .ok()?;
    let child = Command::new("dbus-daemon")
        .arg(format!("--config-file={}", config.display()))
        .args(["--nofork", "--nopidfile"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let child = Kill(child);
    let deadline = Instant::now() + LIMIT;
    while !dir.join("bus").exists() {
        assert!(Instant::now() < deadline, "the dbus-daemon made no socket");
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(child)
}

/// A detached `podssh pipe` with `systemd` as `PODSSH_SYSTEMD`: its pid and
/// its log, once it said its scope or 5 s passed.
fn detached(dir: &Path, systemd: Option<&str>) -> (Detached, String) {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["pipe", "--detach", "--keep-listening", &format!("tcp-listen:127.0.0.1:{port}"), "exec:cat"])
        .env("HOME", dir)
        .env("XDG_CACHE_HOME", dir.join("cache"))
        .env("XDG_RUNTIME_DIR", dir)
        .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={}", dir.join("bus").display()))
        .env_remove("PODSSH_SYSTEMD")
        .stdin(Stdio::null());
    if let Some(value) = systemd {
        cmd.env("PODSSH_SYSTEMD", value);
    }
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let pid: i32 = err
        .split("pid ")
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no pid: {err}"));
    let log = PathBuf::from(err.rsplit("its log ").next().unwrap().trim());
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut text = String::new();
    while Instant::now() < deadline {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.contains("scope") || text.contains("stays in") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (Detached(pid), text)
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 sends nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn a_detached_run_asks_systemd_over_a_real_bus_and_serves_on() {
    let dir = scratch("bus");
    let Some(_bus) = bus(&dir) else {
        eprintln!("did not run: no dbus-daemon here");
        return;
    };
    // Asked: the bus took the call, and no systemd serves the name.
    let (run, log) = detached(&dir, Some("yes"));
    assert!(log.contains("StartTransientUnit: org.freedesktop.DBus.Error.ServiceUnknown"), "{log}");
    assert!(log.contains("which a logout may end") && log.contains("PODSSH_SYSTEMD=no"), "{log}");
    assert!(alive(run.0), "the run serves on: {log}");
    // Off: nothing asked, nothing said.
    let (run, log) = detached(&dir, Some("no"));
    assert!(!log.contains("systemd"), "{log}");
    assert!(alive(run.0));
}

#[test]
fn outside_a_session_s_scope_nothing_is_asked_unless_yes() {
    let here = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let unified = here.lines().find_map(|l| l.strip_prefix("0::")).unwrap_or("");
    if unified.rsplit('/').next().is_some_and(|leaf| leaf.starts_with("session-")) {
        eprintln!("did not run: this test runs in a session's scope ({unified})");
        return;
    }
    let dir = scratch("none");
    let Some(_bus) = bus(&dir) else {
        eprintln!("did not run: no dbus-daemon here");
        return;
    };
    let (run, log) = detached(&dir, None);
    assert!(!log.contains("systemd"), "{log}");
    assert!(alive(run.0));
}
