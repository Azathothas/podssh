//! Connection sharing (T-039) as processes: a master `-M -N -S CTL` serves
//! other runs over its one TCP connection to the test's SSH server, which
//! counts the connections; `-O check` and `-O exit` speak to it; with no
//! master, a run with `ControlPath` connects alone, and with `ControlMaster
//! auto` it becomes the master. On Windows, `-M` is refused.

// The processes of a master are a Unix matter; Windows runs the refusal.
#![cfg_attr(windows, allow(dead_code, unused_imports))]

mod cleanup;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-ctl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// A process that is killed when the test ends, also when it fails.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Setup {
    home: PathBuf,
    port: u16,
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    _runtime: tokio::runtime::Runtime,
}

fn setup(name: &str) -> Setup {
    let home = scratch(name);
    let key = home.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (port, connections) = runtime.block_on(ssh_harness::start_counting(&key));
    Setup { home, port, connections, _runtime: runtime }
}

impl Setup {
    fn podssh(&self, args: &[&str], command: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        let known = self.home.join("known_hosts");
        cmd.args(["ssh", "--direct", "-p", &self.port.to_string(), "-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=accept-new", "-o"])
            .arg(format!("UserKnownHostsFile={}", known.display()))
            .args(args)
            .arg("podtest@127.0.0.1")
            .args(command)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("PODSSH_SSH_CONFIG", "none")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in
            ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK", "PODSSH_LISTEN"]
        {
            cmd.env_remove(name);
        }
        cmd
    }
}

fn ran(mut cmd: Command) -> Output {
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `-O check` passes, within the limit: the master is up.
#[cfg(unix)]
fn wait_for_master(s: &Setup, ctl: &Path, master: &mut Running) {
    let deadline = Instant::now() + LIMIT;
    loop {
        let out = ran(s.podssh(&["-S", ctl.to_str().unwrap(), "-O", "check"], &[]));
        if out.status.code() == Some(0) {
            assert!(text(&out.stderr).contains("Master running (pid="), "{}", text(&out.stderr));
            return;
        }
        if let Some(status) = master.0.try_wait().unwrap() {
            let mut err = String::new();
            let _ = std::io::Read::read_to_string(&mut master.0.stderr.take().unwrap(), &mut err);
            panic!("the master ended with {status}: {err}");
        }
        assert!(Instant::now() < deadline, "no master within {LIMIT:?}: {}", text(&out.stderr));
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
#[test]
fn a_master_serves_other_runs_over_one_connection() {
    let s = setup("master");
    let ctl = s.home.join("ctl");
    let ctl_shown = ctl.to_str().unwrap().to_string();
    let mut master = Running(s.podssh(&["-M", "-N", "-S", &ctl_shown], &[]).spawn().unwrap());
    wait_for_master(&s, &ctl, &mut master);
    let file = s.home.join("ran");
    let append = format!("append {} 3 0", file.display());
    let out = ran(s.podssh(&["-S", &ctl_shown], &[&append]));
    assert_eq!(out.status.code(), Some(3), "the status through the master: {}", text(&out.stderr));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "ran\n");
    let out = ran(s.podssh(&["-S", &ctl_shown], &["greet"]));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), ssh_harness::GREETING);
    assert_eq!(s.connections.load(Ordering::SeqCst), 1, "each run went over the master's one connection");
    // -O exit: the master ends with 0, and its socket goes.
    let out = ran(s.podssh(&["-S", &ctl_shown, "-O", "exit"], &[]));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("Exit request sent."), "{}", text(&out.stderr));
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = master.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the master did not end at -O exit");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(0));
    assert!(!ctl.exists(), "the socket went with the master");
}

#[cfg(unix)]
#[test]
fn with_no_master_a_run_connects_alone_or_becomes_one_with_auto() {
    let s = setup("auto");
    let ctl = s.home.join("ctl").to_str().unwrap().to_string();
    let out = ran(s.podssh(&["-o", &format!("ControlPath={ctl}")], &["greet"]));
    assert_eq!(out.status.code(), Some(0), "alone: {}", text(&out.stderr));
    assert_eq!(s.connections.load(Ordering::SeqCst), 1);
    // ControlMaster auto: this run is the master while its command runs (2 s),
    // and a run meanwhile goes through it.
    let file = s.home.join("ran");
    let slow = format!("append {} 0 2", file.display());
    let auto = ["-o", "ControlMaster=auto", "-o", &format!("ControlPath={ctl}")];
    let mut first = Running(s.podssh(&auto, &[&slow]).spawn().unwrap());
    let deadline = Instant::now() + LIMIT;
    while !Path::new(&ctl).exists() {
        assert!(Instant::now() < deadline, "no socket");
        assert!(first.0.try_wait().unwrap().is_none(), "the first run ended before its socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = ran(s.podssh(&auto, &["greet"]));
    assert_eq!(out.status.code(), Some(0), "through the master: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), ssh_harness::GREETING);
    let deadline = Instant::now() + LIMIT;
    while first.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the first run did not end");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(s.connections.load(Ordering::SeqCst), 2, "the second run shared the first's connection");
    assert!(!Path::new(&ctl).exists(), "the master's socket went with it");
}

#[cfg(unix)]
#[test]
fn o_check_with_no_master_fails_as_openssh_does() {
    let s = setup("none");
    let out = ran(s.podssh(&["-S", s.home.join("no-such-ctl").to_str().unwrap(), "-O", "check"], &[]));
    assert_eq!(out.status.code(), Some(255));
    assert!(text(&out.stderr).contains("Control socket connect("), "{}", text(&out.stderr));
    assert_eq!(s.connections.load(Ordering::SeqCst), 0);
}

#[cfg(windows)]
#[test]
fn connection_sharing_is_refused_on_windows() {
    let s = setup("windows");
    for flags in [&["-M", "-S", "ctl"][..], &["-S", "ctl"], &["-S", "ctl", "-O", "check"]] {
        let out = ran(s.podssh(flags, &["greet"]));
        assert_eq!(out.status.code(), Some(64), "{flags:?}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains("Windows"), "{}", text(&out.stderr));
    }
    assert_eq!(s.connections.load(Ordering::SeqCst), 0);
}
