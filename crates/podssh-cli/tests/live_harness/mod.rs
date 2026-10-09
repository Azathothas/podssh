//! The harness of the live tests of the pairs (T-083, T-084, T-154, T-155):
//! a scratch HOME and cache, the binary on the network, a node that is
//! killed and a pair that is stopped when a test ends, and an echo server on
//! this machine's loopback for a node's TARGET.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const LIMIT: Duration = Duration::from_secs(60);

pub fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-node-live-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, on the network.
pub fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args);
    for name in ["PODSSH_RELAY", "PODSSH_RELAY_ADDR", "PODSSH_RELAY_TOKEN", "PODSSH_OFFLINE"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

pub fn run(home: &Path, args: &[&str]) -> (i32, String, String) {
    let mut child = command(home, args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < deadline, "podssh {args:?} did not end in time");
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("output");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// Kills the node and stops the pair, if a test ends early, and deletes the
/// scratch directory, with its throwaway key, in each case.
pub struct Cleanup<'a> {
    pub home: &'a Path,
    pub node: Option<Child>,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if let Some(mut node) = self.node.take() {
            let _ = node.kill();
            let _ = node.wait();
        }
        if self.home.join("cache").join("podssh").join("pair-lab.json").exists() {
            let _ = run(self.home, &["relay", "revoke", "lab"]);
        }
        let _ = std::fs::remove_dir_all(self.home);
    }
}

/// The node's stderr, a line at a time.
pub fn lines_of(node: &mut Child) -> mpsc::Receiver<String> {
    let stderr = node.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
}

/// An echo server on this machine's loopback, for each connection while the
/// test runs: its port.
pub fn echo_server() -> u16 {
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in echo.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut reader = stream.try_clone().unwrap();
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
            });
        }
    });
    port
}
