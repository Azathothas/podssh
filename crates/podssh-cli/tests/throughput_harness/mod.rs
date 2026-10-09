//! The harness of the throughput method (T-157): a scratch HOME with the
//! test's SSH server, one run of `podssh ssh` in each direction with its
//! clock and its time limit, and the cells, each a way for `podssh ssh` to
//! reach a far end. A cell that cannot be set up says why, and is never
//! counted as 0.

// Each test binary uses a part of it.
#![allow(dead_code)]

mod cells;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use cells::Cell;

const MIB: f64 = 1_048_576.0;
const BLOCK: usize = 64 * 1024;
/// The bound on each run.
const RUN_LIMIT: Duration = Duration::from_secs(300);
/// The bound on each wait of a cell's setup: a pair, a node, a relay.
const SETUP_LIMIT: Duration = Duration::from_secs(60);

/// The commands that a far end runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Far {
    /// The test's own server (`ssh_harness`): `sink` and `source N`.
    Test,
    /// A POSIX server: `sh -c 'echo R; wc -c'` and `head -c N /dev/zero`.
    Posix,
}

impl Far {
    fn command(self, up: bool, bytes: u64) -> String {
        match (self, up) {
            (Far::Test, true) => "sink".into(),
            (Far::Test, false) => format!("source {bytes}"),
            (Far::Posix, true) => "sh -c 'echo R; wc -c'".into(),
            (Far::Posix, false) => format!("head -c {bytes} /dev/zero"),
        }
    }
}

/// A scratch HOME, the test's SSH server on the loopback, and what the
/// cells start, stopped when the session ends.
pub struct Session {
    pub home: PathBuf,
    pub runtime: tokio::runtime::Runtime,
    /// The port of the test's SSH server.
    pub port: u16,
    /// The connections that the test's SSH server took.
    pub connections: Arc<std::sync::atomic::AtomicUsize>,
    children: Mutex<Vec<Child>>,
    pairs: Mutex<Vec<String>>,
    #[cfg(feature = "iroh-test")]
    pub relays: Mutex<Vec<podssh_iroh::test_relay::TestRelay>>,
}

impl Session {
    pub fn start(tag: &str) -> Session {
        let home = scratch(tag);
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let key = home.join("host_key");
        let out = Command::new(env!("CARGO_BIN_EXE_podssh"))
            .args(["keygen", "-q", "-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&key)
            .stdin(Stdio::null())
            .output()
            .expect("podssh keygen runs");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let (port, connections) = runtime.block_on(crate::ssh_harness::start_counting(&key));
        Session {
            home,
            runtime,
            port,
            connections,
            children: Mutex::new(Vec::new()),
            pairs: Mutex::new(Vec::new()),
            #[cfg(feature = "iroh-test")]
            relays: Mutex::new(Vec::new()),
        }
    }

    /// `podssh ARGS` with HOME and the cache under the scratch directory.
    /// The proxy of the machine stays: it is part of the place measured.
    pub fn command(&self, args: &[String]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(args);
        for name in ["PODSSH_OFFLINE", "PODSSH_IROH_RELAY", "PODSSH_TIMEOUT", "SSH_AUTH_SOCK"] {
            cmd.env_remove(name);
        }
        cmd.env("HOME", &self.home).env("USERPROFILE", &self.home);
        cmd.env("XDG_CACHE_HOME", self.home.join("cache")).env("LOCALAPPDATA", self.home.join("cache"));
        cmd
    }

    /// The options of each run: no prompt, and the far end's key recorded in
    /// the scratch directory.
    pub fn common(&self) -> Vec<String> {
        let known = self.home.join("known_hosts");
        ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"]
            .iter()
            .map(|s| s.to_string())
            .chain([format!("UserKnownHostsFile={}", known.display())])
            .collect()
    }

    /// Keep `child` until the session ends.
    pub fn keep(&self, child: Child) {
        self.children.lock().unwrap().push(child);
    }

    /// Stop the pair `name` on the relay when the session ends.
    pub fn revoke_later(&self, name: &str) {
        self.pairs.lock().unwrap().push(name.to_string());
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for mut child in self.children.lock().unwrap().drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }
        for name in self.pairs.lock().unwrap().drain(..) {
            let args = ["relay".to_string(), "revoke".to_string(), name];
            let _ = self.command(&args).stdin(Stdio::null()).output();
        }
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// A fresh, empty scratch directory unique to one test.
pub fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-throughput-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `runs` runs up and `runs` down in `cell`, in turns, in MiB/s; the first
/// run that fails stops the cell, with its reason.
pub fn measure(s: &Session, cell: &Cell, runs: usize, bytes: u64) -> Result<(Vec<f64>, Vec<f64>), String> {
    let (mut ups, mut downs) = (Vec::new(), Vec::new());
    for i in 1..=runs {
        ups.push(run(s, cell, true, bytes).map_err(|why| format!("run {i} up: {why}"))?);
        downs.push(run(s, cell, false, bytes).map_err(|why| format!("run {i} down: {why}"))?);
    }
    Ok((ups, downs))
}

/// One run, a new process: `bytes` into the far end's sink (`up`), or its
/// source read to the end; MiB/s, or why not.
pub fn run(s: &Session, cell: &Cell, up: bool, bytes: u64) -> Result<f64, String> {
    let mut args = cell.args.clone();
    args.push(cell.far.command(up, bytes));
    let mut child = s
        .command(&args)
        .stdin(if up { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("podssh: {e}"))?;
    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    // The limit of the run: the process is killed, which ends its pipes.
    let child = Arc::new(Mutex::new(child));
    let done = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let (child, done) = (child.clone(), done.clone());
        std::thread::spawn(move || {
            let end = Instant::now() + RUN_LIMIT;
            while !done.load(Ordering::SeqCst) && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(100));
            }
            if !done.load(Ordering::SeqCst) {
                let _ = child.lock().unwrap().kill();
            }
        })
    };
    let carried = match stdin {
        Some(stdin) => up_run(stdin, &mut stdout, bytes),
        None => down_run(&mut stdout, bytes),
    };
    let status = loop {
        if let Some(status) = child.lock().unwrap().try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    done.store(true, Ordering::SeqCst);
    let _ = watchdog.join();
    let said = said.join().unwrap_or_default();
    let last = said.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no message").to_string();
    match carried {
        Ok(rate) if status.success() => Ok(rate),
        Ok(_) => Err(format!("exit {:?}: {last}", status.code())),
        Err(why) => Err(format!("{why}; exit {:?}: {last}", status.code())),
    }
}

/// The source read to its end: the clock from the first byte to the last.
fn down_run(stdout: &mut impl Read, bytes: u64) -> Result<f64, String> {
    let mut buf = vec![0u8; BLOCK];
    let (mut got, mut first, mut last) = (0u64, None, Instant::now());
    loop {
        let n = stdout.read(&mut buf).map_err(|e| format!("reading the source: {e}"))?;
        if n == 0 {
            break;
        }
        first.get_or_insert_with(Instant::now);
        got += n as u64;
        last = Instant::now();
    }
    let Some(first) = first.filter(|_| got == bytes) else {
        return Err(format!("{got} of {bytes} bytes came"));
    };
    Ok(rate(bytes, last.duration_since(first)))
}

/// `bytes` into the sink: the clock from its `R` to its count of them.
fn up_run(mut stdin: ChildStdin, stdout: &mut impl Read, bytes: u64) -> Result<f64, String> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| format!("waiting for the sink: {e}"))?;
    if line.trim() != "R" {
        return Err(format!("the sink did not start: {:?}", line.trim()));
    }
    let start = Instant::now();
    let block = vec![0u8; BLOCK];
    let mut left = bytes;
    while left > 0 {
        let n = left.min(BLOCK as u64) as usize;
        stdin.write_all(&block[..n]).map_err(|e| format!("writing to the sink: {e}"))?;
        left -= n as u64;
    }
    drop(stdin);
    line.clear();
    reader.read_line(&mut line).map_err(|e| format!("reading the sink's count: {e}"))?;
    let spent = start.elapsed();
    match line.trim().parse::<u64>() {
        Ok(count) if count == bytes => Ok(rate(bytes, spent)),
        _ => Err(format!("the sink counted {:?} of {bytes} bytes", line.trim())),
    }
}

fn rate(bytes: u64, spent: Duration) -> f64 {
    bytes as f64 / MIB / spent.as_secs_f64().max(1e-6)
}

/// The lines of a child's stderr, as they come.
pub fn lines_of(child: &mut Child) -> std::sync::mpsc::Receiver<String> {
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
}

/// The first line of `lines` that holds `needle`, within the setup's limit.
pub fn wait_for(lines: &std::sync::mpsc::Receiver<String>, needle: &str) -> Result<String, String> {
    let deadline = Instant::now() + SETUP_LIMIT;
    let mut seen = Vec::new();
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) if line.contains(needle) => return Ok(line),
            Ok(line) => seen.push(line),
            Err(_) => return Err(format!("no {needle:?} within {} s: {}", SETUP_LIMIT.as_secs(), seen.join(" | "))),
        }
    }
}

/// Whether `program ARGS` runs here and exits 0: a probe, not an assumption.
pub fn found(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The repository's `scripts/` directory.
pub fn scripts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("scripts")
}
