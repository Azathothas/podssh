//! The stand-ins of a check of the resumable layer on the loopback (T-302,
//! T-305), as `m6_exit.rs` sets them up (T-156): the stand-in relay, a
//! stand-in proxy in front of each end with its faults
//! (`scripts/fake-proxy.py`: `--pause`, `--move`, `--stop-after`), whose
//! clock starts when the start file appears, and a pair whose node stands
//! in front of the tests' SSH server. A run of `echo` carries bytes up and
//! back, starts the fault in their middle, and keeps the time of each line
//! on stderr after the fault.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::throughput_harness::{found, lines_of, scripts, wait_for, without_proxy, Cell, Session};

/// The bound on each run.
pub const LIMIT: Duration = Duration::from_secs(600);
/// The label of the pair.
pub const LABEL: &str = "lab";

/// The name of the tests' SSH server that the client's proxy maps.
pub const TARGET: &str = "target.test";

/// The stand-ins of one check: the relay, and a proxy for each end.
pub struct Stand {
    pub session: Session,
    pub relay: String,
    pub ca: String,
    /// The client's proxy, with the fault.
    pub proxy: String,
    /// The node's.
    pub node_proxy: String,
    /// The file whose appearance starts the clocks of the faults.
    pub start: PathBuf,
}

impl Stand {
    /// The stand-in relay, the client's proxy in front of it with `fault`,
    /// and the node's with `node_fault`; `None` when this host has no Python
    /// or no openssl, which the test says.
    pub fn new(tag: &str, fault: &[&str], node_fault: &[&str]) -> Option<Stand> {
        let session = Session::start(tag);
        let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
            Ok(cell) => cell,
            Err((_, why)) => {
                eprintln!("did not run: {why}");
                return None;
            }
        };
        let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
        let (relay, ca) = (at("--relay-host"), at("--ca-file"));
        let port = relay.rsplit_once(':').unwrap().1.to_string();
        let start = session.home.join("start");
        let map = [format!("relay-a.test=127.0.0.1:{port}")];
        let node_proxy = proxy(&session, "node", &map, node_fault, &start);
        // And the tests' server by a name, for --direct (T-332).
        let client_map = [map[0].clone(), format!("{TARGET}=127.0.0.1:{}", session.port)];
        let proxy = proxy(&session, "client", &client_map, fault, &start);
        Some(Stand { session, relay, ca, proxy, node_proxy, start })
    }

    /// `podssh ARGS` through the client's proxy, with the stand-in relay's
    /// trust.
    pub fn command(&self, args: &[String]) -> Command {
        self.through(&self.proxy, args)
    }

    /// The machine's proxy variables go first: podssh reads https_proxy
    /// before HTTPS_PROXY, and a cloud container sets it.
    pub fn through(&self, proxy: &str, args: &[String]) -> Command {
        let mut cmd = without_proxy(self.session.command(args));
        cmd.env("HTTPS_PROXY", proxy).env("SSL_CERT_FILE", &self.ca);
        cmd
    }

    /// A pair on the stand-in relay, and its node in front of the tests'
    /// SSH server, online. Each run goes through a stand-in proxy whose map
    /// names relay-a.test, and pins no address: a pin to the loopback would
    /// go around the proxy and its fault (T-318).
    pub fn node(&self) {
        let mut args = vec!["relay".to_string(), "pair".into(), LABEL.into()];
        args.extend(["--relay-host".to_string(), self.relay.clone()]);
        let out = self.through(&self.node_proxy, &args).stdin(Stdio::null()).output().unwrap();
        assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
        let args = vec!["node".to_string(), LABEL.into(), format!("127.0.0.1:{}", self.session.port)];
        let mut node =
            self.through(&self.node_proxy, &args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let lines = lines_of(&mut node);
        self.session.keep(node);
        wait_for(&lines, "serving").expect("the node starts");
        // The relay has the node's socket only from this line on.
        wait_for(&lines, "online").expect("the node is online");
    }

    /// Start the clocks of the faults, and wait until each proxy says that
    /// its clock runs: a proxy reads the start file each 50 ms, and a byte
    /// sent before its clock runs passes the fault.
    pub fn start_faults(&self) {
        std::fs::write(&self.start, b"now").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        for name in ["client", "node"] {
            let log = self.session.home.join(format!("proxy-{name}.log"));
            while !std::fs::read_to_string(&log).is_ok_and(|t| t.contains("the faults' clock started")) {
                assert!(Instant::now() < deadline, "the {name}'s proxy did not start the clock of its faults");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    /// The words of `podssh ssh` to the node as `user`, `extra` first, then
    /// `command`.
    pub fn ssh(&self, extra: &[&str], user: &str, command: &str) -> Vec<String> {
        let mut args = vec!["ssh".to_string()];
        args.extend(extra.iter().map(|w| w.to_string()));
        args.extend(self.session.common());
        args.extend([format!("node://{user}@{LABEL}"), command.to_string()]);
        args
    }

    /// The words of `podssh ssh --direct` to the tests' SSH server as
    /// `user`, by the name that the client's proxy maps (T-332), `extra`
    /// first, then `command`.
    #[allow(dead_code)]
    pub fn direct(&self, extra: &[&str], user: &str, command: &str) -> Vec<String> {
        let mut args = vec!["ssh".to_string(), "--direct".to_string()];
        args.extend(extra.iter().map(|w| w.to_string()));
        args.extend(self.session.common());
        args.extend([format!("{user}@{TARGET}"), command.to_string()]);
        args
    }

    /// The words of `podssh ssh` to the tests' SSH server as `user`, on the
    /// forward road through the stand-in relay (T-307), `extra` first, then
    /// `command`; no pin of the relay's name, as through the proxy.
    #[allow(dead_code)]
    pub fn forward(&self, extra: &[&str], user: &str, command: &str) -> Vec<String> {
        let mut args = vec!["ssh".to_string()];
        args.extend(extra.iter().map(|w| w.to_string()));
        args.extend(self.session.common());
        args.extend(["--relay-host".to_string(), self.relay.clone(), "--ca-file".to_string(), self.ca.clone()]);
        args.extend(["-p".to_string(), self.session.port.to_string(), format!("{user}@127.0.0.1"), command.into()]);
        args
    }
}

/// A stand-in proxy, its names mapped, with `fault` from `start`: its URL.
pub fn proxy(session: &Session, name: &str, maps: &[String], fault: &[&str], start: &Path) -> String {
    let python = ["python3", "python"].into_iter().find(|p| found(p, &["--version"])).expect("Python");
    let port_file = session.home.join(format!("proxy-{name}.port"));
    let mut cmd = Command::new(python);
    cmd.arg(scripts().join("fake-proxy.py")).arg("--port-file").arg(&port_file);
    cmd.arg("--log").arg(session.home.join(format!("proxy-{name}.log"))).arg("--start-file").arg(start);
    for map in maps {
        cmd.arg("--map").arg(map);
    }
    cmd.args(fault).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    session.keep(cmd.spawn().expect("the stand-in proxy"));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
            return format!("http://127.0.0.1:{port}");
        }
        assert!(Instant::now() < deadline, "the stand-in proxy did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Bytes that are not all alike, so that a byte out of place shows.
pub fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// What a run of [`echo`] gave.
pub struct Echoed {
    pub code: i32,
    /// Each byte came back once and in order.
    pub whole: bool,
    pub err: String,
    /// Each line on stderr, with its time after the fault started.
    pub lines: Vec<(Duration, String)>,
}

impl Echoed {
    /// When the first line that holds `text` came, after the fault.
    pub fn when(&self, text: &str) -> Option<Duration> {
        self.lines.iter().find(|(_, line)| line.contains(text)).map(|(at, _)| *at)
    }
}

/// `bytes` up and back through `child` (`podssh ssh ... echo`), the fault
/// started when `trigger` bytes are written.
pub fn echo(mut child: Child, start: &Path, bytes: usize, trigger: usize) -> Echoed {
    let sent = pattern(bytes);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let fault: Arc<Mutex<Option<Instant>>> = Arc::default();
    let writing = {
        let (sent, start, fault) = (sent.clone(), start.to_path_buf(), fault.clone());
        std::thread::spawn(move || {
            for (i, chunk) in sent.chunks(64 * 1024).enumerate() {
                if stdin.write_all(chunk).is_err() {
                    return;
                }
                if (i + 1) * 64 * 1024 == trigger {
                    std::fs::write(&start, b"now").unwrap();
                    *fault.lock().unwrap() = Some(Instant::now());
                }
            }
        })
    };
    let reading = std::thread::spawn(move || {
        let mut got = Vec::with_capacity(bytes);
        let _ = stdout.read_to_end(&mut got);
        got
    });
    let said = std::thread::spawn(move || {
        BufReader::new(stderr).lines().map_while(Result::ok).map(|line| (Instant::now(), line)).collect::<Vec<_>>()
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code().unwrap_or(-1);
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the session did not end within {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = writing.join();
    let got = reading.join().unwrap();
    let said = said.join().unwrap();
    let from = fault.lock().unwrap().unwrap_or(started);
    let err: Vec<&str> = said.iter().map(|(_, line)| line.as_str()).collect();
    let lines = said.iter().map(|(at, line)| (at.saturating_duration_since(from), line.clone())).collect();
    Echoed { code, whole: got == sent, err: err.join("\n"), lines }
}
