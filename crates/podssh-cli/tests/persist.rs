//! `podssh ssh --persist` (T-178) against an SSH server of the test with a
//! stand-in for tmux (`tests/tmux_harness`), with `--direct`: a lost link
//! attaches the same session again, and its variable is still there; a
//! session that ends with a status, a server with no tmux, and a session
//! that is gone after the loss each end the run, with no new connection to
//! attach. With `-N` (T-042), a link dropped under a forward of `-R` asks
//! for it again on a new connection.

mod tmux_harness;

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tmux_harness::Tmux;

/// How long each step may take.
const LIMIT: Duration = Duration::from_secs(30);

/// A run of `podssh ssh --direct --persist` against the stand-in: what it
/// prints, as it comes.
struct Run {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
    tmux: Arc<Mutex<Tmux>>,
    home: std::path::PathBuf,
    runtime: tokio::runtime::Runtime,
}

/// Read `from` into `into` as it comes, on a thread of its own.
fn collect(mut from: impl Read + Send + 'static, into: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = from.read(&mut buf) {
            if n == 0 {
                break;
            }
            into.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
}

impl Run {
    fn start(tag: &str, installed: bool) -> Run {
        Run::start_with(tag, installed, &[])
    }

    /// With `extra` before the destination.
    fn start_with(tag: &str, installed: bool, extra: &[&str]) -> Run {
        let home = std::env::temp_dir().join(format!("podssh-persist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let key = home.join("host_key").to_string_lossy().into_owned();
        let made =
            podssh(&home).args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &key]).stdin(Stdio::null()).status();
        assert!(made.expect("podssh keygen runs").success());
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let (port, tmux) = runtime.block_on(tmux_harness::start(std::path::Path::new(&key), installed));
        let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
        let mut child = podssh(&home)
            .args(["ssh", "--direct", "--persist", "-p", &port.to_string(), "-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=accept-new", "-o", &known])
            .args(extra)
            .arg("tester@127.0.0.1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("podssh ssh runs");
        let (out, err) = (Arc::new(Mutex::new(String::new())), Arc::new(Mutex::new(String::new())));
        collect(child.stdout.take().unwrap(), out.clone());
        collect(child.stderr.take().unwrap(), err.clone());
        let stdin = child.stdin.take();
        Run { child, stdin, out, err, tmux, home, runtime }
    }

    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("the input is open");
        stdin.write_all(format!("{line}\n").as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    /// Wait until `what` holds `text`.
    fn wait_for(&mut self, what: &str, text: &str) {
        self.wait_for_count(what, text, 1);
    }

    /// Wait until `what` holds `text` `count` times.
    fn wait_for_count(&mut self, what: &str, text: &str, count: usize) {
        let started = Instant::now();
        loop {
            let seen = if what == "stdout" { &self.out } else { &self.err };
            if seen.lock().unwrap().matches(text).count() >= count {
                return;
            }
            if started.elapsed() > LIMIT || self.child.try_wait().unwrap().is_some() {
                let _ = self.child.kill();
                panic!(
                    "no {text:?} on {what}; stdout: {:?}; stderr: {:?}",
                    self.out.lock().unwrap(),
                    self.err.lock().unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The exit code, within the limit, and stderr.
    fn end(mut self) -> (Option<i32>, String) {
        let started = Instant::now();
        let code = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status.code();
            }
            if started.elapsed() > LIMIT {
                let _ = self.child.kill();
                panic!("podssh did not end; stderr: {:?}", self.err.lock().unwrap());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // A process ends before its readers have taken the last bytes from
        // the pipes; each reader drops its handle at the end of its stream.
        for seen in [&self.out, &self.err] {
            let reading = Instant::now();
            while Arc::strong_count(seen) > 1 && reading.elapsed() < LIMIT {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let err = self.err.lock().unwrap().clone();
        let _ = std::fs::remove_dir_all(&self.home);
        (code, err)
    }

    fn counts(&self) -> (usize, usize) {
        let tmux = self.tmux.lock().unwrap();
        (tmux.connections, tmux.attaches)
    }

    /// Wait until the server has taken `count` forwards.
    fn wait_for_forwards(&mut self, count: usize) {
        let started = Instant::now();
        while self.tmux.lock().unwrap().forwards.len() < count {
            if started.elapsed() > LIMIT || self.child.try_wait().unwrap().is_some() {
                let _ = self.child.kill();
                panic!("no forward {count}; stderr: {:?}", self.err.lock().unwrap());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// What a connection on the port of forward `i` reads, through its own
    /// connection: one line.
    fn through(&self, i: usize) -> String {
        let (port, handle) = self.tmux.lock().unwrap().forwards[i].clone();
        let read = async move {
            let mut channel = handle
                .channel_open_forwarded_tcpip("127.0.0.1", port, "192.0.2.1", 40000)
                .await
                .expect("podssh takes the channel of its forward");
            let mut got = Vec::new();
            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data } => got.extend_from_slice(&data),
                    russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                    _ => {}
                }
                if got.ends_with(b"\n") {
                    break;
                }
            }
            String::from_utf8_lossy(&got).into_owned()
        };
        self.runtime.block_on(async { tokio::time::timeout(LIMIT, read).await }).expect("the target answers in time")
    }

    /// The server drops the connection of forward `i`.
    fn drop_link(&self, i: usize) {
        let handle = self.tmux.lock().unwrap().forwards[i].1.clone();
        let reason = russh::Disconnect::ByApplication;
        let _ = self.runtime.block_on(handle.disconnect(reason, "the test drops the link".into(), String::new()));
    }

    /// End a run that would not end on its own: its stderr.
    fn stop(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let reading = Instant::now();
        while Arc::strong_count(&self.err) > 1 && reading.elapsed() < LIMIT {
            std::thread::sleep(Duration::from_millis(10));
        }
        let err = self.err.lock().unwrap().clone();
        let _ = std::fs::remove_dir_all(&self.home);
        err
    }
}

/// `podssh` with HOME under `home`, and none of the machine's settings.
fn podssh(home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    // The ssh_config of the machine that runs the test must not change it.
    cmd.env("PODSSH_SSH_CONFIG", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_TIMEOUT", "SSH_AUTH_SOCK", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

#[test]
fn a_lost_link_attaches_the_same_tmux_session_again() {
    let mut run = Run::start("again", true);
    run.wait_for("stdout", "[podssh] attached");
    run.send("MARK=kept");
    run.send("drop");
    run.wait_for("stderr", "attaching the tmux session podssh again");
    // Nothing is typed until the session is attached again: on Windows the
    // question whether stdin is a terminal waited for a read of the pipe
    // that the input's task had pending, which only the next line ended.
    run.wait_for_count("stdout", "[podssh] attached", 2);
    run.send("echo M=$MARK");
    run.wait_for("stdout", "M=kept");
    run.send("tmux kill-session");
    let counts = run.counts();
    let (code, err) = run.end();
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("connecting again in"), "{err}");
    assert_eq!(counts, (2, 2), "two connections, each attached: {err}");
}

#[test]
fn a_session_that_ends_with_a_status_does_not_connect_again() {
    let mut run = Run::start("status", true);
    run.wait_for("stdout", "[podssh] attached");
    run.send("tmux kill-session");
    let tmux = run.tmux.clone();
    let (code, err) = run.end();
    assert_eq!(code, Some(0), "{err}");
    let tmux = tmux.lock().unwrap();
    assert_eq!((tmux.connections, tmux.attaches), (1, 1), "{err}");
}

#[test]
fn with_no_tmux_on_the_server_persist_exits_255_and_names_tmux() {
    let run = Run::start("none", false);
    let tmux = run.tmux.clone();
    let (code, err) = run.end();
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("the server has no tmux on PATH; --persist needs it"), "{err}");
    assert_eq!(tmux.lock().unwrap().attaches, 0);
}

/// A server that restarted lost the session: a new shell would look like
/// the old one, so podssh does not start one.
#[test]
fn a_session_gone_after_the_loss_is_not_started_again() {
    let mut run = Run::start("gone", true);
    run.wait_for("stdout", "[podssh] attached");
    run.send("forget");
    let tmux = run.tmux.clone();
    let (code, err) = run.end();
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("the tmux session podssh is gone from the server"), "{err}");
    let tmux = tmux.lock().unwrap();
    assert_eq!((tmux.connections, tmux.attaches), (2, 1), "{err}");
}

/// `--persist -N -R` (T-042): the server drops the link under a forward;
/// podssh connects again and asks for it again, and a connection on the
/// server's port reaches the target through the new connection. The first
/// request of the new connection is refused, as by a server that still holds
/// the port for the old one: podssh asks again.
#[test]
fn a_lost_link_asks_for_the_remote_forward_again() {
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target_port = target.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in target.incoming().flatten() {
            let _ = stream.write_all(b"the target answers\n");
        }
    });
    let forward = format!("2291:127.0.0.1:{target_port}");
    let mut run = Run::start_with("forwards", true, &["-N", "-R", &forward]);
    run.wait_for_forwards(1);
    assert_eq!(run.through(0), "the target answers\n");
    run.tmux.lock().unwrap().refuse_forwards = 1;
    run.drop_link(0);
    run.wait_for("stderr", "connecting again in");
    run.wait_for_forwards(2);
    assert_eq!(run.through(1), "the target answers\n");
    run.wait_for("stderr", "again; its forwards serve again");
    let tmux = run.tmux.clone();
    let err = run.stop();
    assert!(err.contains("the test drops the link"), "the drop is named: {err}");
    assert!(err.contains(&format!("the server refused -R {forward}, which it may still hold")), "{err}");
    let tmux = tmux.lock().unwrap();
    assert_eq!((tmux.connections, tmux.forward_requests, tmux.attaches), (2, 3, 0), "{err}");
}
