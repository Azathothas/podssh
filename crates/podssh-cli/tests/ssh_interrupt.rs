//! Ctrl-C in a session with no remote pty (T-293), against the test's SSH
//! server on the loopback: its command `wait-signal PATH acts|deaf`
//! (`ssh_harness`) prints `started`, writes each `signal` request that comes
//! into PATH, and ends by it (`acts`) or runs on (`deaf`). On Unix the test
//! sends SIGINT to podssh, as a terminal does at Ctrl-C; on Windows it types
//! Ctrl-C into a pseudo console where podssh runs (`conpty_harness`), which
//! gives podssh a CTRL_C_EVENT. `--result-file` tells a command that the
//! signal ended (`signal`) from a wait that ran out (`interrupted`).

mod cleanup;
#[cfg(windows)]
mod conpty_harness;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use podssh_ssh::terminal::interrupt::WAIT;

const LIMIT: Duration = Duration::from_secs(20);

/// The Prove's bound for a server that ignores the request.
const IGNORED_WITHIN: Duration = Duration::from_secs(3);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-interrupt-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The test's server, with a new host key, on a runtime of its own.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    (runtime, port)
}

/// The words of `podssh ssh --direct` to the server, with a result file in
/// `home`, then `args`.
fn ssh_words(home: &Path, port: u16, args: &[&str]) -> Vec<String> {
    let mut words: Vec<String> = vec![
        "ssh".into(),
        "--direct".into(),
        "-p".into(),
        port.to_string(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", home.join("known_hosts").display()),
        "--result-file".into(),
        home.join("result.json").display().to_string(),
    ];
    words.extend(args.iter().map(|a| a.to_string()));
    words
}

/// The server's command that waits for a `signal` request: `acts` or `deaf`.
fn wait_signal(home: &Path, how: &str) -> String {
    format!("wait-signal {} {how}", home.join("signals").display())
}

/// The names of the signals that the server got, a line each.
fn signals(home: &Path) -> String {
    std::fs::read_to_string(home.join("signals")).unwrap_or_default()
}

/// How the session ended, as `--result-file` says it.
fn end_of(home: &Path) -> Option<String> {
    let text = std::fs::read_to_string(home.join("result.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value["end"].as_str().map(str::to_string)
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::Read;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Child, ExitStatus, Stdio};
    use std::sync::{Arc, Mutex};

    /// Whether `done` holds within `limit`, asked each 20 ms.
    fn until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + limit;
        loop {
            if done() {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// podssh, run with its stdin open and its output read as it comes.
    struct Run {
        child: Child,
        out: Arc<Mutex<Vec<u8>>>,
        err: Arc<Mutex<Vec<u8>>>,
    }

    impl Run {
        fn start(mut cmd: Command) -> Run {
            let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            let out = drain(child.stdout.take().unwrap());
            let err = drain(child.stderr.take().unwrap());
            Run { child, out, err }
        }

        /// Wait until the server's command printed `started`.
        fn started(&self) {
            let started = until(LIMIT, || String::from_utf8_lossy(&self.out.lock().unwrap()).contains("started"));
            assert!(started, "the command did not start: {}", self.stderr());
        }

        /// SIGINT to podssh, as a terminal sends it at Ctrl-C.
        fn ctrl_c(&self) {
            // SAFETY: kill sends a signal to podssh's process and does nothing else.
            let sent = unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGINT) };
            assert_eq!(sent, 0, "kill: {}", std::io::Error::last_os_error());
        }

        fn wait(&mut self, limit: Duration) -> Option<ExitStatus> {
            let mut status = None;
            until(limit, || {
                status = self.child.try_wait().unwrap();
                status.is_some()
            });
            status
        }

        fn stderr(&self) -> String {
            String::from_utf8_lossy(&self.err.lock().unwrap()).into_owned()
        }
    }

    impl Drop for Run {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// The bytes of `from`, read on a thread of their own.
    fn drain(mut from: impl Read + Send + 'static) -> Arc<Mutex<Vec<u8>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = seen.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = from.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                into.lock().unwrap().extend_from_slice(&chunk[..n]);
            }
        });
        seen
    }

    /// No ssh_config, and the test's home; no proxy and no agent.
    fn environment(cmd: &mut Command, home: &Path) {
        cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
        for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
            cmd.env_remove(name);
        }
    }

    fn podssh(home: &Path, port: u16, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(ssh_words(home, port, args));
        environment(&mut cmd, home);
        cmd
    }

    /// SIGINT sends `signal INT`, the server ends the command by it, and
    /// podssh exits with the command's signal, 128 + 2.
    #[test]
    fn ctrl_c_sends_signal_int_and_the_command_s_end_is_the_exit_code() {
        let home = scratch("acts");
        let (_runtime, port) = server(&home);
        let command = wait_signal(&home, "acts");
        let mut run = Run::start(podssh(&home, port, &["tester@127.0.0.1", &command]));
        run.started();
        let sent = Instant::now();
        run.ctrl_c();
        let status = run.wait(LIMIT).expect("podssh ends");
        let took = sent.elapsed();
        assert_eq!(status.code(), Some(130), "{status:?}: {}", run.stderr());
        assert!(took < WAIT, "the command's end, not the wait's: {took:?}");
        assert_eq!(signals(&home), "INT\n");
        assert_eq!(end_of(&home).as_deref(), Some("signal"));
        assert!(run.stderr().contains("killed by signal INT"), "{}", run.stderr());
    }

    /// A server that ignores the request: podssh ends when the wait runs
    /// out, within 3 s, with 130.
    #[test]
    fn a_server_that_ignores_the_request_ends_podssh_within_3_s() {
        let home = scratch("deaf");
        let (_runtime, port) = server(&home);
        let command = wait_signal(&home, "deaf");
        let mut run = Run::start(podssh(&home, port, &["tester@127.0.0.1", &command]));
        run.started();
        let sent = Instant::now();
        run.ctrl_c();
        let status = run.wait(LIMIT).expect("podssh ends");
        let took = sent.elapsed();
        assert_eq!(status.code(), Some(130), "{status:?}: {}", run.stderr());
        assert!(took >= WAIT && took < IGNORED_WITHIN, "{took:?}");
        assert_eq!(signals(&home), "INT\n");
        assert_eq!(end_of(&home).as_deref(), Some("interrupted"));
    }

    /// A second SIGINT ends podssh at once, in the wait after the first.
    #[test]
    fn a_second_ctrl_c_ends_podssh_at_once() {
        let home = scratch("again");
        let (_runtime, port) = server(&home);
        let command = wait_signal(&home, "deaf");
        let mut run = Run::start(podssh(&home, port, &["tester@127.0.0.1", &command]));
        run.started();
        run.ctrl_c();
        assert!(until(LIMIT, || signals(&home) == "INT\n"), "no request came: {}", run.stderr());
        let again = Instant::now();
        run.ctrl_c();
        let status = run.wait(LIMIT).expect("podssh ends");
        let took = again.elapsed();
        assert_eq!(status.code(), Some(130), "{status:?}: {}", run.stderr());
        assert!(took < WAIT / 2, "a second Ctrl-C waits for nothing: {took:?}");
        assert_eq!(signals(&home), "INT\n", "one request");
        assert_eq!(end_of(&home).as_deref(), Some("interrupted"));
    }

    /// `--no-signal`: no request, and SIGINT ends podssh at once, as
    /// OpenSSH's client.
    #[test]
    fn with_no_signal_the_server_gets_no_request() {
        let home = scratch("no-signal");
        let (_runtime, port) = server(&home);
        let command = wait_signal(&home, "acts");
        let mut run = Run::start(podssh(&home, port, &["--no-signal", "tester@127.0.0.1", &command]));
        run.started();
        run.ctrl_c();
        let status = run.wait(LIMIT).expect("podssh ends");
        assert_eq!(status.signal(), Some(libc::SIGINT), "{status:?}: {}", run.stderr());
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(signals(&home), "", "a request came");
    }

    /// SIGINT that was ignored when podssh started stays ignored, as in
    /// OpenSSH's client: no request, and podssh runs on.
    #[test]
    fn a_sigint_ignored_at_start_stays_ignored() {
        let home = scratch("ignored");
        let (_runtime, port) = server(&home);
        let command = wait_signal(&home, "acts");
        let mut cmd = podssh(&home, port, &["tester@127.0.0.1", &command]);
        // SAFETY: signal() is safe between fork and exec, as pre_exec asks.
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGINT, libc::SIG_IGN);
                Ok(())
            });
        }
        let mut run = Run::start(cmd);
        run.started();
        run.ctrl_c();
        assert_eq!(run.wait(Duration::from_secs(1)), None, "podssh ended: {}", run.stderr());
        assert_eq!(signals(&home), "", "a request came");
    }

    /// Whether a process whose command line matches `pattern` runs here.
    fn running(pattern: &str) -> bool {
        Command::new("pgrep").args(["-f", pattern]).output().is_ok_and(|o| o.status.success())
    }

    /// In the build image, against T-131's servers on this host: podssh runs
    /// a `sleep` with no pty there, gets SIGINT and ends, and the `sleep` runs
    /// no more. `PODSSH_INTERRUPT_TARGETS` names them as `NAME=USER@HOST:PORT`,
    /// separated by spaces, and `PODSSH_INTERRUPT_KEY` the key to log in with.
    #[test]
    #[ignore = "needs the SSH servers that PODSSH_INTERRUPT_TARGETS names, on this host"]
    fn each_named_server_ends_the_command_at_ctrl_c() {
        let key = std::env::var("PODSSH_INTERRUPT_KEY").expect("PODSSH_INTERRUPT_KEY names a key file");
        let targets = std::env::var("PODSSH_INTERRUPT_TARGETS").unwrap_or_default();
        assert!(!targets.trim().is_empty(), "PODSSH_INTERRUPT_TARGETS names no server");
        for (n, target) in targets.split_whitespace().enumerate() {
            let (name, dest) = target.split_once('=').expect("NAME=USER@HOST:PORT");
            let (login, port) = dest.rsplit_once(':').expect("a port");
            let home = scratch(&format!("named-{n}"));
            // A length that no other sleep of this host has; `^` leaves out
            // podssh's own command line, which holds the words too.
            let sleep = format!("sleep {}", 3171 + n);
            let remote = format!("exec {sleep}");
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
            cmd.args(["ssh", "--direct", "-T", "-p", port, "-i", key.as_str(), "-o", "IdentitiesOnly=yes"]);
            cmd.args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"]);
            cmd.arg(format!("UserKnownHostsFile={}", home.join("known_hosts").display()));
            cmd.args([login, remote.as_str()]);
            environment(&mut cmd, &home);
            let mut run = Run::start(cmd);
            let pattern = format!("^{sleep}");
            assert!(until(LIMIT, || running(&pattern)), "{name}: {sleep} never ran: {}", run.stderr());
            run.ctrl_c();
            let status = run.wait(LIMIT).expect("podssh ends");
            assert!(until(IGNORED_WITHIN, || !running(&pattern)), "{name}: {sleep} still runs");
            println!("{name}: podssh exited with {status:?}, and {sleep} runs no more");
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::conpty_harness::Console;

    /// What a console process exits with when Ctrl-C ends it, by the
    /// console's default handler: STATUS_CONTROL_C_EXIT.
    const CONTROL_C_EXIT: u32 = 0xC000_013A;

    /// A command line of `words`, each quoted when it holds a space.
    fn line(words: &[String]) -> String {
        let quoted: Vec<String> =
            words.iter().map(|w| if w.contains(' ') { format!("\"{w}\"") } else { w.clone() }).collect();
        quoted.join(" ")
    }

    /// `podssh ssh --direct` to the server in a pseudo console of 24 by 80.
    fn console(home: &Path, port: u16, args: &[&str]) -> Console {
        let mut words = vec![env!("CARGO_BIN_EXE_podssh").to_string()];
        words.extend(ssh_words(home, port, args));
        let home = home.to_str().unwrap();
        let changes = [
            ("PODSSH_SSH_CONFIG", Some("none")),
            ("HOME", Some(home)),
            ("USERPROFILE", Some(home)),
            ("PODSSH_OFFLINE", None),
            ("HTTPS_PROXY", None),
            ("ALL_PROXY", None),
            ("SSH_AUTH_SOCK", None),
        ];
        Console::start(&line(&words), &changes, 24, 80)
    }

    /// Ctrl-C typed in a console where podssh runs `-T` sends `signal INT`,
    /// and the command's signal is podssh's exit code.
    #[test]
    fn ctrl_c_in_a_console_sends_signal_int() {
        let home = scratch("console-acts");
        let (_runtime, port) = server(&home);
        let command = wait_signal(&home, "acts");
        let mut console = console(&home, port, &["-T", "tester@127.0.0.1", &command]);
        assert!(console.expect("started", LIMIT), "the console: {:?}", console.text());
        console.send(b"\x03");
        assert_eq!(console.wait(LIMIT), Some(130), "the console: {:?}", console.text());
        assert_eq!(signals(&home), "INT\n");
        assert_eq!(end_of(&home).as_deref(), Some("signal"));
    }

    /// A server that ignores the request: podssh ends when the wait runs
    /// out, within 3 s, with 130.
    #[test]
    fn a_server_that_ignores_it_ends_podssh_after_the_wait() {
        let home = scratch("console-deaf");
        let (_runtime, port) = server(&home);
        let command = wait_signal(&home, "deaf");
        let mut console = console(&home, port, &["-T", "tester@127.0.0.1", &command]);
        assert!(console.expect("started", LIMIT), "the console: {:?}", console.text());
        let sent = Instant::now();
        console.send(b"\x03");
        assert_eq!(console.wait(LIMIT), Some(130), "the console: {:?}", console.text());
        let took = sent.elapsed();
        assert!(took >= WAIT && took < IGNORED_WITHIN, "{took:?}");
        assert_eq!(signals(&home), "INT\n");
        assert_eq!(end_of(&home).as_deref(), Some("interrupted"));
    }

    /// `--no-signal`: no request, and Ctrl-C ends podssh at once, by the
    /// console's default handler, as before.
    #[test]
    fn with_no_signal_ctrl_c_ends_podssh_as_before() {
        let home = scratch("console-no-signal");
        let (_runtime, port) = server(&home);
        let command = wait_signal(&home, "acts");
        let mut console = console(&home, port, &["--no-signal", "-T", "tester@127.0.0.1", &command]);
        assert!(console.expect("started", LIMIT), "the console: {:?}", console.text());
        console.send(b"\x03");
        assert_eq!(console.wait(LIMIT), Some(CONTROL_C_EXIT), "the console: {:?}", console.text());
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(signals(&home), "", "a request came");
    }
}
