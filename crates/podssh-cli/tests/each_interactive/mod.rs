//! `podssh each --interactive` (T-185), the broadcast, against the test's
//! own SSH server on the loopback ([`shell`]), with the lines on a pipe:
//! each reaches the selected hosts (`:only`, `:none`, `:all`, `::`), with
//! `--confirm` after a second Enter; `:intr` sends `signal INT`; a host
//! whose queue is full leaves the selection with a word; and the refusals
//! of the command line are 64, offline. The emergency stop: by SIGQUIT on
//! Unix ([`unix`]), by Ctrl-\ typed into a terminal whose program podssh
//! is on Linux, and by Ctrl-Break typed into a pseudo console on Windows
//! ([`windows`]); each fails when the stop is planted away.

mod shell;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::{each, scratch};

/// The limit of each wait.
const LIMIT: Duration = Duration::from_secs(30);

/// The test's server, with a new host key in `home`, on a runtime of its own.
fn server(home: &Path) -> (tokio::runtime::Runtime, u16) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(shell::start(&key));
    (runtime, port)
}

/// A host of the server, as the list names it.
fn host(user: &str, port: u16) -> String {
    format!("{user}@127.0.0.1:{port}")
}

/// The words of `podssh each --interactive` to `hosts` on the loopback,
/// with this test's known_hosts, and `extra` before the hosts.
fn words(home: &Path, extra: &[&str], hosts: &[&String]) -> Vec<String> {
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let mut words: Vec<String> = ["each", "--interactive", "--direct", "-o", "StrictHostKeyChecking=accept-new", "-o"]
        .iter()
        .map(|w| w.to_string())
        .collect();
    words.push(known);
    words.extend(extra.iter().map(|w| w.to_string()));
    words.push(hosts.iter().map(|h| h.as_str()).collect::<Vec<_>>().join(","));
    words
}

/// No ssh_config and no settings file, the test's home; no proxy, no agent.
fn environment(cmd: &mut Command, home: &Path) {
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("HOME", home).env("USERPROFILE", home);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
}

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

/// The file that the line `touch DIR/NAME` left on the host of `user`.
fn left(home: &Path, name: &str, user: &str) -> bool {
    home.join(format!("{name}.{user}")).exists()
}

/// podssh with its stdin on a pipe that the test writes, and its output
/// read as it comes, each stream on a thread of its own.
struct Run {
    child: Child,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<Vec<u8>>>,
    err: Arc<Mutex<Vec<u8>>>,
    readers: Vec<JoinHandle<()>>,
}

impl Run {
    fn start(home: &Path, words: &[String]) -> Run {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(words);
        environment(&mut cmd, home);
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let (out, out_reader) = drain(child.stdout.take().unwrap());
        let (err, err_reader) = drain(child.stderr.take().unwrap());
        let stdin = child.stdin.take();
        Run { child, stdin, out, err, readers: vec![out_reader, err_reader] }
    }

    /// Type `text` on podssh's stdin.
    fn type_in(&mut self, text: &str) {
        let stdin = self.stdin.as_mut().expect("the input is open");
        stdin.write_all(text.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    /// The end of podssh's input.
    fn close(&mut self) {
        self.stdin = None;
    }

    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().unwrap()).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.err.lock().unwrap()).into_owned()
    }

    /// Wait until stdout or stderr holds `needle`.
    fn shows(&self, needle: &str) {
        let shown = until(LIMIT, || self.stdout().contains(needle) || self.stderr().contains(needle));
        assert!(shown, "{needle:?} never came: stdout {:?}, stderr {:?}", self.stdout(), self.stderr());
    }

    /// The exit code, once podssh has ended and each stream is read to its end.
    fn end(&mut self) -> i32 {
        let mut status = None;
        let ended = until(LIMIT, || {
            status = self.child.try_wait().unwrap();
            status.is_some()
        });
        assert!(ended, "podssh did not end: {}", self.stderr());
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        status.and_then(|s| s.code()).unwrap_or(-1)
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The bytes of `from`, read on a thread of its own to their end.
fn drain(mut from: impl Read + Send + 'static) -> (Arc<Mutex<Vec<u8>>>, JoinHandle<()>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let into = seen.clone();
    let reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = from.read(&mut chunk) {
            if n == 0 {
                break;
            }
            into.lock().unwrap().extend_from_slice(&chunk[..n]);
        }
    });
    (seen, reader)
}

/// The lines of padding, each 1024 bytes with its newline, that a shell
/// counts and does nothing with.
fn padding(lines: usize) -> String {
    format!("# {}\n", "x".repeat(1021)).repeat(lines)
}

#[test]
fn interactive_refusals_are_64_before_anything_connects() {
    let home = scratch("broadcast-refused");
    let dir = home.join("out").display().to_string();
    for (args, says) in [
        (&["--interactive"][..], "give the hosts"),
        (&["--interactive", "a", "--", "true"][..], "takes no COMMAND"),
        (&["--confirm", "a"][..], "--confirm holds the lines of --interactive"),
        (&["--interactive", "--parallel", "2", "a"][..], "--parallel is for a command"),
        (&["--interactive", "--fail-fast", "a"][..], "--fail-fast is for a command"),
        (&["--interactive", "--output-dir", dir.as_str(), "a"][..], "--output-dir is for a command"),
        (&["--interactive", "h{1..65}"][..], "gives 65 hosts"),
        (&["--interactive", "-o", "SessionType=none", "a"][..], "SessionType"),
    ] {
        let (code, out, err) = each(&home, args, true);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
    }
    assert!(!home.join("out").exists(), "a refusal made the files of --output-dir");
}

#[test]
fn interactive_lines_reach_the_selected_hosts() {
    let home = scratch("broadcast-lines");
    let (_runtime, port) = server(&home);
    let (a, b) = (host("a", port), host("b", port));
    let at = |name: &str| home.join(name).display().to_string();
    let mut run = Run::start(&home, &words(&home, &[], &[&a, &b]));
    run.type_in(&format!("echo hello\n:only {b}\ntouch {}\n:none\ntouch {}\n", at("only"), at("none")));
    run.type_in(&format!(":all\n::colon\n:list\ntouch {}\n", at("all")));
    run.close();
    let code = run.end();
    let (out, err) = (run.stdout(), run.stderr());
    assert_eq!(code, 0, "{err}");
    for line in [format!("{a}: hello"), format!("{b}: hello"), format!("{a}: 3 lines"), format!("{b}: 4 lines")] {
        assert!(out.lines().any(|l| l == line), "{line:?}: {out}");
    }
    for line in [format!("{a}: ?:colon"), format!("{b}: ?:colon"), format!("podssh:   {a}  selected")] {
        assert!(err.lines().any(|l| l.starts_with(&line)), "{line:?}: {err}");
    }
    assert!(err.contains("podssh: 1 of 2 hosts take the lines"), "{err}");
    assert!(err.contains("podssh: no host is selected: the line goes to no host"), "{err}");
    assert!(err.contains("podssh each: 2 hosts: 2 gave 0, 0 failed, 0 not started"), "{err}");
    assert!(left(&home, "only", "b") && !left(&home, "only", "a"), "only {b}");
    assert!(!left(&home, "none", "a") && !left(&home, "none", "b"), "no host");
    assert!(left(&home, "all", "a") && left(&home, "all", "b"), "each host");
}

#[test]
fn interactive_confirm_sends_a_line_for_two_hosts_after_a_second_enter() {
    let home = scratch("broadcast-confirm");
    let (_runtime, port) = server(&home);
    let (a, b) = (host("a", port), host("b", port));
    let at = |name: &str| home.join(name).display().to_string();
    let mut run = Run::start(&home, &words(&home, &["--confirm"], &[&a, &b]));
    run.type_in(&format!("touch {}\ntouch {}\n\n:only {a}\ntouch {}\n", at("one"), at("two"), at("solo")));
    run.close();
    let code = run.end();
    let err = run.stderr();
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("podssh: this line goes to 2 hosts: Enter sends it, another line drops it"), "{err}");
    assert!(err.contains("podssh: the line that waited for a second Enter is not sent"), "{err}");
    assert!(!left(&home, "one", "a") && !left(&home, "one", "b"), "the line that another line dropped");
    assert!(left(&home, "two", "a") && left(&home, "two", "b"), "the line of the second Enter");
    assert!(left(&home, "solo", "a") && !left(&home, "solo", "b"), "a line for one host goes at once");
}

#[test]
fn interactive_intr_sends_signal_int_to_the_selected_hosts() {
    let home = scratch("broadcast-intr");
    let (_runtime, port) = server(&home);
    let (a, b) = (host("a", port), host("b", port));
    let mut run = Run::start(&home, &words(&home, &[], &[&a, &b]));
    run.type_in(&format!(":only {b}\n:intr\n"));
    let signals = |user: &str| std::fs::read_to_string(home.join(format!("signals.{user}"))).unwrap_or_default();
    assert!(until(LIMIT, || signals("b") == "INT\n"), "no signal came: {}", run.stderr());
    #[cfg(unix)]
    unix::ctrl_c_goes_to_no_host(&run);
    run.close();
    let code = run.end();
    assert_eq!(code, 0, "{}", run.stderr());
    assert!(run.stderr().contains("podssh: signal INT to 1 hosts"), "{}", run.stderr());
    assert_eq!(signals("b"), "INT\n", "one request, and the shell ran on to its end");
    assert_eq!(signals("a"), "", "a host that is not selected gets none");
}

#[test]
fn interactive_a_full_queue_takes_its_host_out_of_the_selection() {
    let home = scratch("broadcast-full");
    let (_runtime, port) = server(&home);
    let (a, slow) = (host("a", port), host("stall-b", port));
    let mut run = Run::start(&home, &words(&home, &[], &[&a, &slow]));
    // Each shell is open, and the slow one reads nothing for a while.
    run.type_in("echo go\n");
    run.shows(&format!("{a}: go"));
    run.shows(&format!("{slow}: go"));
    run.type_in(&padding(120));
    run.shows(&format!("{slow}: its queue is full"));
    run.close();
    let code = run.end();
    let (out, err) = (run.stdout(), run.stderr());
    assert_eq!(code, 0, "{err}");
    assert!(out.lines().any(|l| l == format!("{a}: 121 lines")), "the other host took each line: {out}");
    let count: Option<usize> =
        out.lines().find_map(|l| l.strip_prefix(&format!("{slow}: "))?.strip_suffix(" lines")?.parse().ok());
    assert!(count.is_some_and(|n| n < 121), "{count:?}: {out}");
    assert!(err.contains(&format!("{slow}: lines that did not reach it because its queue was full: 1")), "{err}");
    assert!(!err.contains(&format!("{a}: its queue is full")), "{err}");
}
